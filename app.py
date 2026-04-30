import os
import sys
import json
import math
import time
import hmac
import hashlib
import secrets
import psutil
import threading
from pathlib import Path
from datetime import datetime
from collections import Counter
from flask import Flask, jsonify, render_template

# ── Shared state (monitor writes, Flask reads) ────────────────────────────────
alert_events   = []          # list of incident dicts
monitor_status = {"running": False, "honeyfiles": [], "last_scan": None}
score_history  = []          # rolling list of {time, file, score} for chart

# ── Paths ─────────────────────────────────────────────────────────────────────
REGISTRY_PATH = Path.home() / ".honeyfile_registry.json"
EVIDENCE_DIR  = Path.home() / "honeyfile_evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)
HMAC_KEY_PATH = Path.home() / ".honeyfile_registry.hmac_key"
HMAC_SIG_PATH = Path.home() / ".honeyfile_registry.sig"

# ── HMAC-SHA256 registry protection ──────────────────────────────────────────

def _load_or_create_hmac_key() -> bytes:
    """Load persistent HMAC key, or generate and save a new one."""
    if HMAC_KEY_PATH.exists():
        return bytes.fromhex(HMAC_KEY_PATH.read_text().strip())
    key = secrets.token_bytes(32)
    HMAC_KEY_PATH.write_text(key.hex())
    os.chmod(HMAC_KEY_PATH, 0o600)
    return key

def sign_registry(registry_bytes: bytes) -> str:
    """Return hex HMAC-SHA256 of registry contents."""
    key = _load_or_create_hmac_key()
    return hmac.new(key, registry_bytes, hashlib.sha256).hexdigest()

def verify_registry_signature(registry_bytes: bytes) -> bool:
    """Return True if stored signature matches current registry contents."""
    if not HMAC_SIG_PATH.exists():
        print("[!] HMAC signature file missing — registry may have been tampered with")
        return False
    stored_sig = HMAC_SIG_PATH.read_text().strip()
    expected   = sign_registry(registry_bytes)
    if not hmac.compare_digest(stored_sig, expected):
        print("[!!!] REGISTRY INTEGRITY FAILURE — HMAC mismatch, aborting monitor")
        return False
    return True

SCORE_ENCRYPTED_FILE = 50
SCORE_HIGH_ENTROPY   = 30
SCORE_HEADER_CHANGED = 15
SCORE_DECRYPT_FAILED = 20
ALERT_THRESHOLD      = 50

# ── Normal-file track thresholds ──────────────────────────────────────────────
NORMAL_SCORE_PER_ENCRYPTED = 10   # points per .encrypted copy found
NORMAL_SCORE_PER_SPIKE     = 15   # points per entropy spike confirmed
NORMAL_ALERT_THRESHOLD     = 40   # fires when ≥3 files encrypted + spiked

# ── Crypto-forensics helpers ──────────────────────────────────────────────────

def file_entropy(path):
    try:
        data = Path(path).read_bytes()
        if not data:
            return 0.0
        counts = Counter(data)
        total  = len(data)
        return -sum((c/total) * math.log2(c/total) for c in counts.values())
    except Exception:
        return 0.0

def header_changed(path, original_header_hex):
    try:
        current = Path(path).read_bytes()[:16].hex()
        return current != original_header_hex
    except Exception:
        return False

def verify_decryption(path, key_hex, iv_hex):
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        key  = bytes.fromhex(key_hex)
        iv   = bytes.fromhex(iv_hex)
        data = Path(path).read_bytes()
        plain = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), AES.block_size)
        return b"HONEY_TOKEN_ACTIVE" in plain
    except Exception:
        return False

def compute_score(honeyfile, reg_entry, original_path):
    breakdown = {}
    score     = 0
    encrypted_path = Path(f"test_files/{honeyfile}.encrypted")
    enc_exists = encrypted_path.exists()

    # Signal 1: .encrypted copy appeared
    if enc_exists:
        score += SCORE_ENCRYPTED_FILE
        breakdown["encrypted_file_found"] = SCORE_ENCRYPTED_FILE

    # Use whichever file exists — prefer .encrypted since that's what attacker wrote
    # If neither exists (pre-attack) use original for baseline entropy display
    check_path = encrypted_path if enc_exists else Path(original_path)

    # Signal 2: entropy — measure the file the attacker produced
    entropy = file_entropy(check_path)
    breakdown["entropy"] = round(entropy, 3)
    baseline = reg_entry.get("baseline_entropy", 7.0)
    breakdown["baseline_entropy"] = baseline
    if enc_exists and entropy > 7.2 and (entropy - baseline) > 0.05:
        score += SCORE_HIGH_ENTROPY
        breakdown["high_entropy"] = SCORE_HIGH_ENTROPY

    # Signal 3: header changed — attacker's IV+ciphertext starts differently
    # When the attacker re-encrypts with their own random IV, first 16 bytes will differ
    if enc_exists and reg_entry.get("original_header"):
        # Read the .encrypted file — the first 16 bytes are the attacker's IV, which
        # will almost certainly differ from our original ciphertext header
        if header_changed(encrypted_path, reg_entry["original_header"]):
            score += SCORE_HEADER_CHANGED
            breakdown["header_changed"] = SCORE_HEADER_CHANGED

    # Signal 4: decryption — try our key on the .encrypted file; it will fail
    # because the attacker used their own key
    if enc_exists and reg_entry.get("key"):
        ok = verify_decryption(encrypted_path, reg_entry["key"], reg_entry["iv"])
        breakdown["decryption_ok"] = ok
        if not ok:
            score += SCORE_DECRYPT_FAILED
            breakdown["decrypt_failed"] = SCORE_DECRYPT_FAILED
    elif not enc_exists and reg_entry.get("key"):
        # pre-attack: verify our own file is still intact
        ok = verify_decryption(original_path, reg_entry["key"], reg_entry["iv"])
        breakdown["decryption_ok"] = ok

    breakdown["total_score"] = score
    return score, breakdown
file_entropy_history = {}   # {filename: [{"time": t, "entropy": e}, ...]}
file_baselines       = {}   # {filename: baseline_entropy}
ENTROPY_JUMP_THRESH  = 1.5  # bits/byte rise considered suspicious
entropy_alerts       = []   # files flagged by entropy alone

def scan_normal_files():
    """Detect entropy spikes by reading the .encrypted copies the attacker writes."""
    test_dir = Path("test_files")
    if not test_dir.exists():
        return []

    flagged = []
    for f in sorted(test_dir.iterdir()):
        # only look at .encrypted files, skip honeyfile encrypted copies
        if f.suffix != ".encrypted":
            continue
        # strip .encrypted to get the original name for display
        original_name = f.stem   # e.g. "budget.txt" from "budget.txt.encrypted"
        if original_name in ("admin_honey.txt", "audit_trace.txt"):
            continue
        if not f.is_file():
            continue

        ent  = file_entropy(f)
        name = original_name
        now  = datetime.now().strftime("%H:%M:%S")

        # first time we see this file's encrypted copy — record it
        if name not in file_baselines:
            # baseline is what the original plaintext would have been (~3-5)
            # we approximate by reading the original if it still exists
            orig = test_dir / original_name
            file_baselines[name] = file_entropy(orig) if orig.exists() else 3.5
            file_entropy_history[name] = []

        file_entropy_history[name].append({"time": now, "entropy": round(ent, 3)})
        if len(file_entropy_history[name]) > 60:
            file_entropy_history[name].pop(0)

        jump = ent - file_baselines[name]
        already_flagged = any(a["file"] == name for a in entropy_alerts)
        if jump >= ENTROPY_JUMP_THRESH and not already_flagged:
            entropy_alerts.append({
                "file":     name,
                "time":     now,
                "baseline": round(file_baselines[name], 3),
                "current":  round(ent, 3),
                "jump":     round(jump, 3),
            })
            flagged.append(name)
            print(f"[!] ENTROPY SPIKE — {name}  {file_baselines[name]:.2f} → {ent:.2f}")

    return flagged

def compute_normal_score() -> tuple[int, dict]:
    """
    Second scoring track — runs on normal files, no registry needed.
    Returns (score, breakdown). Fires independently of the honeyfile track.
    Signals:
      - 10 pts per .encrypted copy of a normal file found
      - 15 pts per confirmed entropy spike (jump >= ENTROPY_JUMP_THRESH)
    Threshold: NORMAL_ALERT_THRESHOLD (40 pts → ≥ 3 files encrypted+spiked)
    """
    test_dir = Path("test_files")
    if not test_dir.exists():
        return 0, {}

    encrypted_copies = []
    spiked_files     = []
    spiked_set       = {a["file"] for a in entropy_alerts}

    for ef in test_dir.iterdir():
        if ef.suffix != ".encrypted":
            continue
        original_name = ef.stem
        if original_name in ("admin_honey.txt", "audit_trace.txt"):
            continue
        if not ef.is_file():
            continue
        encrypted_copies.append(original_name)
        if original_name in spiked_set:
            spiked_files.append(original_name)

    score = (len(encrypted_copies) * NORMAL_SCORE_PER_ENCRYPTED +
             len(spiked_files)     * NORMAL_SCORE_PER_SPIKE)

    breakdown = {
        "encrypted_normal_files":  len(encrypted_copies),
        "entropy_spiked_files":    len(spiked_files),
        "encrypted_score":         len(encrypted_copies) * NORMAL_SCORE_PER_ENCRYPTED,
        "entropy_score":           len(spiked_files)     * NORMAL_SCORE_PER_SPIKE,
        "total_score":             score,
        "track":                   "normal_files",
    }
    return score, breakdown

def get_attacker_pid():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and 'ransomware_agent' in proc.info['name'].lower():
                return proc.info['pid']
        except Exception:
            continue
    return None

def suspend_attacker(pid):
    try:
        psutil.Process(pid).suspend()
        return True
    except Exception:
        return False

def terminate_attacker(pid):
    try:
        p = psutil.Process(pid)
        p.resume()
        p.terminate()
        return True
    except Exception:
        return False

def recover_key():
    c2_log = Path("c2_server.log")
    if c2_log.exists():
        for line in open(c2_log):
            if 'KEY:' in line:
                for part in line.split():
                    if part.startswith('KEY:'):
                        return part[4:]
    return None

def write_report(honeyfile_name, pid, key, encrypted_count, score, breakdown):
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = EVIDENCE_DIR / f"incident_{timestamp}.json"
    report = {
        "timestamp":        datetime.now().isoformat(),
        "honeyfile":        honeyfile_name,
        "attacker_pid":     pid,
        "recovered_key":    key,
        "key_bits":         len(key) * 4 if key else 0,
        "encrypted_files":  encrypted_count,
        "status":           "suspended" if pid else "not_found",
        "threat_score":     score,
        "score_breakdown":  breakdown,
    }
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    return report

# ── Monitor loop (runs in background thread) ──────────────────────────────────

def monitor_loop():
    if not REGISTRY_PATH.exists():
        print("[!] Registry not found. Run: python app.py seed")
        return

    registry_bytes = REGISTRY_PATH.read_bytes()
    if not verify_registry_signature(registry_bytes):
        monitor_status["running"] = False
        return

    registry   = json.loads(registry_bytes)
    honeyfiles = {Path(p).name: (p, v) for p, v in registry.items()}

    monitor_status["running"]    = True
    monitor_status["honeyfiles"] = list(honeyfiles.keys())
    alerted = set()
    print(f"[*] Monitoring: {list(honeyfiles.keys())}")

    # pre-seed entropy baselines from original plaintext files before attack starts
    test_dir = Path("test_files")
    if test_dir.exists():
        for f in test_dir.iterdir():
            if f.is_file() and f.suffix != ".encrypted" and f.name not in ("admin_honey.txt", "audit_trace.txt"):
                file_baselines[f.name]       = file_entropy(f)
                file_entropy_history[f.name] = []
                print(f"[*] Baseline {f.name}: {file_baselines[f.name]:.3f} bits/byte")

    while True:
        try:
            monitor_status["last_scan"] = datetime.now().isoformat()
            tick_time      = datetime.now().strftime("%H:%M:%S")
            tick_max       = 0
            tick_breakdown = {}

            for name, (full_path, reg_entry) in honeyfiles.items():
                try:
                    score, breakdown = compute_score(name, reg_entry, full_path)
                except Exception as e:
                    print(f"[!] compute_score error for {name}: {e}")
                    score, breakdown = 0, {}

                score_history.append({
                    "time":      tick_time,
                    "file":      name,
                    "score":     score,
                    "breakdown": breakdown
                })

                if score > tick_max:
                    tick_max       = score
                    tick_breakdown = breakdown

                if score >= ALERT_THRESHOLD and name not in alerted:
                    alerted.add(name)
                    try:
                        encrypted_count = len(list(Path("test_files").glob("*.encrypted")))
                        pid  = get_attacker_pid()
                        if pid:
                            suspend_attacker(pid)
                        key    = recover_key()
                        report = write_report(name, pid, key, encrypted_count, score, breakdown)
                        alert_events.append(report)
                        print(f"[!!!] ALERT — {name}  score={score}")
                    except Exception as e:
                        print(f"[!] Alert handling error: {e}")

            score_history.append({
                "time":      tick_time,
                "file":      "__chart__",
                "score":     tick_max,
                "breakdown": tick_breakdown
            })

            while len(score_history) > 120:
                score_history.pop(0)

            try:
                scan_normal_files()
            except Exception as e:
                print(f"[!] scan_normal_files error: {e}")

            # ── Normal-file scoring track (fallback if honeyfiles avoided) ──
            try:
                n_score, n_breakdown = compute_normal_score()

                # push to chart history so it shows on the live graph
                if n_score > tick_max:
                    tick_max       = n_score
                    tick_breakdown = n_breakdown

                score_history.append({
                    "time":      tick_time,
                    "file":      "__normal_track__",
                    "score":     n_score,
                    "breakdown": n_breakdown,
                })

                if n_score >= NORMAL_ALERT_THRESHOLD and "normal_track" not in alerted:
                    alerted.add("normal_track")
                    try:
                        encrypted_count = len(list(Path("test_files").glob("*.encrypted")))
                        pid  = get_attacker_pid()
                        if pid:
                            suspend_attacker(pid)
                        key    = recover_key()
                        report = write_report(
                            "normal_file_track", pid, key,
                            encrypted_count, n_score, n_breakdown
                        )
                        alert_events.append(report)
                        print(f"[!!!] NORMAL-TRACK ALERT  score={n_score}  "
                              f"({n_breakdown['encrypted_normal_files']} files encrypted, "
                              f"{n_breakdown['entropy_spiked_files']} spiked)")
                    except Exception as e:
                        print(f"[!] Normal-track alert error: {e}")

            except Exception as e:
                print(f"[!] compute_normal_score error: {e}")

        except Exception as e:
            print(f"[!] Monitor loop error: {e}")

        time.sleep(0.5)

# ── Flask routes ──────────────────────────────────────────────────────────────

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/health')
def health():
    registry_ok = False
    if REGISTRY_PATH.exists():
        registry_ok = verify_registry_signature(REGISTRY_PATH.read_bytes())
    return jsonify({
        "monitor_running":   monitor_status["running"],
        "last_scan":         monitor_status["last_scan"],
        "score_history_len": len(score_history),
        "alert_count":       len(alert_events),
        "registry_integrity": registry_ok,
    })

@app.route('/api/status')
def status():
    encrypted_files = list(Path("test_files").glob("*.encrypted")) if Path("test_files").exists() else []
    return jsonify({
        "monitor":         monitor_status,
        "alerts":          len(alert_events),
        "encrypted_count": len(encrypted_files),
        "encrypted_files": [f.name for f in encrypted_files],
    })

@app.route('/api/events')
def events():
    return jsonify(alert_events)

@app.route('/api/scores')
def scores():
    return jsonify(score_history)

@app.route('/api/terminate/<int:pid>', methods=['POST'])
def terminate(pid):
    ok = terminate_attacker(pid)
    return jsonify({"success": ok, "pid": pid})

@app.route('/api/entropy')
def entropy_data():
    return jsonify({
        "history":  file_entropy_history,
        "baselines": file_baselines,
        "alerts":   entropy_alerts,
    })

@app.route('/api/reports')
def reports():
    items = []
    for f in sorted(EVIDENCE_DIR.glob("incident_*.json"), reverse=True)[:20]:
        try:
            items.append(json.loads(f.read_text()))
        except Exception:
            pass
    return jsonify(items)

# ── Seed (kept here for convenience) ─────────────────────────────────────────

def seed_honeyfiles():
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto.Random import get_random_bytes
    from collections import Counter as _Counter

    AES_KEY   = get_random_bytes(32)
    TOKEN     = b"HONEY_TOKEN_ACTIVE"
    LOCATIONS = ["test_files/admin_honey.txt", "test_files/audit_trace.txt"]

    registry = {}
    for path_str in LOCATIONS:
        path = Path(path_str).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            os.chmod(path, 0o600)
            path.unlink()

        iv         = get_random_bytes(16)
        cipher     = AES.new(AES_KEY, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(TOKEN, AES.block_size))
        path.write_bytes(ciphertext)
        os.chmod(path, 0o400)

        registry[str(path)] = {
            "iv":               iv.hex(),
            "key":              AES_KEY.hex(),
            "original_header":  ciphertext[:16].hex(),
            "baseline_entropy": round(-sum((v/len(ciphertext))*math.log2(v/len(ciphertext)) for v in _Counter(ciphertext).values()), 3),
            "created":          datetime.now().isoformat(),
        }

    registry_bytes = json.dumps(registry, indent=2).encode()
    REGISTRY_PATH.write_text(registry_bytes.decode())
    sig = sign_registry(registry_bytes)
    HMAC_SIG_PATH.write_text(sig)
    os.chmod(HMAC_SIG_PATH, 0o600)
    print(f"[+] Registry signed  (HMAC-SHA256: {sig[:16]}...)")
    print(f"[+] Seeded {len(LOCATIONS)} honeyfiles")

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seed":
        seed_honeyfiles()
        sys.exit(0)

    # start monitor in background thread
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()

    print("[*] Dashboard → http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False, threaded=True)