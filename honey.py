"""
Student S — Week 3: Suspend-First Protocol with Cryptographic Evidence
======================================================================
Builds on Week 2 (weighted scoring + entropy detection) and adds:
  1. Process suspension — freeze attacker immediately on threshold breach
  2. Memory forensics — scan frozen process for AES key schedules
  3. GUI alert — Tkinter popup showing full incident details
  4. Forensic report — structured JSON evidence capture

Dependencies:
    pip install pycryptodome watchdog psutil

Usage:
    python honeyfile_week3.py seed     # Plant honeyfiles
    python honeyfile_week3.py monitor  # Live monitor with full Week 3 response
    python honeyfile_week3.py verify   # Manual integrity check
    python honeyfile_week3.py clean    # Remove all honeyfiles

Week 3 flow:
    Honeyfile touched
        → Weighted scorer breaches threshold (Week 2)
        → Suspend attacker process immediately
        → Scan process memory for AES key material
        → Pop GUI alert with full forensic details
        → Write evidence report to disk
"""

import os
import sys
import re
import math
import json
import time
import hmac
import struct
import hashlib
import logging
import argparse
import platform
import subprocess
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime, timezone
from pathlib import Path

import psutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

AES_KEY  = get_random_bytes(32)
HMAC_KEY = get_random_bytes(32)

HONEY_TOKEN = b"HONEY_TOKEN_ACTIVE"

HONEYFILE_LOCATIONS = [
    Path("test_files/budget_report.pdf"),
    Path("test_files/client_creds.txt"),
    Path("test_files/contract.docx"),
    Path("test_files/api_keys.json"),
    Path("test_files/financials.xlsx"),
]

REGISTRY_PATH   = Path.home() / ".honeyfile_registry.json"
LOG_FILE        = Path.home() / "honeyfile_alerts.log"
ALERT_LOG       = Path.home() / "honeyfile_alerts.jsonl"
EVIDENCE_DIR    = Path.home() / "honeyfile_evidence"

SCORE_WEIGHTS = {
    "ACCESS":    50,
    "MODIFIED":  100,
    "ENCRYPTED": 150,
}
ALERT_THRESHOLD = 250
ENTROPY_HIGH    = 7.5
ENTROPY_MEDIUM  = 6.0

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("HoneyfileMonitor")

EVIDENCE_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────
# REGISTRY
# ─────────────────────────────────────────────

def load_registry() -> dict:
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH) as f:
            return json.load(f)
    return {}

def save_registry(registry: dict):
    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)
    os.chmod(REGISTRY_PATH, 0o600)

# ─────────────────────────────────────────────
# CRYPTO HELPERS
# ─────────────────────────────────────────────

def encrypt_token(token: bytes) -> tuple[bytes, bytes]:
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(token, AES.block_size))

def decrypt_and_verify(filepath: Path) -> tuple[bool, str]:
    registry = load_registry()
    key = str(Path(filepath).resolve())
    if key not in registry:
        return False, "Not in registry"
    meta = registry[key]
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return False, "File missing"

    expected_mac = meta["hmac"]
    actual_mac   = hmac.new(HMAC_KEY, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, actual_mac):
        return False, "HMAC mismatch — tampered"

    iv = bytes.fromhex(meta["iv"])
    try:
        cipher    = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(raw), AES.block_size)
    except (ValueError, KeyError) as e:
        return False, f"Decryption failed: {e}"

    if decrypted != HONEY_TOKEN:
        return False, "Token mismatch"
    return True, "OK"

# ─────────────────────────────────────────────
# ENTROPY (from Week 2)
# ─────────────────────────────────────────────

def calculate_shannon_entropy(filepath: Path) -> float:
    with open(filepath, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length  = len(data)
    for count in freq:
        if count == 0:
            continue
        p        = count / length
        entropy -= p * math.log2(p)
    return entropy

def detect_encryption_by_entropy(filepath: Path, baseline: float = None) -> tuple[int, str]:
    try:
        entropy = calculate_shannon_entropy(filepath)
    except Exception as e:
        return 0, f"Could not read: {e}"
    log.info(f"[ENTROPY] {filepath.name} → {entropy:.3f}"
             + (f"  (baseline {baseline:.3f})" if baseline else ""))

    # Absolute high entropy — clearly encrypted regardless of baseline
    if entropy > ENTROPY_HIGH:
        return SCORE_WEIGHTS["ENCRYPTED"], f"High entropy {entropy:.3f}"

    # Delta detection — only flag if BOTH the jump is large AND entropy is elevated
    # Prevents false positive when baseline == current (startup noise, metadata writes)
    if baseline is not None:
        delta = entropy - baseline
        if delta > 2.0 and entropy > ENTROPY_MEDIUM:
            return SCORE_WEIGHTS["ENCRYPTED"], f"Entropy jumped +{delta:.3f} (now {entropy:.3f})"

    if entropy > ENTROPY_MEDIUM:
        return 50, f"Medium entropy {entropy:.3f}"

    return 0, f"Normal entropy {entropy:.3f}"

# ─────────────────────────────────────────────
# WEEK 3 — PROCESS IDENTIFICATION
# ─────────────────────────────────────────────

def get_accessor_pid(filepath: Path) -> tuple[int | None, str]:
    """
    Find the attacker process using three methods in order:
      1. lsof on the honeyfile (works if file handle still open)
      2. lsof on the .encrypted copy being written
      3. psutil scan — find any process whose cwd matches the
         target directory (catches fast processes already done)
    """
    targets = [filepath, Path(str(filepath) + ".encrypted")]
    for target in targets:
        try:
            result = subprocess.run(
                ["lsof", str(target)],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1]), parts[0]
                    except ValueError:
                        continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # psutil scan — match by working directory or open .encrypted files
    target_dir = str(filepath.parent.resolve())
    ATTACKER_BINARY_NAMES = {"ransomware", "a.out", "main", "attacker"}
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "cwd", "open_files"]):
            try:
                info = proc.info
                # Match by open files in the target directory (most reliable)
                if info.get("open_files"):
                    for f in info["open_files"]:
                        if target_dir in f.path:
                            return proc.pid, info.get("name", "unknown")
                # Match by known attacker binary name
                if info.get("name", "").lower() in ATTACKER_BINARY_NAMES:
                    return proc.pid, info.get("name", "unknown")
                # Match by cwd — resolve to handle symlinks
                try:
                    cwd = proc.cwd()
                    if cwd == target_dir or target_dir in str(cwd):
                        return proc.pid, info.get("name", "unknown")
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                if info.get("exe") and target_dir in str(info.get("exe", "")):
                    return proc.pid, info.get("name", "unknown")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        log.warning(f"[PID SCAN] psutil scan error: {e}")

    return None, "Process exited before capture"


def get_process_info(pid: int) -> dict:
    """Collect forensic metadata about a process before suspending it."""
    try:
        proc = psutil.Process(pid)
        return {
            "pid":        pid,
            "name":       proc.name(),
            "exe":        proc.exe(),
            "cmdline":    " ".join(proc.cmdline()),
            "cwd":        proc.cwd(),
            "status":     proc.status(),
            "created":    datetime.fromtimestamp(
                              proc.create_time(), tz=timezone.utc
                          ).isoformat(),
            "username":   proc.username(),
            "open_files": [f.path for f in proc.open_files()],
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"pid": pid, "error": str(e)}

# ─────────────────────────────────────────────
# WEEK 3 — PROCESS SUSPENSION
# ─────────────────────────────────────────────

def suspend_attacker(pid: int) -> bool:
    """
    Suspend (freeze) the attacker process.

    Why suspend instead of kill?
      Killing immediately destroys in-memory data including any
      encryption keys the attacker hasn't wiped yet.
      Suspending freezes execution while keeping memory intact
      so we can scan it for key material first.
    """
    try:
        proc = psutil.Process(pid)
        proc.suspend()
        log.critical(f"[SUSPENDED] PID {pid} ({proc.name()}) — process frozen")
        return True
    except psutil.NoSuchProcess:
        log.warning(f"[SUSPEND FAILED] PID {pid} no longer exists")
        return False
    except psutil.AccessDenied:
        log.warning(f"[SUSPEND FAILED] Access denied for PID {pid} — may need sudo")
        return False

def terminate_attacker(pid: int):
    """Terminate after evidence capture is complete."""
    try:
        proc = psutil.Process(pid)
        proc.resume()    # Resume briefly so it can be killed cleanly
        proc.terminate()
        gone, alive = psutil.wait_procs([proc], timeout=5)
        if alive:
            alive[0].kill()   # Force kill if terminate didn't work
        log.info(f"[TERMINATED] PID {pid}")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
        log.warning(f"[TERMINATE] {e}")

# ─────────────────────────────────────────────
# WEEK 3 — ENCRYPTION ALGORITHM DETECTION
# ─────────────────────────────────────────────

def detect_encryption_algorithm(encrypted_path: Path) -> str:
    """
    Identify encryption by inspecting the .encrypted file.
    Student A's attacker prepends a 16-byte random IV before AES-CBC ciphertext.
    We detect this by:
      - No known file magic bytes (PDF, PNG, ZIP etc.)
      - File size is a multiple of 16 (AES block size)
      - First 16 bytes (IV) have high entropy
    """
    try:
        with open(encrypted_path, "rb") as f:
            header = f.read(64)
        file_size = encrypted_path.stat().st_size

        magic = {
            b"%PDF": "PDF (plaintext)",
            b"\x89PNG": "PNG (plaintext)",
            b"PK\x03\x04": "ZIP/Office (plaintext)",
            b"\xff\xd8\xff": "JPEG (plaintext)",
        }
        for sig, name in magic.items():
            if header.startswith(sig):
                return name

        if file_size % 16 == 0 and len(header) >= 16:
            iv_bytes = header[:16]
            unique   = len(set(iv_bytes))
            if unique > 10:
                return f"AES-256-CBC (16-byte IV, block-aligned {file_size}B, {unique}/256 unique IV bytes)"

        return "Unknown cipher or compression"
    except Exception as e:
        return f"Could not analyse: {e}"


# ─────────────────────────────────────────────
# WEEK 3 — KEY RECOVERY FROM C2 LOG
# ─────────────────────────────────────────────

def recover_key_from_c2_log(c2_log: Path = Path("c2_server.log")) -> list[dict]:
    """
    Parse the attacker's exfiltrated key from c2_server.log.
    Student A logs: [timestamp] SESSION:xxx PID:yyy KEY:zzz
    The key is here even after forensic_wipe_memory() runs —
    exfiltration happened before the wipe.
    Returns list of sessions, most recent first.
    """
    sessions = []
    if not c2_log.exists():
        log.warning(f"[KEY RECOVERY] {c2_log} not found")
        return sessions
    try:
        with open(c2_log) as f:
            for line in f:
                line = line.strip()
                if "KEY:" not in line:
                    continue
                s = {"raw": line}
                for part in line.split():
                    if part.startswith("SESSION:"):
                        s["session_id"] = part[8:]
                    elif part.startswith("PID:"):
                        s["pid"] = part[4:]
                    elif part.startswith("KEY:"):
                        s["key_hex"] = part[4:]
                        s["key_bits"] = len(part[4:]) * 4
                if "key_hex" in s:
                    sessions.append(s)
    except Exception as e:
        log.warning(f"[KEY RECOVERY] Parse error: {e}")

    sessions.reverse()
    if sessions:
        k = sessions[0]
        log.info(f"[KEY RECOVERY] {len(sessions)} session(s) found — "
                 f"latest: {k['key_hex'][:16]}... ({k['key_bits']} bits)")
    return sessions


# ─────────────────────────────────────────────
# WEEK 3 — MEMORY FORENSICS
# ─────────────────────────────────────────────

def scan_memory_region(data: bytes) -> list[str]:
    candidates = []
    for key_len in [16, 24, 32]:
        for i in range(0, len(data) - key_len, 4):
            chunk = data[i:i + key_len]
            if len(set(chunk)) < 10:
                continue
            freq = [0] * 256
            for b in chunk:
                freq[b] += 1
            entropy = -sum(
                (c / key_len) * math.log2(c / key_len)
                for c in freq if c > 0
            )
            if entropy > 7.0:
                candidates.append(chunk.hex())
    return list(dict.fromkeys(candidates))


def scan_process_memory(pid: int) -> list[str]:
    """
    Linux: read /proc/{pid}/mem for key material.
    macOS: direct memory read requires entitlements —
           fall back to c2_server.log key recovery instead.
    """
    candidates = []

    if platform.system() == "Linux":
        try:
            with open(f"/proc/{pid}/maps") as mf:
                for line in mf:
                    if "rw" not in line:
                        continue
                    parts = line.split()
                    start, end = [int(x, 16) for x in parts[0].split("-")]
                    size = end - start
                    if size < 16 or size > 10 * 1024 * 1024:
                        continue
                    try:
                        with open(f"/proc/{pid}/mem", "rb") as mem:
                            mem.seek(start)
                            candidates.extend(scan_memory_region(mem.read(size)))
                    except (OSError, OverflowError):
                        continue
        except (FileNotFoundError, PermissionError) as e:
            log.warning(f"[MEMORY] {e}")

    elif platform.system() == "Darwin":
        log.info("[MEMORY] macOS: direct memory access requires entitlements")
        log.info("[MEMORY] Using C2 log recovery as forensic key source")
        sessions = recover_key_from_c2_log()
        candidates = [s["key_hex"] for s in sessions]

    log.info(f"[MEMORY] {len(candidates)} key candidate(s) recovered")
    return candidates[:10]


# ─────────────────────────────────────────────
# WEEK 3 — FORENSIC REPORT
# ─────────────────────────────────────────────

def write_evidence_report(honeyfile: Path, pid: int | None,
                           proc_info: dict, key_candidates: list[str],
                           event_history: list[dict],
                           algorithm: str = "Unknown",
                           c2_sessions: list = None) -> Path:
    """Write structured JSON evidence report — the forensic artifact."""
    timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = EVIDENCE_DIR / f"incident_{timestamp}.json"

    encrypted_copy = Path(str(honeyfile) + ".encrypted")

    report = {
        "incident": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host":      platform.node(),
            "os":        platform.platform(),
        },
        "honeyfile": {
            "path":            str(honeyfile),
            "integrity_valid": decrypt_and_verify(honeyfile)[0],
            "encrypted_copy":  str(encrypted_copy) if encrypted_copy.exists() else None,
        },
        "encryption_analysis": {
            "algorithm_detected": algorithm,
            "source":             str(encrypted_copy) if encrypted_copy.exists() else "N/A",
        },
        "attacker_process": proc_info,
        "key_forensics": {
            "memory_candidates":    key_candidates,
            "c2_log_sessions":      c2_sessions or [],
            "recovered_key":        c2_sessions[0]["key_hex"] if c2_sessions else None,
            "recovered_key_bits":   c2_sessions[0]["key_bits"] if c2_sessions else None,
            "note": "Key from c2_server.log — exfiltrated before memory wipe",
        },
        "event_chain":    event_history,
        "response_taken": "Process suspended. Awaiting analyst decision.",
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    log.info(f"[EVIDENCE] Report → {report_path}")
    return report_path


# ─────────────────────────────────────────────
# WEEK 3 — GUI ALERT
# ─────────────────────────────────────────────

# Global queue for passing alert data from watchdog thread → main thread
_alert_queue = []
_alert_lock  = threading.Lock()


def show_gui_alert(honeyfile: Path, pid: int | None, proc_info: dict,
                   key_candidates: list[str], report_path: Path,
                   algorithm: str = "Unknown", c2_sessions: list = None,
                   on_terminate=None):
    """Queue alert for main thread — macOS requires Tkinter on main thread."""
    with _alert_lock:
        _alert_queue.append({
            "honeyfile":      honeyfile,
            "pid":            pid,
            "proc_info":      proc_info,
            "key_candidates": key_candidates,
            "report_path":    report_path,
            "algorithm":      algorithm,
            "c2_sessions":    c2_sessions or [],
            "on_terminate":   on_terminate,
        })


def _build_gui(alert: dict):
    """Build Tkinter alert. Must be called on main thread."""
    honeyfile      = alert["honeyfile"]
    pid            = alert["pid"]
    proc_info      = alert["proc_info"]
    key_candidates = alert["key_candidates"]
    report_path    = alert["report_path"]
    algorithm      = alert["algorithm"]
    c2_sessions    = alert["c2_sessions"]
    on_terminate   = alert["on_terminate"]

    recovered_key  = c2_sessions[0]["key_hex"] if c2_sessions else None
    key_bits       = c2_sessions[0].get("key_bits", "?") if c2_sessions else "?"

    root = tk.Tk()
    root.title("HONEYFILE ALERT — Intrusion Detected")
    root.configure(bg="#1a1a2e")
    root.geometry("700x640")
    root.resizable(False, False)

    # ── Header ──
    tk.Label(root, text="⚠  HONEYFILE TRIGGERED",
             font=("Courier", 18, "bold"), fg="#ff4444", bg="#1a1a2e"
             ).pack(pady=(20, 5))
    tk.Label(root, text=datetime.now(timezone.utc).strftime("UTC %Y-%m-%d %H:%M:%S"),
             font=("Courier", 10), fg="#888888", bg="#1a1a2e").pack()

    # ── Incident details ──
    frame = tk.Frame(root, bg="#16213e", bd=1, relief="solid")
    frame.pack(fill="x", padx=20, pady=12)

    fields = [
        ("Honeyfile",    str(honeyfile.name)),
        ("Attacker PID", str(pid) if pid else "Exited before capture"),
        ("Process",      proc_info.get("name", "Unknown")),
        ("Executable",   proc_info.get("exe",  "Unknown")),
        ("Status",       "🔴 SUSPENDED" if pid else "⚠  Process already exited"),
        ("Algorithm",    algorithm),
        ("Key Status",   f"✅ RECOVERED ({key_bits}-bit)" if recovered_key
                         else "❌ Not recovered"),
        ("Evidence",     report_path.name),
    ]

    for label, value in fields:
        row = tk.Frame(frame, bg="#16213e")
        row.pack(fill="x", padx=10, pady=3)
        tk.Label(row, text=f"{label}:", width=16, anchor="w",
                 font=("Courier", 10, "bold"), fg="#00d4ff", bg="#16213e"
                 ).pack(side="left")
        tk.Label(row, text=value[:70], anchor="w",
                 font=("Courier", 10), fg="#ffffff", bg="#16213e"
                 ).pack(side="left")

    # ── Recovered key box ──
    key_label = "🔑 Recovered Encryption Key (from C2 log):" \
                if recovered_key else "🔑 Key Recovery:"
    tk.Label(root, text=key_label,
             font=("Courier", 10, "bold"), fg="#ffaa00", bg="#1a1a2e"
             ).pack(anchor="w", padx=20, pady=(8, 2))

    key_box = tk.Text(root, height=2, font=("Courier", 9),
                      bg="#0f0f23", fg="#00ff88", bd=0, padx=6, pady=4)
    key_box.pack(fill="x", padx=20)
    if recovered_key:
        key_box.insert("end", f"{recovered_key}\n({key_bits}-bit AES key)")
    else:
        key_box.insert("end", "Key not found in C2 log.\nRun: cat c2_server.log")
    key_box.config(state="disabled")

    # ── Buttons ──
    btn_frame = tk.Frame(root, bg="#1a1a2e")
    btn_frame.pack(pady=16)

    def on_terminate_click():
        if pid and on_terminate:
            on_terminate(pid)
        root.destroy()

    tk.Button(btn_frame, text="Terminate Process",
              font=("Courier", 11, "bold"),
              bg="#ff4444", fg="white", activebackground="#cc0000",
              padx=20, pady=8, command=on_terminate_click
              ).pack(side="left", padx=10)

    tk.Button(btn_frame, text="Dismiss",
              font=("Courier", 11),
              bg="#444444", fg="white", activebackground="#222222",
              padx=20, pady=8, command=root.destroy
              ).pack(side="left", padx=10)

    root.mainloop()


# ─────────────────────────────────────────────
# WEEK 2 SCORER (carried forward)
# ─────────────────────────────────────────────

class ThreatScorer:
    def __init__(self, threshold=ALERT_THRESHOLD):
        self.scores    = {}
        self.history   = {}
        self.threshold = threshold
        self.escalated = set()
        self.enabled   = False   # starts disabled until warm-up completes

    def record_event(self, filepath: Path, event_type: str, detail: str = ""):
        if not self.enabled:
            log.info(f"[WARMUP] Ignoring startup noise: {filepath.name} {event_type}")
            return
        key   = str(filepath)
        score = SCORE_WEIGHTS.get(event_type, 0)
        self.scores[key] = self.scores.get(key, 0) + score
        self.history.setdefault(key, []).append({
            "time":   datetime.now(timezone.utc).isoformat(),
            "event":  event_type,
            "score":  score,
            "detail": detail,
        })
        total = self.scores[key]
        log.info(f"[SCORE] {filepath.name}  +{score} ({event_type}) → total {total}")

        if total >= self.threshold and key not in self.escalated:
            self.escalated.add(key)
            self.full_response(filepath, total)

    def full_response(self, filepath: Path, total: int):
        log.critical(
            f"\n{'='*60}\n"
            f"THRESHOLD BREACHED: {filepath.name}  score={total}\n"
            f"Initiating Week 3 response protocol...\n"
            f"{'='*60}"
        )

        # Step 1: identify process
        pid, proc_name = get_accessor_pid(filepath)
        log.info(f"[FORENSIC] Accessor: PID={pid}  name={proc_name}")

        # Step 2: suspend immediately — preserves memory before wipe
        if pid:
            suspend_attacker(pid)

        # Step 3: collect process metadata
        proc_info = get_process_info(pid) if pid else {}

        # Step 4: detect encryption algorithm from .encrypted file
        encrypted_copy = Path(str(filepath) + ".encrypted")
        algorithm = detect_encryption_algorithm(encrypted_copy) \
                    if encrypted_copy.exists() else "No encrypted copy found yet"
        log.info(f"[FORENSIC] Algorithm: {algorithm}")

        # Step 5: recover key — memory scan on Linux, C2 log on macOS
        key_candidates = scan_process_memory(pid) if pid else []
        # Always also check C2 log — key is there even after memory wipe
        c2_sessions = recover_key_from_c2_log()
        if not key_candidates and c2_sessions:
            key_candidates = [c2_sessions[0]["key_hex"]]

        # Step 6: write evidence report
        history     = self.history.get(str(filepath), [])
        report_path = write_evidence_report(
            filepath, pid, proc_info, key_candidates,
            history, algorithm, c2_sessions
        )

        # Step 7: GUI alert
        show_gui_alert(
            filepath, pid, proc_info, key_candidates,
            report_path, algorithm, c2_sessions,
            on_terminate=terminate_attacker,
        )

        trigger_alert(filepath, "FULL_RESPONSE_INITIATED",
                      f"PID={pid} suspended, algo={algorithm}, "
                      f"key={'RECOVERED' if key_candidates else 'NOT FOUND'}, "
                      f"report={report_path}")


scorer = ThreatScorer()


# ─────────────────────────────────────────────
# ALERT LOGGER
# ─────────────────────────────────────────────

def trigger_alert(path: Path, event_type: str, detail: str = ""):
    msg = (
        f"\n{'='*60}\n"
        f"🚨 HONEYFILE ALERT\n"
        f"   Time:   {datetime.now(timezone.utc).isoformat()}Z\n"
        f"   File:   {path}\n"
        f"   Event:  {event_type}\n"
        f"   Host:   {platform.node()}\n"
        f"   Detail: {detail}\n"
        f"{'='*60}\n"
    )
    log.critical(msg)
    with open(ALERT_LOG, "a") as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file":      str(path),
            "event":     event_type,
            "detail":    detail,
            "host":      platform.node(),
        }, f)
        f.write("\n")


# ─────────────────────────────────────────────
# WATCHDOG HANDLER
# ─────────────────────────────────────────────

class HoneyfileEventHandler(FileSystemEventHandler):

    def __init__(self, watched_paths: set[str]):
        self.watched_paths = watched_paths

    def _is_honeyfile(self, path: str) -> bool:
        return str(Path(path).resolve()) in self.watched_paths

    def _analyse(self, filepath: Path, base_event: str):
        registry = load_registry()
        meta     = registry.get(str(filepath.resolve()), {})
        baseline = meta.get("baseline_entropy")

        scorer.record_event(filepath, base_event)

        entropy_score, entropy_reason = detect_encryption_by_entropy(filepath, baseline)
        if entropy_score > 0:
            scorer.record_event(filepath, "ENCRYPTED", entropy_reason)

        # Only run integrity check post-warm-up — avoids spurious HMAC errors on startup
        if scorer.enabled:
            is_valid, reason = decrypt_and_verify(filepath)
            if not is_valid:
                scorer.record_event(filepath, "ENCRYPTED", f"Decryption: {reason}")
            else:
                log.info(f"[INTEGRITY OK] {filepath.name}")

    def on_accessed(self, event):
        if not event.is_directory and self._is_honeyfile(event.src_path):
            path = Path(event.src_path)
            trigger_alert(path, "ACCESS")
            self._analyse(path, "ACCESS")

    def on_modified(self, event):
        if not event.is_directory and self._is_honeyfile(event.src_path):
            path = Path(event.src_path)
            trigger_alert(path, "MODIFIED")
            self._analyse(path, "MODIFIED")

    def on_deleted(self, event):
        if not event.is_directory and self._is_honeyfile(event.src_path):
            path = Path(event.src_path)
            trigger_alert(path, "DELETED", "Possible ransomware")
            scorer.record_event(path, "ENCRYPTED", "File deleted")
            # Deleted honeyfile is unambiguous — bypass threshold and respond immediately
            if scorer.enabled and str(path) not in scorer.escalated:
                scorer.escalated.add(str(path))
                scorer.full_response(path, ALERT_THRESHOLD)

    def on_moved(self, event):
        if not event.is_directory and self._is_honeyfile(event.src_path):
            path = Path(event.src_path)
            trigger_alert(path, "MOVED", f"→ {event.dest_path}")
            scorer.record_event(path, "MODIFIED", "Relocated")

    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        # Existing honeyfile was recreated
        if self._is_honeyfile(event.src_path):
            trigger_alert(path, "RECREATED")
            self._analyse(path, "MODIFIED")
            return
        # Attacker created a .encrypted copy alongside a known honeyfile
        # (attacker writes file.txt.encrypted without touching file.txt)
        if path.suffix == ".encrypted":
            original = Path(str(path)[:-len(".encrypted")])
            if self._is_honeyfile(str(original)):
                trigger_alert(original, "ENCRYPTED_COPY_CREATED",
                              f"Attacker created {path.name} next to honeyfile")
                scorer.record_event(original, "MODIFIED", "Encrypted copy created")
                scorer.record_event(original, "ENCRYPTED",
                                    f"Encrypted copy detected: {path.name}")


# ─────────────────────────────────────────────
# SEED
# ─────────────────────────────────────────────

def seed_honeyfiles():
    registry = load_registry()
    for path in HONEYFILE_LOCATIONS:
        path = path.resolve()           # always use absolute paths
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            log.info(f"[SKIP] {path}")
            continue
        iv, ciphertext = encrypt_token(HONEY_TOKEN)
        with open(path, "wb") as f:
            f.write(ciphertext)
        mac              = hmac.new(HMAC_KEY, ciphertext, hashlib.sha256).hexdigest()
        baseline_entropy = calculate_shannon_entropy(path)
        os.chmod(path, 0o400)
        registry[str(path)] = {
            "iv":               iv.hex(),
            "hmac":             mac,
            "created":          datetime.now(timezone.utc).isoformat(),
            "size_bytes":       len(ciphertext),
            "baseline_entropy": baseline_entropy,
        }
        log.info(f"[SEEDED] {path}  entropy_baseline={baseline_entropy:.3f}")
    save_registry(registry)
    log.info(f"Registry saved → {REGISTRY_PATH}")


# ─────────────────────────────────────────────
# VERIFY
# ─────────────────────────────────────────────

def verify_all_honeyfiles():
    registry = load_registry()
    if not registry:
        log.warning("No honeyfiles registered.")
        return
    for filepath_str, meta in registry.items():
        path = Path(filepath_str)
        log.info(f"\n── {path} ──")
        score, reason = detect_encryption_by_entropy(path, meta.get("baseline_entropy"))
        log.info(f"  Entropy:   +{score}  {reason}")
        valid, msg = decrypt_and_verify(path)
        if valid:
            log.info(f"  Integrity: OK")
        else:
            log.critical(f"  Integrity: FAIL — {msg}")
            trigger_alert(path, "VERIFICATION_FAILURE", msg)


# ─────────────────────────────────────────────
# MONITOR
# ─────────────────────────────────────────────

def start_monitor():
    registry = load_registry()
    if not registry:
        log.error("No honeyfiles registered. Run 'seed' first.")
        sys.exit(1)

    watched_paths = {str(Path(p).resolve()) for p in registry}
    dirs_to_watch = {}
    for abs_path in watched_paths:
        parent = str(Path(abs_path).parent)
        dirs_to_watch.setdefault(parent, set()).add(abs_path)

    handler   = HoneyfileEventHandler(watched_paths)
    observers = []

    for directory in dirs_to_watch:
        observer = Observer()
        observer.schedule(handler, path=directory, recursive=False)
        observer.start()
        observers.append(observer)
        log.info(f"[WATCH] {directory}")

    log.info(
        f"Week 3 monitor active — {len(watched_paths)} honeyfiles\n"
        f"Threshold: {ALERT_THRESHOLD}  |  "
        f"Evidence dir: {EVIDENCE_DIR}\n"
        f"On breach: suspend → memory scan → GUI alert → evidence report\n"
        f"Warm-up: 3 seconds (ignoring startup filesystem noise)..."
    )

    # macOS FSEvents fires spurious MODIFIED events on watched files the moment
    # the observer registers — wait 3 seconds before scoring starts
    time.sleep(3)
    scorer.enabled = True
    log.info("Warm-up complete — now monitoring. Press Ctrl+C to stop.")

    try:
        while True:
            # Poll the alert queue on the main thread — required on macOS
            # because Tkinter/NSWindow must be instantiated on the main thread.
            # Watchdog fires on a background thread so GUI calls are queued
            # and drained here on every loop tick instead.
            with _alert_lock:
                pending = list(_alert_queue)
                _alert_queue.clear()

            for alert in pending:
                _build_gui(alert)   # safe — we are on main thread here

            time.sleep(0.25)   # 250ms poll keeps UI responsive

    except KeyboardInterrupt:
        log.info("Stopping...")
        for obs in observers:
            obs.stop()
        for obs in observers:
            obs.join()


# ─────────────────────────────────────────────
# CLEAN
# ─────────────────────────────────────────────

def clean_honeyfiles():
    registry = load_registry()
    for filepath_str in registry:
        path = Path(filepath_str)
        if path.exists():
            os.chmod(path, 0o600)
            path.unlink()
            log.info(f"[REMOVED] {path}")
    if REGISTRY_PATH.exists():
        REGISTRY_PATH.unlink()
    log.info("Clean complete.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Student S — Week 3: Suspend-First Protocol"
    )
    parser.add_argument("command", choices=["seed", "verify", "monitor", "clean"])
    args = parser.parse_args()
    {"seed": seed_honeyfiles, "verify": verify_all_honeyfiles,
     "monitor": start_monitor, "clean": clean_honeyfiles}[args.command]()

if __name__ == "__main__":
    main()