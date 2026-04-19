import os
import sys
import json
import math
import time
import psutil
import tkinter as tk
from pathlib import Path
from datetime import datetime
from collections import Counter

REGISTRY_PATH = Path.home() / ".honeyfile_registry.json"
EVIDENCE_DIR = Path.home() / "honeyfile_evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)

# ── Weighted scoring thresholds 
SCORE_ENCRYPTED_FILE = 50  # .encrypted file appeared
SCORE_HIGH_ENTROPY = 30  # entropy jumped to near-random
SCORE_HEADER_CHANGED = 15  # magic bytes no longer match original
SCORE_DECRYPT_FAILED = 20  # our key can no longer decrypt it
ALERT_THRESHOLD = 50  # minimum score to raise an alert


def load_registry():
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH, "r") as f:
            return json.load(f)
    return {}


# ── Crypto-forensics helpers

def file_entropy(path):
   
    try:
        data = Path(path).read_bytes()
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())
    except Exception:
        return 0.0


def header_changed(path, original_header_hex):
    """if the first 16 bytes no longer match what we recorded at seed time."""
    try:
        current = Path(path).read_bytes()[:16].hex()
        return current != original_header_hex
    except Exception:
        return False


def verify_decryption(path, key_hex, iv_hex):
    """Return True if we can still decrypt the file with our stored key+IV."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        data = Path(path).read_bytes()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = unpad(cipher.decrypt(data), AES.block_size)
        return b"HONEY_TOKEN_ACTIVE" in plain
    except Exception:
        return False


def compute_score(honeyfile, reg_entry, original_path):
    """
    Score the threat level for one honeyfile. Returns (score, breakdown_dict).
    reg_entry keys: iv, key, original_header, created
    """
    breakdown = {}
    score = 0

    encrypted_path = Path(f"test_files/{honeyfile}.encrypted")

    # 1. Encrypted copy appeared
    if encrypted_path.exists():
        score += SCORE_ENCRYPTED_FILE
        breakdown["encrypted_file_found"] = SCORE_ENCRYPTED_FILE

    # 2. Entropy of the live file
    entropy = file_entropy(original_path)
    breakdown["entropy"] = round(entropy, 3)
    if entropy > 7.2:
        score += SCORE_HIGH_ENTROPY
        breakdown["high_entropy_score"] = SCORE_HIGH_ENTROPY

    # 3. Header / magic-bytes changed
    if reg_entry.get("original_header") and header_changed(
        original_path, reg_entry["original_header"]
    ):
        score += SCORE_HEADER_CHANGED
        breakdown["header_changed_score"] = SCORE_HEADER_CHANGED

    # 4. Decryption verification (only if we stored the key)
    if reg_entry.get("key"):
        ok = verify_decryption(original_path, reg_entry["key"], reg_entry["iv"])
        breakdown["decryption_ok"] = ok
        if not ok:
            score += SCORE_DECRYPT_FAILED
            breakdown["decrypt_failed_score"] = SCORE_DECRYPT_FAILED
    else:
        breakdown["decryption_ok"] = "key_not_stored"

    breakdown["total_score"] = score
    return score, breakdown


# ── Attacker process helpers ─────────────────────────────────────────────────


def get_attacker_pid():
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] and "anagha_ransomware" in proc.info["name"].lower():
                return proc.info["pid"]
        except Exception:
            continue
    return None


def suspend_attacker(pid):
    try:
        psutil.Process(pid).suspend()
        print(f"[!] SUSPENDED attacker PID {pid}")
        return True
    except Exception as e:
        print(f"[X] Failed to suspend: {e}")
        return False


def terminate_attacker(pid):
    try:
        p = psutil.Process(pid)
        p.resume()
        p.terminate()
        print(f"[!] TERMINATED attacker PID {pid}")
    except Exception:
        pass


def recover_key():
    c2_log = Path("c2_server.log")
    if c2_log.exists():
        for line in open(c2_log):
            if "KEY:" in line:
                for part in line.split():
                    if part.startswith("KEY:"):
                        return part[4:]
    return None


# ── Reporting & GUI ──────────────────────────────────────────────────────────


def write_report(honeyfile_name, pid, key, encrypted_count, score, breakdown):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = EVIDENCE_DIR / f"incident_{timestamp}.json"
    report = {
        "timestamp": datetime.now().isoformat(),
        "honeyfile": honeyfile_name,
        "attacker_pid": pid,
        "recovered_key": key,
        "key_bits": len(key) * 4 if key else 0,
        "encrypted_files_count": encrypted_count,
        "status": "suspended" if pid else "not_found",
        "threat_score": score,
        "score_breakdown": breakdown,
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved: {report_path}")
    return report_path


def show_alert(honeyfile_name, pid, key, score, breakdown):
    encrypted_count = len(list(Path("test_files").glob("*.encrypted")))
    write_report(honeyfile_name, pid, key, encrypted_count, score, breakdown)

    root = tk.Tk()
    root.title("HONEYFILE ALERT")
    root.geometry("580x520")
    root.configure(bg="black")

    # Colour the score badge
    score_colour = "red" if score >= 80 else ("orange" if score >= 50 else "yellow")

    tk.Label(
        root,
        text="HONEYFILE TRIGGERED",
        font=("Arial", 18, "bold"),
        fg="red",
        bg="black",
    ).pack(pady=(20, 5))
    tk.Label(
        root,
        text=f"Threat Score: {score}  ({'CRITICAL' if score>=80 else 'HIGH' if score>=50 else 'MEDIUM'})",
        font=("Arial", 14, "bold"),
        fg=score_colour,
        bg="black",
    ).pack(pady=(0, 10))

    tk.Label(
        root,
        text=f"Honeyfile : {honeyfile_name}",
        fg="white",
        bg="black",
        font=("Courier", 11),
    ).pack()
    tk.Label(
        root,
        text=f"Attacker PID : {pid if pid else 'Not found'}",
        fg="white",
        bg="black",
        font=("Courier", 11),
    ).pack()
    tk.Label(
        root,
        text=f"Files Encrypted : {encrypted_count}",
        fg="white",
        bg="black",
        font=("Courier", 11),
    ).pack()

    # Score breakdown box
    tk.Label(
        root, text="Score Breakdown:", fg="yellow", bg="black", font=("Arial", 11)
    ).pack(pady=(12, 2))
    bx = tk.Text(root, height=6, font=("Courier", 9), bg="#1a1a1a", fg="lime")
    bx.pack(fill="x", padx=20)
    for k, v in breakdown.items():
        bx.insert("end", f"  {k}: {v}\n")
    bx.config(state="disabled")

    if key:
        tk.Label(
            root,
            text="Recovered AES-256 Key:",
            fg="yellow",
            bg="black",
            font=("Arial", 11),
        ).pack(pady=(10, 2))
        kbox = tk.Text(root, height=2, font=("Courier", 9), bg="#333", fg="lime")
        kbox.pack(fill="x", padx=20)
        kbox.insert("1.0", key)
        kbox.config(state="disabled")

    def on_terminate():
        if pid:
            terminate_attacker(pid)
        root.destroy()

    tk.Button(
        root,
        text="Terminate Attacker",
        command=on_terminate,
        bg="red",
        fg="white",
        padx=20,
        pady=8,
    ).pack(pady=15)
    tk.Button(
        root,
        text="Dismiss",
        command=root.destroy,
        bg="gray",
        fg="white",
        padx=20,
        pady=8,
    ).pack()
    root.mainloop()


# ── Seed ─────────────────────────────────────────────────────────────────────


def seed_honeyfiles():
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto.Random import get_random_bytes

    AES_KEY = get_random_bytes(32)
    HONEY_TOKEN = b"HONEY_TOKEN_ACTIVE"
    HONEYFILE_LOCATIONS = ["test_files/admin_honey.txt", "test_files/audit_trace.txt"]

    registry = {}
    for path_str in HONEYFILE_LOCATIONS:
        path = Path(path_str).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            os.chmod(path, 0o600)
            path.unlink()

        iv = get_random_bytes(16)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(HONEY_TOKEN, AES.block_size))
        with open(path, "wb") as f:
            f.write(ciphertext)
        os.chmod(path, 0o400)

        registry[str(path)] = {
            "iv": iv.hex(),
            "key": AES_KEY.hex(),  # stored so we can verify later
            "original_header": ciphertext[:16].hex(),  # first 16 bytes as baseline
            "created": datetime.now().isoformat(),
        }

    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)
    print(f"[+] Seeded {len(HONEYFILE_LOCATIONS)} honeyfiles")


# ── Monitor ───────────────────────────────────────────────────────────────────


def monitor():
    if not REGISTRY_PATH.exists():
        print("Run: python3 honey_poll.py seed  first")
        return

    registry = load_registry()
    # Build a quick name→(full_path, reg_entry) map
    honeyfiles = {Path(p).name: (p, v) for p, v in registry.items()}
    print(f"[*] Monitoring: {list(honeyfiles.keys())}")
    print("[*] DEFENDER ACTIVE — scanning every 0.5 s\n")

    alerted = set()

    try:
        while True:
            for name, (full_path, reg_entry) in honeyfiles.items():
                score, breakdown = compute_score(name, reg_entry, full_path)

                if score >= ALERT_THRESHOLD and name not in alerted:
                    alerted.add(name)
                    print(f"\n[!!!] ALERT — {name}  score={score}")
                    print(f"      breakdown: {breakdown}")

                    pid = get_attacker_pid()
                    if pid:
                        suspend_attacker(pid)
                    else:
                        print("[!] Attacker process not found")

                    key = recover_key()
                    if key:
                        print(f"[+] KEY RECOVERED: {key[:32]}...")

                    show_alert(name, pid, key, score, breakdown)

            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Monitor stopped")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 honey_poll.py [seed|monitor]")
        sys.exit(1)
    if sys.argv[1] == "seed":
        seed_honeyfiles()
    elif sys.argv[1] == "monitor":
        monitor()
    else:
        print("Invalid command. Use: seed | monitor")
