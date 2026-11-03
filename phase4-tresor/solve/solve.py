#!/usr/bin/env python3
"""
Phase 4 Solve-Script -- "Der Tresor des Grafen"

Läuft AUF DEM ZIEL als root (Voraussetzung: Phase 3 abgeschlossen).
Kombiniert die drei Fragmente zum finalen Schlüssel und entschlüsselt
den Tresor.

  Teil A : --fragment-a   (aus Phase 1, LFI -> /proc/self/environ)
  Teil B : --fragment-b   (aus Phase 2, Krypto-Bruch des Geheimsenders)
  Teil C : automatisch per Memory-Forensik aus vault_daemon ermittelt,
           oder manuell via --fragment-c (z. B. bereits per gdb
           extrahiert).

Nutzung (als root auf dem Zielsystem):
    python3 solve.py --fragment-a <A> --fragment-b <B>
"""
import argparse
import os
import re
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "crypto"))
import vault_crypto  # noqa: E402

FRAGMENT_RE = re.compile(rb"VAULTC_BEGIN:([^:]+):VAULTC_END")


def find_fragment_c(pid: int) -> str:
    """Durchsucht alle lesbaren Speicherregionen des Prozesses nach dem
    Fragment-Marker. Ein direktes `strings /proc/<pid>/mem` funktioniert
    NICHT zuverlässig (Lesefehler an nicht gemappten Offsets) -- wir
    lesen daher gezielt die in /proc/<pid>/maps gelisteten Bereiche."""
    with open(f"/proc/{pid}/maps") as maps_f:
        regions = []
        for line in maps_f:
            parts = line.split()
            if len(parts) < 2 or "r" not in parts[1]:
                continue
            start_s, end_s = parts[0].split("-")
            regions.append((int(start_s, 16), int(end_s, 16)))

    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for start, end in regions:
            try:
                mem.seek(start)
                data = mem.read(end - start)
            except OSError:
                continue
            for m in FRAGMENT_RE.finditer(data):
                value = m.group(1)
                if value != b"%s":  # das ist nur das printf-Format-Literal im Binary
                    return value.decode("utf-8", errors="replace")
    raise RuntimeError("Fragment C nicht im Prozessspeicher gefunden (laeuft vault_daemon?)")


def read_pid(pidfile: str) -> int:
    with open(pidfile) as f:
        return int(f.read().strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fragment-a", required=True, help="Teil A aus Phase 1 (LFI/environ)")
    ap.add_argument("--fragment-b", required=True, help="Teil B aus Phase 2 (Krypto-Bruch)")
    ap.add_argument("--fragment-c", help="Teil C manuell angeben (sonst Memory-Scan)")
    ap.add_argument("--pidfile", default="/run/vault_daemon.pid")
    ap.add_argument("--archive", default="/opt/vault/tresor.db.enc")
    args = ap.parse_args()

    fragment_c = args.fragment_c
    if fragment_c is None:
        pid = read_pid(args.pidfile)
        print(f"[*] Scanne Prozessspeicher von vault_daemon (pid={pid}) ...")
        fragment_c = find_fragment_c(pid)
        print(f"[+] Fragment C gefunden: {fragment_c}")

    key_material = f"{args.fragment_a}|{args.fragment_b}|{fragment_c}".encode("utf-8")

    with open(args.archive, "rb") as f:
        blob = f.read()

    print("[*] Entschlüssele Tresor ...")
    plaintext = vault_crypto.decrypt(blob, key_material)

    fd, tmp_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        with open(tmp_path, "wb") as f:
            f.write(plaintext)
        conn = sqlite3.connect(tmp_path)
        rows = conn.execute("SELECT kind, content FROM tresor").fetchall()
        conn.close()
    finally:
        os.remove(tmp_path)

    for kind, content in rows:
        print(f"\n===== {kind.upper()} =====")
        print(content)


if __name__ == "__main__":
    main()
