#!/usr/bin/env python3
"""
Phase 2 Solve-Script -- "Der Geheimsender"

Voraussetzung: lokaler SSH-Tunnel steht bereits, z. B.
    ssh -i ../../phase1-galerie/solve/id_ganimard -L 9001:127.0.0.1:9001 ganimard@<target>

Nutzung:
    python3 solve.py --host 127.0.0.1 --port 9001 --key C4GL10
    # --key wurde zuvor per `strings` aus /opt/lupin/cipher_stamp
    # extrahiert (auf dem Zielsystem als ganimard lesbar).

Alternativ (ohne --key) kann der Schlüssel per Known-Plaintext-Angriff
aus dem Stream selbst rekonstruiert werden, da jede Nachricht mit dem
bekannten JSON-Präfix beginnt: siehe --recover-key.
"""
import argparse
import json
import socket
import sys


def read_frame(sock: socket.socket) -> bytes:
    length_bytes = recv_exact(sock, 4)
    length = int.from_bytes(length_bytes, "big")
    return recv_exact(sock, length)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Verbindung geschlossen")
        buf += chunk
    return buf


def xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


KNOWN_PREFIX = b'{"from": "lupin", "to": "associate", "ts": '


def recover_key(ciphertext: bytes, known_prefix: bytes, max_key_len: int = 12) -> bytes:
    """Known-Plaintext-Angriff: key[i] = ct[i] XOR plaintext[i] für den
    bekannten Präfix, dann über mehrere Perioden gemittelt/validiert."""
    partial = xor_repeat(ciphertext[: len(known_prefix)], b"\x00" * len(known_prefix))
    # partial ist hier nur ciphertext selbst (XOR mit 0) -- eigentlicher Trick:
    keystream_guess = bytes(c ^ p for c, p in zip(ciphertext, known_prefix))
    for key_len in range(1, max_key_len + 1):
        candidate = keystream_guess[:key_len]
        if len(candidate) < key_len:
            continue
        # Validierung: candidate über die ganze bekannte Präfixlänge wiederholen
        # und prüfen, ob es durchgängig zum Präfix passt.
        repeated = (candidate * (len(known_prefix) // key_len + 1))[: len(known_prefix)]
        if xor_repeat(ciphertext[: len(known_prefix)], candidate) == known_prefix:
            return candidate
    raise ValueError("Key-Recovery fehlgeschlagen -- mehr Ciphertext nötig")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9001)
    ap.add_argument("--key", help="Bekannter XOR-Key (z. B. aus `strings cipher_stamp`)")
    ap.add_argument("--recover-key", action="store_true",
                     help="Key per Known-Plaintext-Angriff aus dem Stream rekonstruieren")
    ap.add_argument("--messages", type=int, default=1, help="Anzahl Nachrichten lesen")
    args = ap.parse_args()

    sock = socket.create_connection((args.host, args.port), timeout=10)
    print(f"[*] Verbunden mit {args.host}:{args.port}")

    key = args.key.encode() if args.key else None
    token = None

    for i in range(max(args.messages, 1 if not args.recover_key else 1)):
        ct = read_frame(sock)
        if key is None:
            key = recover_key(ct, KNOWN_PREFIX)
            print(f"[+] XOR-Key rekonstruiert: {key!r}")
        pt = xor_repeat(ct, key)
        try:
            msg = json.loads(pt.decode("utf-8"))
        except Exception:
            print("[!] Konnte Nachricht nicht als JSON parsen:", pt[:80])
            continue
        print(f"[*] Nachricht: {msg.get('note')}")
        token = msg.get("session_token")

    sock.close()

    if not token:
        print("[!] Kein session_token empfangen.", file=sys.stderr)
        sys.exit(1)

    out_path = "id_lupin_associate"
    with open(out_path, "w") as f:
        f.write(token.strip() + "\n")
    import os
    os.chmod(out_path, 0o600)
    print(f"[+] Session-Credentials für lupin_associate -> {out_path}")


if __name__ == "__main__":
    main()
