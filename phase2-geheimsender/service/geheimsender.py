#!/usr/bin/env python3
"""
Phase 2 Daemon -- "Der Geheimsender"

Lauscht NUR auf 127.0.0.1:9001 (siehe infra/entrypoint.sh / Docker
"expose" ohne Port-Mapping nach außen). Erreichbar für Teilnehmer erst,
nachdem sie sich per SSH als `ganimard` angemeldet und einen lokalen
Port-Forward aufgebaut haben:

    ssh -i id_ganimard -L 9001:127.0.0.1:9001 ganimard@<target>

Der Dienst streamt fortlaufend "abgefangene" Nachrichten zwischen Lupin
und seinem Komplizen `lupin_associate`, verschlüsselt über das
Legacy-C-Tool cipher_stamp (Repeating-Key-XOR, Schlüssel per `strings`
auslesbar -- siehe cipher-tool/cipher_stamp.c).
"""
import json
import os
import random
import socket
import subprocess
import threading
import time

CIPHER_TOOL = os.environ.get("CIPHER_TOOL_PATH", "/opt/lupin/cipher_stamp")
SESSION_TOKEN_PATH = os.environ.get("LUPIN_ASSOCIATE_KEY_PATH", "/run/secrets/id_lupin_associate")
BIND_HOST = "127.0.0.1"
BIND_PORT = 9001

FLAVOR = [
    "Der Baron schläft schlecht seit dem Verkauf der Nocturne.",
    "Ganimard riecht etwas, aber er findet nie etwas -- wie immer.",
    "Das Rendezvous bleibt wie besprochen, gleiche Stelle.",
    "Die Tresorkombination wechselt wöchentlich, Vorsicht beim nächsten Schritt.",
    "Noch zwei Nächte, dann ist die Sammlung unser.",
    "Ganimard glaubt immer noch, 6 Zeichen seien ein sicherer Schlüssel.",
    "Erinnerung an mich selbst: cipher_stamp endlich mal ersetzen. (seit 2019)",
]


def stamp(data: bytes) -> bytes:
    """Ver-/Entschlüsselt über das externe Legacy-Tool (involutorisches XOR)."""
    proc = subprocess.run([CIPHER_TOOL], input=data, stdout=subprocess.PIPE, check=True)
    return proc.stdout


def load_session_token() -> str:
    with open(SESSION_TOKEN_PATH, "r") as f:
        return f.read()


def client_loop(conn: socket.socket, addr):
    print(f"[geheimsender] Verbindung von {addr}")
    try:
        while True:
            token = load_session_token()
            msg = {
                "from": "lupin",
                "to": "associate",
                "ts": int(time.time()),
                "note": random.choice(FLAVOR),
                "session_token": token,
            }
            payload = json.dumps(msg, ensure_ascii=False).encode("utf-8")
            ct = stamp(payload)
            conn.sendall(len(ct).to_bytes(4, "big") + ct)
            time.sleep(2)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        conn.close()
        print(f"[geheimsender] Verbindung {addr} beendet")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, BIND_PORT))
    srv.listen(8)
    print(f"[geheimsender] lauscht auf {BIND_HOST}:{BIND_PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=client_loop, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
