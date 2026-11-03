#!/usr/bin/env python3
"""
Baut die Tresor-Datenbank (SQLite) und verschlüsselt sie mit den drei
Fragmenten zu /opt/vault/tresor.db.enc. Wird von infra/entrypoint.sh
beim Containerstart ausgeführt, NACHDEM alle drei Fragmente generiert
wurden. Die Klartext-DB existiert nur kurz in /run (tmpfs) und wird
danach gelöscht -- auf persistenter Disk landet ausschließlich der
Ciphertext.

Benötigte Umgebungsvariablen:
  VAULT_FRAGMENT_A, VAULT_FRAGMENT_B, VAULT_FRAGMENT_C, CTF_FLAG
Optional:
  VAULT_ARCHIVE_PATH (Default: /opt/vault/tresor.db.enc)
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "crypto"))
import vault_crypto  # noqa: E402

LETTER = """Mon cher Ganimard,

Sie haben es bis hierher geschafft -- das allein verdient Respekt. Baron
d'Ermont hat seine Opfer zu lange im Dunkeln gehalten: Erpressung,
gestohlene Kunst, gekaufte Beamte. Ich überlasse Ihnen den Rest: die
Beweise, die Sie gerade entschlüsselt haben, gehören nicht in meine
Taschen, sondern auf die Titelseiten.

Richten Sie dem Baron aus, dass das Haus d'Ermont von nun an leer steht.

-- A.L.
"""


def build_database(path: str, flag: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE tresor (id INTEGER PRIMARY KEY, kind TEXT, content TEXT)")
    conn.execute("INSERT INTO tresor (kind, content) VALUES ('flag', ?)", (flag,))
    conn.execute("INSERT INTO tresor (kind, content) VALUES ('lupin_letter', ?)", (LETTER,))
    conn.commit()
    conn.close()


def main() -> None:
    fragment_a = os.environ["VAULT_FRAGMENT_A"]
    fragment_b = os.environ["VAULT_FRAGMENT_B"]
    fragment_c = os.environ["VAULT_FRAGMENT_C"]
    flag = os.environ["CTF_FLAG"]
    out_path = os.environ.get("VAULT_ARCHIVE_PATH", "/opt/vault/tresor.db.enc")

    key_material = f"{fragment_a}|{fragment_b}|{fragment_c}".encode("utf-8")

    fd, db_path = tempfile.mkstemp(dir="/run", suffix=".db")
    os.close(fd)
    try:
        build_database(db_path, flag)
        with open(db_path, "rb") as f:
            plaintext = f.read()
        blob = vault_crypto.encrypt(plaintext, key_material)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(blob)
        print(f"[encrypt_vault] Tresor verschlüsselt -> {out_path}")
    finally:
        try:
            os.remove(db_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
