"""
Gemeinsames Krypto-Modul für den Tresor (Phase 4).

Verwendet ausschließlich PyCA `cryptography` (siehe requirements.txt) --
keine eigene Krypto-Implementierung. Format der verschlüsselten Datei:

    salt (16 Byte) || iv (16 Byte) || ciphertext (AES-256-CBC, PKCS7)

Der Schlüssel wird NICHT direkt aus den drei Fragmenten verwendet,
sondern über PBKDF2-HMAC-SHA256 (200.000 Iterationen) abgeleitet --
auch wenn die Fragmente selbst schon hohe Entropie haben, vermeidet das
Schlüsselmaterial, das 1:1 aus den Fragment-Strings besteht.

Dependency: cryptography>=42 (PyCA, https://github.com/pyca/cryptography)
  - weit verbreitet, von der Python Cryptographic Authority gepflegt,
    kein Typosquatting-Risiko (offizieller Paketname), aktiv maintained.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_LEN = 16
IV_LEN = 16
KEY_LEN = 32  # AES-256
PBKDF2_ITERATIONS = 200_000


def derive_key(key_material: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(key_material)


def encrypt(plaintext: bytes, key_material: bytes) -> bytes:
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = derive_key(key_material, salt)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    return salt + iv + ct


def decrypt(blob: bytes, key_material: bytes) -> bytes:
    salt, iv, ct = blob[:SALT_LEN], blob[SALT_LEN:SALT_LEN + IV_LEN], blob[SALT_LEN + IV_LEN:]
    key = derive_key(key_material, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()
