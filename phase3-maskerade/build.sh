#!/bin/sh
# Hilfsskript, das infra/Dockerfile beim Bauen des Gesamt-Images aufruft,
# um vault_backup zu kompilieren und zu installieren. Kein eigenständiger
# Container, da PrivEsc auf demselben Host wie Phase 1/2 erfolgt.
set -e
gcc -O0 -o /usr/local/bin/vault_backup "$(dirname "$0")/vault_backup.c" -Wno-format-security
chmod 755 /usr/local/bin/vault_backup
mkdir -p /opt/vault/data
echo "Dummy-Tresordaten (Phase 3 Backup-Ziel)" > /opt/vault/data/placeholder.txt
