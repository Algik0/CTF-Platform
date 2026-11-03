#!/bin/bash
# Entrypoint für den Zielcontainer "dermont-target".
#
# Generiert ALLE Secrets (SSH-Keys, Krypto-Key, Key-Fragmente, Flag)
# bei jedem Containerstart neu, ausschließlich im RAM (tmpfs) bzw. als
# frisch kompilierte Artefakte -- niemals im Docker-Image. Siehe
# docs/ARCHITECTURE.md, Abschnitt "Dynamic Secrets".
set -euo pipefail

log() { echo "[entrypoint] $*" >&2; }

# gen_token <label> <länge>
#   Ohne DEPLOY_SEED: echtes Zufallstoken aus /dev/urandom (Standardfall,
#   jede Instanz/jedes Team bekommt eigene, nicht teilbare Secrets).
#   Mit DEPLOY_SEED gesetzt: deterministisch aus dem Seed abgeleitet
#   (SHA-256 über "SEED|label") -- nur für reproduzierbare lokale Tests
#   oder eine vom Dozenten kontrollierte, pro-Team-feste Instanz gedacht.
gen_token() {
    local label="$1" len="$2"
    if [ -n "${DEPLOY_SEED:-}" ]; then
        python3 -c "import hashlib; print(hashlib.sha256('${DEPLOY_SEED}|${label}'.encode()).hexdigest()[:${len}])"
    else
        head -c "$((len * 3))" /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "${len}"
    fi
}

# ---------------------------------------------------------------------
# 1) Secrets generieren
# ---------------------------------------------------------------------
VAULT_FRAGMENT_A="$(gen_token fragment_a 16)"
VAULT_FRAGMENT_B="$(gen_token fragment_b 6)"
VAULT_FRAGMENT_C="$(gen_token fragment_c 20)"
CTF_FLAG="FLAG{l_heritage_de_cagliostro_$(gen_token flag 12)}"
log "Secrets generiert (Flag bleibt pro Deployment einmalig, sofern kein DEPLOY_SEED gesetzt ist)."

# ---------------------------------------------------------------------
# 2) SSH: Host-Keys + dynamische User-Keypairs
# ---------------------------------------------------------------------
ssh-keygen -A >/dev/null 2>&1 || true   # Host-Keys, falls nicht vorhanden

mkdir -p /home/ganimard/.ssh /home/lupin_associate/.ssh
ssh-keygen -t ed25519 -f /tmp/id_ganimard -N "" -C "ganimard@dermont-target" -q
ssh-keygen -t ed25519 -f /tmp/id_lupin_associate -N "" -C "lupin_associate@dermont-target" -q

cat /tmp/id_ganimard.pub > /home/ganimard/.ssh/authorized_keys
cat /tmp/id_lupin_associate.pub > /home/lupin_associate/.ssh/authorized_keys
chown -R ganimard:ganimard /home/ganimard/.ssh
chown -R lupin_associate:lupin_associate /home/lupin_associate/.ssh
chmod 700 /home/ganimard/.ssh /home/lupin_associate/.ssh
chmod 600 /home/ganimard/.ssh/authorized_keys /home/lupin_associate/.ssh/authorized_keys

mkdir -p /run/secrets
cp /tmp/id_lupin_associate /run/secrets/id_lupin_associate   # Phase-2-Payload
chmod 600 /run/secrets/id_lupin_associate
log "SSH-Keypairs für ganimard/lupin_associate erzeugt."

# ---------------------------------------------------------------------
# 3) Phase 1: Service-Account-Config außerhalb des Webroots
#    (das ist das Ziel der LFI aus preview.php -- siehe dort für die
#    Begründung, warum NICHT /proc/self/environ verwendet wird)
# ---------------------------------------------------------------------
mkdir -p /etc/dermont-config
GANIMARD_KEY_CONTENT="$(cat /tmp/id_ganimard)"
python3 - "$GANIMARD_KEY_CONTENT" "$VAULT_FRAGMENT_A" <<'PYEOF'
import json, sys
key, fragment_a = sys.argv[1], sys.argv[2]
with open("/etc/dermont-config/service-accounts.json", "w") as f:
    json.dump({"ganimard_ssh_private_key": key, "vault_fragment_a": fragment_a}, f, indent=2)
PYEOF
chown root:www-data /etc/dermont-config/service-accounts.json
chmod 640 /etc/dermont-config/service-accounts.json
rm -f /tmp/id_ganimard /tmp/id_ganimard.pub /tmp/id_lupin_associate /tmp/id_lupin_associate.pub
log "Phase-1-Config geschrieben (/etc/dermont-config/service-accounts.json)."

# ---------------------------------------------------------------------
# 4) Phase 2: cipher_stamp mit per-Deployment-Key neu kompilieren
# ---------------------------------------------------------------------
sed "s/__KEY__/${VAULT_FRAGMENT_B}/" /opt/src/cipher_stamp.c.tmpl > /tmp/cipher_stamp.c
gcc -O2 -o /opt/lupin/cipher_stamp /tmp/cipher_stamp.c
chmod 755 /opt/lupin/cipher_stamp
rm -f /tmp/cipher_stamp.c
log "cipher_stamp mit frischem Schlüssel kompiliert."

# ---------------------------------------------------------------------
# 5) Phase 4: Tresor-Archiv bauen + verschlüsseln (Ciphertext auf Disk)
# ---------------------------------------------------------------------
export VAULT_FRAGMENT_A VAULT_FRAGMENT_B VAULT_FRAGMENT_C CTF_FLAG
python3 /opt/vault/build/encrypt_vault.py
log "Tresor-Archiv verschlüsselt."

# ---------------------------------------------------------------------
# 6) Hintergrunddienste starten
# ---------------------------------------------------------------------
export VAULT_FRAGMENT_C
export VAULT_DAEMON_PIDFILE=/run/vault_daemon.pid
/opt/vault/vault_daemon &
log "vault_daemon laeuft (PID $(cat /run/vault_daemon.pid 2>/dev/null || echo '?'))."

export CIPHER_TOOL_PATH=/opt/lupin/cipher_stamp
export LUPIN_ASSOCIATE_KEY_PATH=/run/secrets/id_lupin_associate
python3 /opt/lupin/geheimsender.py &
log "geheimsender laeuft auf 127.0.0.1:9001."

mkdir -p /run/sshd
/usr/sbin/sshd
log "sshd laeuft."

# ---------------------------------------------------------------------
# 7) Apache im Vordergrund -- hält den Container (PID 1) am Leben
# ---------------------------------------------------------------------
log "Starte Apache (Vordergrund) ..."
exec apache2-foreground
