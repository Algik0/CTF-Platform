# "dermont-target" -- Gesamt-Image für alle vier Phasen von
# "Das Erbe von Cagliostro" (siehe docs/ARCHITECTURE.md).
#
# Build-Kontext ist das REPO-ROOT (nicht infra/), da Dateien aus allen
# phaseX-*/-Ordnern kopiert werden:
#   docker build -f infra/Dockerfile -t dermont-target .
#
# WICHTIG beim `docker run`/compose: Standard-Capabilities NICHT droppen
# (insb. CAP_SYS_PTRACE wird implizit für root in Phase 4 benötigt, um
# /proc/<pid>/mem von vault_daemon zu lesen -- root hat das standardmäßig,
# ein `--cap-drop=ALL` ohne gezieltes `--cap-add` würde Phase 4 brechen).
FROM php:8.3-apache

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        gcc \
        python3 \
        python3-cryptography \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# --- Systembenutzer für die Pivot-Kette ------------------------------
RUN useradd -m -s /bin/bash ganimard \
    && useradd -m -s /bin/bash lupin_associate

# --- Phase 1: Galerie-Website (LFI + Honeypot) -----------------------
COPY phase1-galerie/apache-vhost.conf /etc/apache2/sites-available/000-default.conf
COPY phase1-galerie/app/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html

# --- Phase 2: Geheimsender (Netzwerk/Krypto) --------------------------
# cipher_stamp wird NICHT hier kompiliert -- das passiert erst beim
# Containerstart in entrypoint.sh mit einem pro Deployment zufälligen
# Schlüssel (siehe ARCHITECTURE.md, "Dynamic Secrets").
RUN mkdir -p /opt/lupin /opt/src
COPY phase2-geheimsender/cipher-tool/cipher_stamp.c.tmpl /opt/src/cipher_stamp.c.tmpl
COPY phase2-geheimsender/service/geheimsender.py /opt/lupin/geheimsender.py

# --- Phase 3: Meistermaskerade (PrivEsc/PWN) --------------------------
COPY phase3-maskerade/vault_backup.c /tmp/vault_backup.c
RUN gcc -O0 -o /usr/local/bin/vault_backup /tmp/vault_backup.c -Wno-format-security \
    && chmod 755 /usr/local/bin/vault_backup \
    && rm -f /tmp/vault_backup.c \
    && mkdir -p /opt/vault/data \
    && echo "Dummy-Tresordaten (Phase 3 Backup-Ziel)" > /opt/vault/data/placeholder.txt
COPY phase3-maskerade/sudoers.d/lupin_associate /etc/sudoers.d/lupin_associate
RUN chmod 440 /etc/sudoers.d/lupin_associate && visudo -cf /etc/sudoers.d/lupin_associate

# --- Phase 4: Tresor des Grafen (Forensik/Memory) ---------------------
COPY phase4-tresor/daemon/vault_daemon.c /tmp/vault_daemon.c
RUN gcc -O0 -o /opt/vault/vault_daemon /tmp/vault_daemon.c && rm -f /tmp/vault_daemon.c
COPY phase4-tresor/crypto/ /opt/vault/crypto/
COPY phase4-tresor/build/ /opt/vault/build/

# --- SSH-Hardening -----------------------------------------------------
RUN mkdir -p /run/sshd \
    && { \
        echo "PermitRootLogin no"; \
        echo "PasswordAuthentication no"; \
        echo "KbdInteractiveAuthentication no"; \
        echo "AllowUsers ganimard lupin_associate"; \
    } >> /etc/ssh/sshd_config

# --- Entrypoint ---------------------------------------------------------
COPY infra/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 80 22
ENTRYPOINT ["/entrypoint.sh"]
