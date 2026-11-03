#!/bin/bash
# Provisioniert eine frische Ubuntu-Server-VM als Hülle für den
# "dermont-target"-Container (siehe docs/ARCHITECTURE.md).
#
# Nutzung (auf der VM, als root/sudo, Repo bereits auf die VM kopiert
# oder per `git clone` geholt):
#   sudo ./infra/vm-provision/setup-vm.sh
#
# Danach: VM als OVA exportieren und an die Teilnehmer verteilen.
# Port 80 und 22 des Containers werden 1:1 auf die VM gemappt, sodass
# aus Teilnehmersicht die VM selbst das Zielsystem ist.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "[setup-vm] Installiere Docker ..."
    curl -fsSL https://get.docker.com | sh
fi

echo "[setup-vm] Baue dermont-target Image ..."
docker build -f "${REPO_ROOT}/infra/Dockerfile" -t dermont-target "${REPO_ROOT}"

echo "[setup-vm] Entferne ggf. alten Container ..."
docker rm -f dermont-target >/dev/null 2>&1 || true

echo "[setup-vm] Starte Container (restart=always, Ports 80/22 direkt auf die VM) ..."
# --cap-drop bewusst NICHT gesetzt. CAP_SYS_PTRACE wird zusaetzlich EXPLIZIT
# hinzugefuegt -- Dockers Default-Capability-Set enthaelt SYS_PTRACE NICHT.
# Ohne diese Capability blockt Yamas ptrace_scope den /proc/<pid>/mem-Zugriff
# aus Phase 4 auch fuer UID 0 im Container (SUID-root reicht dafuer nicht,
# verifiziert gegen eine echte laufende Instanz).
docker run -d \
    --name dermont-target \
    --restart=always \
    --cap-add=SYS_PTRACE \
    -p 80:80 \
    -p 22:22 \
    dermont-target

echo "[setup-vm] Fertig. Dynamic Secrets wurden im Container generiert (siehe"
echo "           ARCHITECTURE.md) und liegen NICHT auf der VM-Platte im Klartext."
echo "           Jeder Neustart der VM/des Containers erzeugt neue Secrets --"
echo "           für eine über mehrere Sitzungen stabile Instanz ggf."
echo "           DEPLOY_SEED als Environment-Variable beim 'docker run' setzen."
