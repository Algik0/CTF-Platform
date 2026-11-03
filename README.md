# CTF-Platform — "Das Erbe von Cagliostro"

Arsène-Lupin-themed CTF für den Offensive-Security-Kurs (DHBW Mannheim,
TINF24CS1). Vier Phasen auf einem einzelnen Zielsystem ("dermont-target"),
vollständig end-to-end verifiziert.

## Schnellstart

```bash
docker compose -f infra/docker-compose.yml up --build
# Phase 1: http://localhost:8080
# SSH:     ssh -p 2222 ganimard@localhost -i <per-Deployment-Key>
```

Für die VM-Hülle (Verteilung an Teilnehmer als OVA):
siehe [`infra/vm-provision/setup-vm.sh`](infra/vm-provision/setup-vm.sh).

## Struktur

| Pfad | Inhalt |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Gesamtarchitektur, Anti-Cheat-Design (Dynamic Secrets) |
| [`docs/writeup/DOSSIER-SURETE.md`](docs/writeup/DOSSIER-SURETE.md) | Vollständiges Dozenten-Writeup (alle 4 Phasen, PoCs, Remediation) |
| `phase1-galerie/` | Web/Recon — LFI + Honeypot |
| `phase2-geheimsender/` | Netzwerk/Krypto — Repeating-Key-XOR |
| `phase3-maskerade/` | PrivEsc/PWN — Format-String + sudo PATH-Hijack |
| `phase4-tresor/` | Forensik — Prozessspeicher + verschlüsselter Tresor |
| `infra/` | Dockerfile, Entrypoint (Dynamic Secrets), Compose, VM-Provisioning |

Jede `phaseX-*/solve/`-Ordner enthält ein verifiziertes, lauffähiges
Lösungsskript für diese Phase.

## Status

Alle vier Phasen wurden gegen eine echte, lokal laufende Instanz
(Apache+mod_php, OpenSSH, sudo, kompilierte Binaries) end-to-end
durchgetestet — siehe Writeup, Abschnitt 7.1 für die vollständige
Pivot-Kette eines realen Testlaufs.
