# Architektur – "Das Erbe von Cagliostro"

## Zielsetzung

Ein einzelnes, in sich geschlossenes Zielsystem ("Maison d'Ermont"), das die
vier Phasen der Story nacheinander freigibt. Das System wird als **ein**
Docker-Image gebaut und in einer VM betrieben. Die VM ist die
Distributionseinheit (OVA/Vagrant-Box), der Container im Inneren ist die
Anti-Cheat-Grenze.

```
┌─────────────────────────── VM (Ubuntu Server, read-only Distribution) ───┐
│                                                                           │
│   systemd ─▶ docker.service ─▶ Container "dermont-target"                │
│                                                                           │
│   ┌───────────────────── Container dermont-target ───────────────────┐  │
│   │  entrypoint.sh (PID 1, s.u. "Dynamic Secrets")                    │  │
│   │   ├─ sshd            :22   (nur Key-Auth, Phase 1 Ziel)           │  │
│   │   ├─ gallery (flask) :80   (Phase 1)                              │  │
│   │   ├─ geheimsender    :9001 (nur 127.0.0.1 – Phase 2, SSH-Tunnel)  │  │
│   │   ├─ vault_daemon         (root-Prozess, hält Key-Fragment C)     │  │
│   │   └─ /usr/local/bin/vault_backup (root via sudo, Phase 3)         │  │
│   └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
```

Von außen sind initial nur Port 80 (HTTP) und Port 22 (SSH) erreichbar.
Port 9001 ist an `127.0.0.1` gebunden – ohne den SSH-Zugang aus Phase 1
unerreichbar (lokales Port-Forwarding ist der Gate zwischen Phase 1 und 2).

## Warum ein Container, nicht vier?

Die Story verlangt **eine fortlaufende Kompromittierung eines Servers**
(nicht vier getrennte Boxen) – Lupin bewegt sich lateral *in einem* System.
Vier separate Container pro Phase würden das Pivoting (SSH-Tunnel von
Phase 1 zu Phase 2, lokale PrivEsc in Phase 3, Prozessspeicher in Phase 4)
unnötig verkomplizieren, weil `/proc/<pid>/mem` aus Phase 4 sonst nicht auf
den `vault_daemon` aus Phase 2/3 zugreifen könnte. Die Isolation, die
Studierende am Mounten/Grep'en der VM-Platte hindern soll, kommt nicht aus
"viele Container", sondern aus **Laufzeit-Secrets, die nie auf der
VM-Festplatte landen** (siehe unten).

## Anti-Cheat: Dynamic Secrets

Problem: Ein Teilnehmer bootet die ausgeteilte VM von einem Live-Linux-USB,
mountet die virtuelle Festplatte read-only von außen und durchsucht sie
mit `grep -rn "FLAG{" /mnt`.

Gegenmaßnahme:
1. Das Docker-Image selbst enthält **keine** Flags, Keys oder Secrets –
   weder im Layer noch im Build-Kontext. Es enthält nur Code und
   Platzhalter-Logik.
2. `entrypoint.sh` läuft beim Container-Start (jedes Mal, wenn die VM
   bootet) als PID 1 und:
   - zieht Entropie aus `/dev/urandom` + einer pro Deployment festen
     `DEPLOY_SEED` (vom Dozenten vergeben, z. B. pro Team unterschiedlich,
     damit Flags nicht teilbar sind),
   - leitet daraus alle Phasen-Secrets ab (SSH-Key für `ganimard`,
     Krypto-Key für Phase 2, das Format-String-Zielwort für Phase 3,
     Key-Fragment C für `vault_daemon`),
   - schreibt sie **ausschließlich** nach `/run/secrets` (`tmpfs`,
     RAM-only, verschwindet beim Neustart) bzw. hält sie als Prozess-
     Environment/Heap-Daten von `vault_daemon`.
   - Die SQLite-Datenbank mit der finalen Flagge liegt verschlüsselt auf
     Disk (AES-256, Key = Kombination aus Teil A+B+C); ohne die drei zur
     Laufzeit generierten Fragmente ist die Datei kryptografisch wertlos,
     ein Platten-Mount liefert nur Ciphertext.
3. Ergebnis: Ein VM-Platten-Mount von außen (Container gestoppt) liefert
   höchstens Code und eine verschlüsselte SQLite-Datei – keine Klartext-
   Flags. Ein Mount *während* der Container läuft, zeigt nur
   Container-Overlay-Dateien, keinen Zugriff auf einen fremden
   Prozess-Adressraum (für Phase 4 ist genau das Lesen des *eigenen*
   erreichten Prozessspeichers die Aufgabe, nicht ein Shortcut).

## Fortschritt zwischen den Phasen (Pivot-Kette)

| Von | Mechanismus | Nach |
|---|---|---|
| Anonym | LFI → `/proc/self/environ` → SSH-Private-Key | `ganimard` (SSH) |
| `ganimard` | Lokales Port-Forwarding auf `127.0.0.1:9001`, Krypto-Bruch | `lupin_associate` (Session-Credentials) |
| `lupin_associate` | `sudo -l` → `vault_backup` (Format-String) | `root` |
| `root` | `/proc/<vault_daemon_pid>/mem` auslesen | Key-Fragment C |
| (alle Fragmente) | A (LFI-String) + B (Krypto-Key) + C (Memory-Token) | Finale Flag |

## Build/Deploy-Fluss

1. `docker build` aus `infra/Dockerfile` → ein Image, das Code aus allen
   vier `phaseX-*/`-Ordnern enthält.
2. `infra/vm-provision/setup-vm.sh` auf einer frischen Ubuntu-Server-VM
   ausführen: installiert Docker, lädt/baut das Image, startet den
   Container mit `--restart=always` und den nötigen Port-Mappings.
3. Die fertige VM wird als OVA exportiert und an die Teilnehmer verteilt
   (oder `infra/docker-compose.yml` für lokale Entwicklung/Tests ohne VM).

## Verzeichnisstruktur

```
docs/                     Architektur + Dozenten-Writeup
infra/                    Dockerfile, compose, VM-Setup, Secret-Generierung
phase1-galerie/           Flask-Webapp + LFI + Honeypot + Solve-Script
phase2-geheimsender/      TCP-Krypto-Dienst + Solve-Script
phase3-maskerade/         vault_backup.c (Format-String) + Exploit
phase4-tresor/            vault_daemon + verschlüsseltes Archiv + Solve-Script
```
