/*
 * vault_backup -- internes Backup-Tool für den Tresorbestand des Barons.
 *
 * Wird per sudoers-Eintrag von `lupin_associate` als root ausführbar
 * freigegeben (siehe infra/sudoers.d/lupin). Enthält absichtlich ZWEI
 * Schwachstellen, wie im Dozenten-Briefing gefordert:
 *
 *   1) Format-String-Vulnerability: Das Backup-Label wird ungefiltert
 *      als Format-String an printf() übergeben.
 *   2. Unsicherer system()-Aufruf: "tar" wird ohne absoluten Pfad
 *      aufgerufen, kombiniert mit einer sudoers-Regel, die
 *      `secure_path` für diesen Nutzer deaktiviert -> PATH-Hijacking.
 *
 * Die zweite Schwachstelle ist der verlässliche, deterministische
 * Lösungsweg (unabhängig von ASLR/Compiler-Flags); die erste dient dem
 * Lernziel "Format-String-Angriffe erkennen" und kann zusätzlich zum
 * Auslesen von Stack-Daten genutzt werden.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
    /* Altlast auf dem Stack -- nie entfernt, gutes Ziel für einen
     * Format-String-Leak (%x/%s-Ketten), aber kein notwendiger
     * Lösungsweg. */
    char legacy_note[64] = "Legacy-Hinweis: Tresor-PIN-Rotation Mo 03:00 UTC";
    (void)legacy_note;

    if (argc < 2) {
        fprintf(stderr, "Nutzung: %s <backup-label>\n", argv[0]);
        return 1;
    }

    char label[256];
    snprintf(label, sizeof(label), "%s", argv[1]);

    printf("[vault_backup] Sicherung gestartet. Label: ");
    printf(label);               /* <-- Format-String-Vulnerability */
    printf("\n");

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "tar czf /opt/vault/backup-%ld.tar.gz -C /opt/vault data 2>/dev/null",
             (long)time(NULL));
    printf("[vault_backup] Fuehre aus: %s\n", cmd);

    int rc = system(cmd);        /* <-- "tar" ohne absoluten Pfad */
    if (rc != 0) {
        fprintf(stderr, "[vault_backup] Warnung: Sicherung fehlgeschlagen (rc=%d)\n", rc);
    } else {
        printf("[vault_backup] Sicherung abgeschlossen.\n");
        printf("[vault_backup] Der Baron waere stolz. Falls er wuesste, dass es dieses Tool gibt.\n");
    }
    return 0;
}
