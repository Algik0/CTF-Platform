/*
 * vault_daemon -- hält Key-Fragment C (Teil der finalen Tresor-
 * Entschlüsselung) im Prozessspeicher. Läuft als root; nur root kann
 * seinen Speicher über /proc/<pid>/mem auslesen (daher Abhängigkeit
 * von der in Phase 3 erlangten Root-Shell).
 *
 * Das Fragment liegt NICHT verschlüsselt im Prozessspeicher -- das ist
 * Absicht, es ist die zu findende "Asservate"-Spur, keine zusätzliche
 * Hürde. Es wird über die Umgebungsvariable VAULT_FRAGMENT_C beim
 * Containerstart injiziert (siehe infra/entrypoint.sh) und in einen
 * lokalen Puffer mit Markern kopiert, damit es per
 * `strings /proc/<pid>/mem | grep VAULTC_BEGIN` auffindbar ist.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *frag = getenv("VAULT_FRAGMENT_C");
    if (!frag || strlen(frag) == 0) {
        fprintf(stderr, "[vault_daemon] VAULT_FRAGMENT_C nicht gesetzt -- Abbruch\n");
        return 1;
    }

    char memory_blob[512];
    int written = snprintf(memory_blob, sizeof(memory_blob),
                            "VAULTC_BEGIN:%s:VAULTC_END", frag);
    if (written < 0 || (size_t)written >= sizeof(memory_blob)) {
        fprintf(stderr, "[vault_daemon] Fragment zu lang\n");
        return 1;
    }

    const char *pidfile_path = getenv("VAULT_DAEMON_PIDFILE");
    if (!pidfile_path) pidfile_path = "/run/vault_daemon.pid";

    FILE *pidf = fopen(pidfile_path, "w");
    if (pidf) {
        fprintf(pidf, "%d\n", getpid());
        fclose(pidf);
    } else {
        fprintf(stderr, "[vault_daemon] Warnung: Pidfile %s nicht schreibbar\n", pidfile_path);
    }

    fprintf(stderr, "[vault_daemon] laeuft (pid=%d), Fragment im Speicher resident.\n", getpid());
    fprintf(stderr, "[vault_daemon] Gruesse an Ganimard -- Sie kommen naeher, aber noch nicht nah genug.\n");

    volatile char keep_alive;
    for (;;) {
        keep_alive = memory_blob[0];
        (void)keep_alive;
        sleep(3600);
    }
    return 0;
}
