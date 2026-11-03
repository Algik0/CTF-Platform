/*
 * cipher_stamp -- Lupin'sche "Feldchiffre", Altlast aus den 2010er Jahren.
 *
 * Liest Bytes von stdin, verschlüsselt (XOR) sie mit einem kurzen,
 * fest im Binary verankerten Schlüssel und schreibt das Ergebnis auf
 * stdout. Da XOR involutorisch ist, entschlüsselt derselbe Aufruf auch
 * wieder (enc(enc(x)) == x) -- das ist Teil der Schwachstelle, nicht
 * nur fauler Code.
 *
 * Absichtlich für Reversing-Übungen gebaut: der Schlüssel liegt im
 * Klartext im .rodata-Segment und ist mit `strings` sofort sichtbar.
 *
 * Dies ist die STANDALONE-Variante mit festem Testschlüssel (für den
 * isolierten Dockerfile-Build dieser Phase). Die echte, pro Deployment
 * zufällige Variante ist cipher_stamp.c.tmpl + infra/entrypoint.sh.
 */
#include <stdio.h>
#include <unistd.h>

static const unsigned char LUPIN_FIELD_KEY[] = "C4GL10"; /* 6 Byte -- viel zu kurz */
#define KEY_LEN 6

static const char TAUNT[] = "Salut Ganimard. Sie sind wieder zu langsam.";

int main(void) {
    fprintf(stderr, "[cipher_stamp] %s\n", TAUNT);

    unsigned char buf[65536];
    ssize_t n;
    size_t ctr = 0;

    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        for (ssize_t j = 0; j < n; j++) {
            buf[j] ^= LUPIN_FIELD_KEY[ctr % KEY_LEN];
            ctr++;
        }
        if (write(STDOUT_FILENO, buf, (size_t)n) != n) {
            return 1;
        }
    }
    return 0;
}
