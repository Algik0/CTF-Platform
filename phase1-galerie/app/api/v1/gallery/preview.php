<?php
/**
 * Interner Preview-Dienst für die Galerie.
 *
 * GET /api/v1/gallery/preview?img=<name>
 *
 * Entwickler-Notiz (aus dem alten Commit-Log übernommen):
 *   "Lädt Vorschaubilder aus static/gallery/. Für Spezialfälle (externe
 *    Mirrors, komprimierte Thumbnails) darf img auch einen vollen Pfad
 *    bzw. einen Stream-Wrapper enthalten -- betrifft uns nicht, da wir
 *    nur Admin-Zugriff auf diesen Endpoint erlauben." (-- das stimmt
 *    nicht: der Endpoint ist unauthenticated.)
 *
 * Hinweis für Betreuer/Writeup: Der naheliegende Lehrbuch-Trick
 * "php://filter/convert.base64-encode/resource=/proc/self/environ"
 * funktioniert gegen einen echten Apache-mod_php-Worker NICHT
 * zuverlässig. Apache's mpm_prefork-Worker droppen Root->www-data per
 * in-process setuid() OHNE anschließendes execve() -- der Kernel
 * löscht dabei das "dumpable"-Flag, wodurch der Prozess sein EIGENES
 * /proc/self/environ nicht mehr lesen darf (siehe `man proc`,
 * "/proc/[pid]/environ", Abschnitt zu PR_SET_DUMPABLE). Das wurde beim
 * Bau dieser Challenge gegen ein echtes Apache+mod_php-Setup verifiziert
 * (nicht nur angenommen) -- deshalb liegt das eigentliche Secret in
 * einer Config-Datei außerhalb des Webroots, nicht in der Umgebung.
 * Der Stream-Wrapper selbst bleibt als Technik relevant, z. B. um
 * preview.php per convert.base64-encode gefahrlos (ohne Ausführung)
 * im Quelltext zu lesen.
 */

header('X-Powered-By: MaisonDErmont-Preview/1.4');
header('Content-Type: text/plain; charset=utf-8');

$img = $_GET['img'] ?? '';

if ($img === '') {
    http_response_code(400);
    echo "Parameter 'img' fehlt.";
    exit;
}

// "Sicherheitsfilter" gegen die offensichtlichsten Path-Traversal-Versuche.
// Greift nur bei literalen "../"-Sequenzen -- Stream-Wrapper und absolute
// Pfade werden nicht erkannt.
$blacklist = ['../', '..\\', '/etc/passwd', '/etc/shadow'];
foreach ($blacklist as $pattern) {
    $img = str_ireplace($pattern, '', $img);
}

$gallery_dir = realpath(__DIR__ . '/../../../static/gallery');

// Enthält der (gefilterte) Parameter keinen Schrägstrich, wird er als
// einfacher Dateiname innerhalb von static/gallery/ behandelt.
// Enthält er einen Schrägstrich (Pfad ODER Stream-Wrapper wie
// "php://filter/..." oder "data://..."), wird angenommen, es handle
// sich um eine der oben erwähnten "Spezialfälle" und der Wert wird
// UNGEFILTERT an include() übergeben.
if (basename($img) === $img) {
    $target = $gallery_dir . '/' . $img;
} else {
    $target = $img; // <-- Local File Inclusion / Wrapper-Abuse
}

ob_start();
$ok = @include($target);
$content = ob_get_clean();

if ($ok === false && $content === '') {
    http_response_code(404);
    echo "Vorschau nicht verfügbar.";
    exit;
}

echo $content;
