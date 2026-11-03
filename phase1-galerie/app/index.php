<?php
/**
 * Maison d'Ermont -- öffentliche Galerie-Website.
 * Phase 1 "Die Fassade der Galerie" -- bewusst verwundbare Zielanwendung
 * für das Offensive-Security-CTF "Das Erbe von Cagliostro".
 */
$pieces = [
    ['title' => 'La Dame au Voile Bleu',  'era' => '1888', 'note' => 'Herkunft ungeklärt – laut Katalog "Privatankauf, Genf".'],
    ['title' => 'Nocturne sur la Seine',  'era' => '1901', 'note' => 'Zuletzt 1962 im Musée d\'Orsay dokumentiert.'],
    ['title' => 'Portrait du Cardinal',   'era' => '1743', 'note' => 'Herkunftsnachweis fehlt vollständig.'],
    ['title' => 'Étude en Or',            'era' => '1925', 'note' => 'Versicherungswert: "nicht offengelegt".'],
];
?>
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Maison d'Ermont — Privatgalerie</title>
  <style>
    body { font-family: Georgia, serif; background:#0d0d0d; color:#e8e0c8; margin:0; }
    header { padding:3rem 2rem 1rem; border-bottom:1px solid #4a3f2a; }
    h1 { font-size:2.2rem; letter-spacing:.1em; color:#c9a34e; margin:0; }
    .sub { color:#8a7f63; font-style:italic; }
    main { max-width:900px; margin:2rem auto; padding:0 2rem; }
    .piece { border:1px solid #2a2a2a; padding:1.2rem; margin-bottom:1rem; background:#141414; }
    .piece h2 { margin:0 0 .3rem; color:#c9a34e; font-size:1.2rem; }
    .piece .era { color:#8a7f63; font-size:.9rem; }
    footer { text-align:center; color:#4a3f2a; padding:2rem; font-size:.8rem; }
  </style>
</head>
<body>
<header>
  <h1>MAISON D'ERMONT</h1>
  <div class="sub">Privatsammlung &amp; Kunsthandel seit 1961 — Baron Édouard d'Ermont</div>
</header>
<main>
  <p>Willkommen auf der privaten Galerieseite des Hauses d'Ermont. Unsere Sammlung
  umfasst Werke von unschätzbarem, mitunter ungeklärtem Wert.</p>
  <?php foreach ($pieces as $p): ?>
  <div class="piece">
    <h2><?php echo htmlspecialchars($p['title']); ?></h2>
    <div class="era"><?php echo htmlspecialchars($p['era']); ?></div>
    <p><?php echo htmlspecialchars($p['note']); ?></p>
  </div>
  <?php endforeach; ?>
  <p style="color:#4a3f2a;font-size:.85rem;">Bildvorschauen werden dynamisch über unser
  internes Preview-System geladen und sind aus Performance-Gründen nicht Teil
  dieser Seite.</p>
</main>
<footer>&copy; Maison d'Ermont — Alle Rechte vorbehalten (angeblich).</footer>
<!-- Lupin war hier. Wer gut genug sucht, findet seine Karte in der Galerie. -->
<!-- -- der Praktikant, der diesen Kommentar nicht löschen sollte -->
</body>
</html>
