<?php
/**
 * Honeypot. Sieht aus wie eine Backup-Verwaltung, nimmt JEDE Eingabe an
 * und führt direkt zur Spottkarte. Es gibt hier nichts zu gewinnen --
 * echte Tools wie ffuf/gobuster finden dieses Verzeichnis leicht, aber
 * das ist von der Story so beabsichtigt (Lupin markiert den offensichtlichen
 * Köder).
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Location: mockery.php');
    exit;
}
?>
<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>Backup-Verwaltung — Maison d'Ermont</title>
<style>
  body{font-family:monospace;background:#111;color:#ddd;display:flex;
       align-items:center;justify-content:center;height:100vh;margin:0;}
  .box{border:1px solid #333;padding:2rem;background:#1a1a1a;width:320px;}
  input{width:100%;padding:.5rem;margin:.4rem 0;background:#000;color:#0f0;
        border:1px solid #333;box-sizing:border-box;}
  button{width:100%;padding:.6rem;background:#333;color:#eee;border:none;
         margin-top:.6rem;cursor:pointer;}
</style></head>
<body>
<div class="box">
  <h3>🔒 Backup-Administration</h3>
  <form method="post">
    <input name="user" placeholder="Benutzername" autocomplete="off">
    <input name="pass" type="password" placeholder="Passwort">
    <button type="submit">Anmelden</button>
  </form>
</div>
</body>
</html>
