<?php
// PHP built-in web server router: only expose the public/ directory.
$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
if ($path==='/assets/style.css') return false;
require __DIR__.'/index.php';
