<?php
/**
 * icons.php — Inventario de SVG inline a sustituir por Material Icons.
 * Uso: php tools/icons.php [--context]
 */

declare(strict_types=1);

$root = dirname(__DIR__) . '/public_html';
$withContext = in_array('--context', $argv, true);
$exclude = ['/setup.php', '/admin-recovery.php', '/diagnostic.php', '/views/errors/', '/views/layout/header.php', '/views/admin/login.php'];

$groups = [];

$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if ($f->getExtension() !== 'php') { continue; }
    $path = str_replace('\\', '/', $f->getPathname());
    $skip = false;
    foreach ($exclude as $ex) { if (str_ends_with($path, $ex)) { $skip = true; break; } }
    if ($skip) { continue; }

    $src = file_get_contents($path);
    if (!preg_match_all('@<svg\b[^>]*>.*?</svg>@s', $src, $m, PREG_OFFSET_CAPTURE)) { continue; }

    foreach ($m[0] as [$svg, $offset]) {
        $inner = '';
        if (preg_match_all('/\sd="([^"]+)"/', $svg, $dm)) { $inner = implode('|', $dm[1]); }
        $key = substr($inner, 0, 60);

        $cls = '';
        if (preg_match('/class="([^"]*)"/', $svg, $cm)) { $cls = $cm[1]; }

        $groups[$key]['count'] = ($groups[$key]['count'] ?? 0) + 1;
        $groups[$key]['class'] = $cls;
        $groups[$key]['files'][basename($path)] = true;

        if ($withContext) {
            $before = substr($src, max(0, $offset - 120), 120);
            $after = substr($src, $offset + strlen($svg), 120);
            $ctx = preg_replace('/\s+/', ' ', strip_tags($before) . ' [SVG] ' . strip_tags($after));
            $groups[$key]['ctx'] = trim(substr($ctx, -160));
        }
    }
}

uasort($groups, fn($a, $b) => $b['count'] <=> $a['count']);

echo 'SVG únicos: ' . count($groups) . PHP_EOL;
echo str_repeat('=', 80) . PHP_EOL;

foreach ($groups as $key => $g) {
    echo '[' . $g['count'] . 'x] class="' . $g['class'] . '"' . PHP_EOL;
    echo '    ' . (str_contains($key, '|') ? explode('|', $key)[0] : $key) . PHP_EOL;
    if ($withContext && isset($g['ctx'])) {
        echo '    ctx: ' . $g['ctx'] . PHP_EOL;
    }
    echo '    files: ' . implode(', ', array_keys($g['files'])) . PHP_EOL;
    echo PHP_EOL;
}
