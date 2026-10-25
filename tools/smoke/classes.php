<?php
/**
 * classes.php — Analiza las clases usadas en las vistas (CLI).
 * Uso:
 *   php tools/smoke/classes.php --top=60            (tokens)
 *   php tools/smoke/classes.php --pairs --top=40    (pares claro/oscuro)
 *   php tools/smoke/classes.php --full --top=30     (atributo class completo)
 */

declare(strict_types=1);

$root = dirname(__DIR__, 2) . '/public_html';
$topN = 60;
$mode = 'tokens';
$only = null;

foreach ($argv as $a) {
    if (str_starts_with($a, '--top=')) { $topN = (int)substr($a, 6); }
    if ($a === '--pairs') { $mode = 'pairs'; }
    if ($a === '--full') { $mode = 'full'; }
    if (str_starts_with($a, '--file=')) { $only = substr($a, 7); }
}

$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
$tokens = [];
$pairs = [];
$full = [];
$attrs = 0;
$files = 0;

foreach ($it as $f) {
    if ($f->getExtension() !== 'php') { continue; }
    $p = $f->getPathname();
    if ($only !== null && !str_contains($p, $only)) { continue; }
    $files++;
    $src = file_get_contents($p);
    if (!preg_match_all('/class\s*=\s*"([^"]*)"/s', $src, $m)) { continue; }
    foreach ($m[1] as $raw) {
        if (str_contains($raw, '<?')) { continue; }
        $attrs++;
        $val = trim($raw);
        if ($val !== '') { $full[$val] = ($full[$val] ?? 0) + 1; }

        $classes = preg_split('/\s+/', $val) ?: [];
        foreach ($classes as $c) {
            if ($c === '') { continue; }
            $tokens[$c] = ($tokens[$c] ?? 0) + 1;
        }
        for ($i = 0; $i < count($classes) - 1; $i++) {
            if (str_starts_with($classes[$i + 1], 'dark:')) {
                $key = $classes[$i] . ' ' . $classes[$i + 1];
                $pairs[$key] = ($pairs[$key] ?? 0) + 1;
            }
        }
    }
}

$data = match ($mode) {
    'pairs' => $pairs,
    'full'  => $full,
    default => $tokens,
};
arsort($data);

$label = match ($mode) { 'pairs' => 'pares', 'full' => 'atributos completos', default => 'tokens' };
echo "Ficheros: {$files} · atributos class: {$attrs} · {$label}: " . count($data) . PHP_EOL;
echo str_repeat('-', 78) . PHP_EOL;

$i = 0;
foreach ($data as $k => $v) {
    printf("%5d  %s\n", $v, $k);
    if (++$i >= $topN) { break; }
}
