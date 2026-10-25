<?php
/**
 * Analiza las clases usadas en las vistas (CLI).
 * Uso: php tools/smoke/classes.php [--pairs] [--top=N] [--file=ruta]
 */

declare(strict_types=1);

$root = dirname(__DIR__, 2) . '/public_html';
$args = $argv;
$topN = 120;
$mode = 'tokens';
$only = null;

foreach ($args as $a) {
    if (str_starts_with($a, '--top=')) { $topN = (int)substr($a, 6); }
    if ($a === '--pairs') { $mode = 'pairs'; }
    if (str_starts_with($a, '--file=')) { $only = substr($a, 7); }
}

$files = [];
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if ($f->getExtension() !== 'php') { continue; }
    $p = $f->getPathname();
    if ($only !== null && !str_contains($p, $only)) { continue; }
    $files[] = $p;
}

$tokens = [];
$pairs = [];
$attrs = 0;

foreach ($files as $file) {
    $src = file_get_contents($file);
    if (!preg_match_all('/class\s*=\s*"([^"]*)"/s', $src, $m)) { continue; }
    foreach ($m[1] as $raw) {
        $attrs++;
        // Ignorar valores con PHP interpolado (se resuelven en runtime)
        $classes = preg_split('/\s+/', trim($raw)) ?: [];
        foreach ($classes as $c) {
            if ($c === '' || str_contains($c, '<') || str_contains($c, '<?')) { continue; }
            $tokens[$c] = ($tokens[$c] ?? 0) + 1;
        }
        // pares "X dark:Y"
        for ($i = 0; $i < count($classes) - 1; $i++) {
            if (str_starts_with($classes[$i + 1], 'dark:')) {
                $key = $classes[$i] . ' ' . $classes[$i + 1];
                $pairs[$key] = ($pairs[$key] ?? 0) + 1;
            }
        }
    }
}

$data = ($mode === 'pairs') ? $pairs : $tokens;
arsort($data);

echo 'Ficheros: ' . count($files) . ' · atributos class: ' . $attrs . ' · ' . ($mode === 'pairs' ? 'pares' : 'tokens') . ': ' . count($data) . PHP_EOL;
echo str_repeat('-', 70) . PHP_EOL;

$i = 0;
foreach ($data as $k => $v) {
    printf("%5d  %s\n", $v, $k);
    if (++$i >= $topN) { break; }
}
