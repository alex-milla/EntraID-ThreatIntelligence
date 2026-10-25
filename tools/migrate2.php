<?php
/**
 * migrate2.php — Segunda pasada: componentes del catálogo y limpieza de restos.
 *
 *   php tools/migrate2.php --dry-run
 *   php tools/migrate2.php
 *
 *   1. Botones y avisos completos -> .btn / .alert
 *   2. Badges de estado -> .status-*
 *   3. Limpieza: quita dark:<color>-* redundantes cuando ya hay token semántico
 */

declare(strict_types=1);

$root   = dirname(__DIR__) . '/public_html';
$dryRun = in_array('--dry-run', $argv, true);

$exclude = ['/setup.php', '/admin-recovery.php', '/diagnostic.php', '/views/errors/'];

/* ------------------------------------------------------------
   1. Composiciones exactas
   ------------------------------------------------------------ */
$composites = [
    // Botones primarios
    'inline-flex items-center gap-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors' => 'btn',
    'w-full px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors' => 'btn w-full',
    'px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors' => 'btn',
    'inline-flex items-center gap-2 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors' => 'btn btn-small',
    'px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg' => 'btn btn-small',
    'w-full py-2.5 px-4 bg-brand-500 hover:bg-brand-600 text-white font-medium rounded-lg transition-colors' => 'btn w-full',

    // Botones secundarios
    'inline-flex items-center gap-2 px-4 py-2 border border-line hover:bg-muted text-sm font-medium rounded-lg transition-colors' => 'btn btn-outline',
    'px-4 py-2 border border-line hover:bg-muted text-sm font-medium rounded-lg transition-colors' => 'btn btn-outline',
    'inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-line hover:bg-muted transition-colors' => 'btn btn-small btn-outline',
    'inline-flex items-center px-3 py-1.5 border border-line hover:bg-muted text-xs font-medium rounded-lg transition-colors' => 'btn btn-small btn-outline',

    // Avisos
    'mb-4 px-4 py-3 rounded-lg text-sm text-danger bg-danger-bg' => 'alert alert-error',
    'mb-4 px-4 py-3 rounded-lg text-sm text-success bg-success-bg' => 'alert alert-success',
    'mb-4 px-4 py-3 rounded-lg text-sm text-warning bg-warning-bg' => 'alert alert-warning',
    'mb-4 px-4 py-3 rounded-lg text-sm text-info bg-info-bg' => 'alert alert-info',
];
uksort($composites, fn($a, $b) => strlen($b) <=> strlen($a));

/* ------------------------------------------------------------
   2. Badges de estado
   ------------------------------------------------------------ */
$badgeMap = [
    'bg-danger-bg'  => ['status-failed',    'text-danger'],
    'bg-success-bg' => ['status-completed', 'text-success'],
    'bg-warning-bg' => ['status-pending',   'text-warning'],
    'bg-info-bg'    => ['status-running',   'text-info'],
];

$shapeTokens = ['inline-flex', 'items-center', 'px-2', 'px-2.5', 'py-0.5', 'rounded-full', 'text-[10px]', 'text-[11px]'];

/* ------------------------------------------------------------
   3. Restos oscuros redundantes
   ------------------------------------------------------------ */
$semanticColors = ['green', 'emerald', 'red', 'rose', 'amber', 'yellow', 'blue', 'sky'];

function stripLeftovers(string $value, array $semanticColors): array
{
    $removed = 0;
    $tokens = preg_split('/\s+/', $value) ?: [];
    $has = fn(string $t) => in_array($t, $tokens, true);

    $hasTextSem = $has('text-success') || $has('text-danger') || $has('text-warning') || $has('text-info');
    $hasBgSem   = $has('bg-success-bg') || $has('bg-danger-bg') || $has('bg-warning-bg') || $has('bg-info-bg');
    $hasBdSem   = $has('border-success-border') || $has('border-danger-border')
               || $has('border-warning-border') || $has('border-info-border');

    $out = [];
    foreach ($tokens as $t) {
        $drop = false;
        foreach ($semanticColors as $c) {
            if ($hasTextSem && preg_match('@^dark:text-' . $c . '-(200|300|400)$@', $t)) { $drop = true; }
            if ($hasBgSem && preg_match('@^dark:bg-' . $c . '-(800|900|950)(/\d+)?$@', $t)) { $drop = true; }
            if ($hasBdSem && preg_match('@^dark:border-' . $c . '-(700|800|900)$@', $t)) { $drop = true; }
        }
        if ($drop) { $removed++; continue; }
        $out[] = $t;
    }

    return [implode(' ', $out), $removed];
}

/* ------------------------------------------------------------
   Aplicación
   ------------------------------------------------------------ */
$stats = ['composite' => 0, 'badge' => 0, 'cleanup' => 0, 'files' => 0];

$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if ($f->getExtension() !== 'php') { continue; }
    $path = str_replace('\\', '/', $f->getPathname());
    $skip = false;
    foreach ($exclude as $ex) { if (str_ends_with($path, $ex)) { $skip = true; break; } }
    if ($skip) { continue; }

    $src = file_get_contents($path);
    $fileChanges = 0;

    $out = preg_replace_callback('/class\s*=\s*"([^"]*)"/s', function ($m) use ($composites, $badgeMap, $shapeTokens, $semanticColors, &$stats, &$fileChanges) {
        $original = $m[1];
        if (str_contains($original, '<?')) { return $m[0]; }

        $value = $original;

        // 1) Composiciones
        foreach ($composites as $from => $to) {
            if (!str_contains($value, $from)) { continue; }
            $value = str_replace($from, $to, $value, $count);
            if ($count > 0) { $stats['composite'] += $count; $fileChanges += $count; }
        }

        // 2) Badges de estado
        $tokens = preg_split('/\s+/', trim($value)) ?: [];
        $isBadgeShape = in_array('inline-flex', $tokens, true)
            && in_array('rounded-full', $tokens, true)
            && (in_array('px-2', $tokens, true) || in_array('px-2.5', $tokens, true));

        if ($isBadgeShape) {
            foreach ($badgeMap as $bg => [$status, $text]) {
                if (!in_array($bg, $tokens, true)) { continue; }
                $tokens = array_values(array_filter($tokens, fn($t) => !in_array($t, $shapeTokens, true)));
                $tokens = array_values(array_filter($tokens, fn($t) => $t !== $bg && $t !== $text));
                $tokens[] = $status;
                $tokens = array_values(array_unique($tokens));
                $value = implode(' ', $tokens);
                $stats['badge']++;
                $fileChanges++;
                break;
            }
        }

        // 3) Limpieza de restos oscuros
        [$cleaned, $removed] = stripLeftovers($value, $semanticColors);
        if ($removed > 0) {
            $value = $cleaned;
            $stats['cleanup'] += $removed;
            $fileChanges += $removed;
        }

        if ($value === $original) { return $m[0]; }

        $final = preg_split('/\s+/', trim($value)) ?: [];
        $final = array_values(array_unique(array_filter($final, fn($t) => $t !== '')));

        return 'class="' . implode(' ', $final) . '"';
    }, $src);

    if ($out !== null && $out !== $src) {
        $stats['files']++;
        if (!$dryRun) { file_put_contents($path, $out); }
    }
}

echo ($dryRun ? 'DRY-RUN' : 'APLICADO') . PHP_EOL;
echo '  composiciones (btn/alert): ' . $stats['composite'] . PHP_EOL;
echo '  badges de estado:          ' . $stats['badge'] . PHP_EOL;
echo '  restos dark:* eliminados:  ' . $stats['cleanup'] . PHP_EOL;
echo '  ficheros modificados:      ' . $stats['files'] . PHP_EOL;
