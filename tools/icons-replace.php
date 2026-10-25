<?php
/**
 * icons-replace.php — Sustituye los SVG inline por Material Icons.
 *
 *   php tools/icons-replace.php --dry-run
 *   php tools/icons-replace.php
 *
 * Conserva las clases de contexto (color, animación, posicionamiento) y
 * traduce el tamaño (w-4 -> icon-16, w-[18px] -> icon-18, …).
 */

declare(strict_types=1);

$root   = dirname(__DIR__) . '/public_html';
$dryRun = in_array('--dry-run', $argv, true);

$exclude = ['/setup.php', '/admin-recovery.php', '/diagnostic.php', '/views/errors/',
            '/views/layout/header.php', '/views/admin/login.php'];

/** Prefijo del path (lucide) -> nombre Material Icons */
$icons = [
    'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9'   => 'sync',
    'M9 5l7 7-7 7'                                    => 'chevron_right',
    'M19 7l-.867 12.142A2 2 0 0116.138 21'            => 'delete',
    'M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11'         => 'edit',
    'M12 4v16m8-8H4'                                  => 'add',
    'M12 9v2m0 4h.01m-6.938 4h13.856c1.54'            => 'warning',
    'M15 19l-7-7 7-7'                                 => 'chevron_left',
    'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2'          => 'description',
    'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4' => 'download',
    'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118'      => 'check_circle',
    'M9.663 17h4.673M12 3v1m6.364 1.636l-.707'        => 'lightbulb',
    'M5 13l4 4L19 7'                                  => 'check',
    'M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2'             => 'widgets',
    'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2'                => 'analytics',
    'M17 20h5v-2a3 3 0 00-5.356-1.857M17'            => 'group',
    'M10.325 4.317c.426-1.756 2.924-1.756'            => 'settings',
    'M21 21l-4.35-4.35M17 10.5a6.5 6.5 0'            => 'search',
    'M4 8V4h4M20 8V4h-4M4 16v4h4M20 16v4h-4'         => 'open_in_full',
    'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14'     => 'business',
    'M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8'         => 'folder',
    'M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z'            => 'progress_activity',
    'M6 18L18 6M6 6l12 12'                            => 'close',
    'M4 4v5h5M20 20v-5h-5M5.3 9A7 7 0'               => 'refresh',
    'M3 10h18M3 14h18m-9-4v8m-7 0h14a2'              => 'dns',
    'M20 7l-8-4-8 4m16 0l-8 4m8-4v10'                => 'inventory_2',
    'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0'               => 'terminal',
    'M13 10V3L4 14h7v7l9-11h-7z'                      => 'bolt',
    'M3 21h18M5 21V7l7-4 7 4v14M9 9h.01'             => 'apartment',
    'M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2'       => 'print',
    'M18.364 18.364A9 9 0 005.636 5.636m12.728'      => 'block',
    'M10 19l-7-7m0 0l7-7m-7 7h18'                    => 'arrow_back',
];

$sizeByClass = [
    'w-3 h-3' => 12,
    'w-3.5 h-3.5' => 14,
    'w-4 h-4' => 16,
    'w-[18px] h-[18px]' => 18,
    'w-5 h-5' => 20,
    'w-6 h-6' => 24,
    'w-8 h-8' => 32,
];

$stats = ['replaced' => 0, 'unknown' => 0, 'files' => 0];
$unknown = [];

$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if ($f->getExtension() !== 'php') { continue; }
    $path = str_replace('\\', '/', $f->getPathname());
    $skip = false;
    foreach ($exclude as $ex) { if (str_ends_with($path, $ex)) { $skip = true; break; } }
    if ($skip) { continue; }

    $src = file_get_contents($path);
    $fileChanges = 0;

    $out = preg_replace_callback('@<svg\b([^>]*)>(.*?)</svg>@s', function ($m) use ($icons, $sizeByClass, &$stats, &$unknown, &$fileChanges) {
        $attrs = $m[1];
        $inner = $m[2];

        $d = '';
        if (preg_match('/\sd="([^"]+)"/', $inner, $dm)
            || preg_match('/\sd="([^"]+)"/', $attrs, $dm)) {
            $d = $dm[1];
        }

        $name = null;
        foreach ($icons as $prefix => $mat) {
            if (str_starts_with($d, $prefix)) { $name = $mat; break; }
        }

        if ($name === null) {
            $stats['unknown']++;
            $unknown[substr($d, 0, 50)] = ($unknown[substr($d, 0, 50)] ?? 0) + 1;
            return $m[0];
        }

        $class = '';
        if (preg_match('/class="([^"]*)"/', $attrs, $cm)) { $class = $cm[1]; }

        $size = 18;
        foreach ($sizeByClass as $sig => $px) {
            if (str_contains($class, $sig)) { $size = $px; break; }
        }

        // Conservar clases de contexto y quitar las de tamaño
        $keep = preg_split('/\s+/', trim($class)) ?: [];
        $keep = array_filter($keep, function ($c) {
            return !preg_match('@^[wh]-(\d+(\.\d+)?|\[[^\]]+\])$@', $c)
                && !in_array($c, ['inline', 'shrink-0'], true);
        });
        $keep = array_values($keep);

        $stats['replaced']++;
        $fileChanges++;

        return '<i class="material-icons icon-' . $size . ($keep ? ' ' . implode(' ', $keep) : '') . '"'
            . ' aria-hidden="true">' . $name . '</i>';
    }, $src);

    if ($out !== null && $out !== $src) {
        $stats['files']++;
        if (!$dryRun) { file_put_contents($path, $out); }
    }
}

echo ($dryRun ? 'DRY-RUN' : 'APLICADO') . PHP_EOL;
echo '  iconos sustituidos: ' . $stats['replaced'] . PHP_EOL;
echo '  ficheros:           ' . $stats['files'] . PHP_EOL;
echo '  sin mapear:         ' . $stats['unknown'] . PHP_EOL;
if ($unknown) {
    foreach ($unknown as $d => $n) { echo '    [' . $n . 'x] ' . $d . PHP_EOL; }
}
