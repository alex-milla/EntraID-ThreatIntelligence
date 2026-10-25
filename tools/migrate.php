<?php
/**
 * migrate.php — Migración del markup al sistema de tokens.
 *
 *   php tools/migrate.php --dry-run     (informe, sin escribir)
 *   php tools/migrate.php               (aplica)
 *   php tools/migrate.php --only=admin  (solo rutas que contengan "admin")
 *
 * Transforma SOLO los atributos class="..." de las vistas:
 *   · pares claro/oscuro  -> utilidad tokenizada (bg-surface, border-line, text-ink…)
 *   · familias semánticas -> tokens de significado (success/danger/warning/info)
 *   · utilidades grises sueltas -> token equivalente
 * No toca PHP, ni estructura, ni comportamiento.
 */

declare(strict_types=1);

$root    = dirname(__DIR__) . '/public_html';
$dryRun  = in_array('--dry-run', $argv, true);
$only    = null;
foreach ($argv as $a) {
    if (str_starts_with($a, '--only=')) { $only = substr($a, 7); }
}

/** Ficheros excluidos: páginas independientes con CSS propio. */
$exclude = ['/setup.php', '/admin-recovery.php', '/diagnostic.php', '/views/errors/'];

/* ============================================================
   1. Pares claro/oscuro (orden: más largos primero)
   ============================================================ */
$pairs = [
    // Superficie de página
    'bg-gray-50 dark:bg-gray-900'                 => 'bg-page',

    // Superficies
    'bg-white dark:bg-surface-dark'               => 'bg-surface',
    'bg-surface dark:bg-surface-dark'             => 'bg-surface',
    'bg-white dark:bg-gray-900'                   => 'bg-surface',
    'bg-white dark:bg-gray-800'                   => 'bg-surface',
    'bg-white dark:bg-slate-800'                  => 'bg-surface',

    // Superficies internas / hover
    'bg-gray-50 dark:bg-gray-800'                 => 'bg-muted',
    'bg-gray-50 dark:bg-gray-700'                 => 'bg-muted',
    'bg-gray-100 dark:bg-gray-800'                => 'bg-muted',
    'bg-gray-100 dark:bg-gray-900'                => 'bg-muted',
    'bg-gray-100 dark:bg-gray-700'                => 'bg-surface-3',
    'bg-gray-200 dark:bg-gray-700'                => 'bg-surface-3',
    'hover:bg-gray-50 dark:hover:bg-muted-dark'   => 'hover:bg-muted',
    'hover:bg-gray-50 dark:hover:bg-gray-800/50'  => 'hover:bg-muted',
    'hover:bg-gray-50 dark:hover:bg-gray-800/40'  => 'hover:bg-muted',
    'hover:bg-gray-50 dark:hover:bg-gray-800/60'  => 'hover:bg-muted',
    'hover:bg-gray-50 dark:hover:bg-gray-800'     => 'hover:bg-muted',
    'hover:bg-gray-100 dark:hover:bg-gray-800'    => 'hover:bg-muted',
    'hover:bg-gray-100 dark:hover:bg-muted-dark'  => 'hover:bg-muted',
    'hover:bg-gray-200 dark:hover:bg-gray-700'    => 'hover:bg-surface-3',

    // Bordes
    'border-gray-200 dark:border-gray-700'        => 'border-line',
    'border-gray-200 dark:border-gray-800'        => 'border-line',
    'border-gray-100 dark:border-gray-700'        => 'border-line-subtle',
    'border-gray-100 dark:border-gray-800'        => 'border-line-subtle',
    'border-gray-100 dark:border-gray-700/50'     => 'border-line-subtle',
    'border-gray-300 dark:border-gray-600'        => 'border-line-strong',
    'border-gray-300 dark:border-gray-500'        => 'border-line-strong',

    'divide-gray-100 dark:divide-gray-700/50'     => 'divide-line-subtle',
    'divide-gray-100 dark:divide-gray-800'        => 'divide-line-subtle',
    'divide-gray-200 dark:divide-gray-700'        => 'divide-line',

    // Texto
    'text-gray-900 dark:text-white'               => 'text-ink',
    'text-gray-900 dark:text-gray-100'            => 'text-ink',
    'text-gray-800 dark:text-white'               => 'text-ink',
    'text-gray-700 dark:text-gray-300'            => 'text-ink',
    'text-gray-700 dark:text-gray-200'            => 'text-ink',
    'text-gray-600 dark:text-gray-300'            => 'text-ink-muted',
    'text-gray-600 dark:text-gray-400'            => 'text-ink-muted',
    'text-gray-500 dark:text-gray-400'            => 'text-ink-muted',
    'text-gray-500 dark:text-gray-300'            => 'text-ink-muted',
    'text-gray-400 dark:text-gray-500'            => 'text-ink-soft',

    // Marca
    'text-brand-600 dark:text-brand-400'          => 'text-primary',
    'text-brand-500 dark:text-brand-400'          => 'text-primary',
    'text-brand-700 dark:text-brand-300'          => 'text-brand-700 dark:text-brand-300',
    'hover:text-brand-600 dark:hover:text-brand-400' => 'hover:text-primary-hover',
    'hover:text-brand-500 dark:hover:text-brand-400' => 'hover:text-primary-hover',
];

/* ============================================================
   2. Familias semánticas -> tokens de significado
   ============================================================ */
$families = [
    'green'  => 'success',
    'emerald'=> 'success',
    'red'    => 'danger',
    'rose'   => 'danger',
    'amber'  => 'warning',
    'yellow' => 'warning',
    'blue'   => 'info',
    'sky'    => 'info',
];

$semantic = [];
foreach ($families as $color => $sem) {
    // fondos suaves
    foreach ([50, 100] as $shade) {
        $semantic["bg-{$color}-{$shade} dark:bg-{$color}-900/30"] = "bg-{$sem}-bg";
        $semantic["bg-{$color}-{$shade} dark:bg-{$color}-900/20"] = "bg-{$sem}-bg";
        $semantic["bg-{$color}-{$shade} dark:bg-{$color}-900/25"] = "bg-{$sem}-bg";
        $semantic["bg-{$color}-{$shade} dark:bg-{$color}-900/40"] = "bg-{$sem}-bg";
        $semantic["bg-{$color}-{$shade} dark:bg-{$color}-950"]    = "bg-{$sem}-bg";
        $semantic["bg-{$color}-{$shade} dark:bg-{$color}-800"]    = "bg-{$sem}-bg";
    }
    // texto
    foreach ([500, 600, 700, 800] as $shade) {
        $semantic["text-{$color}-{$shade} dark:text-{$color}-300"] = "text-{$sem}";
        $semantic["text-{$color}-{$shade} dark:text-{$color}-400"] = "text-{$sem}";
        $semantic["text-{$color}-{$shade} dark:text-{$color}-200"] = "text-{$sem}";
    }
    // bordes
    foreach ([200, 300] as $shade) {
        $semantic["border-{$color}-{$shade} dark:border-{$color}-800"] = "border-{$sem}-border";
        $semantic["border-{$color}-{$shade} dark:border-{$color}-700"] = "border-{$sem}-border";
        $semantic["border-{$color}-{$shade} dark:border-{$color}-900"] = "border-{$sem}-border";
    }
}

/* ============================================================
   3. Utilidades sueltas
   ============================================================ */
$singles = [
    'text-gray-500'  => 'text-ink-muted',
    'text-gray-600'  => 'text-ink-muted',
    'text-gray-700'  => 'text-ink',
    'text-gray-800'  => 'text-ink',
    'text-gray-900'  => 'text-ink',
    'text-gray-400'  => 'text-ink-soft',
    'bg-white'       => 'bg-surface',
    'bg-gray-50'     => 'bg-muted',
    'bg-gray-100'    => 'bg-muted',
    'bg-gray-200'    => 'bg-surface-3',
    'border-gray-200'=> 'border-line',
    'border-gray-300'=> 'border-line-strong',
    'border-gray-100'=> 'border-line-subtle',
    'divide-gray-100'=> 'divide-line-subtle',
    'divide-gray-200'=> 'divide-line',
    'placeholder-gray-400' => 'placeholder:text-ink-soft',
    'placeholder-gray-500' => 'placeholder:text-ink-soft',
];

/* ============================================================
   4. Familias semánticas sueltas (sin par oscuro)
   ============================================================ */
foreach ($families as $color => $sem) {
    foreach ([50, 100] as $shade) {
        $singles["bg-{$color}-{$shade}"] = "bg-{$sem}-bg";
    }
    foreach ([600, 700] as $shade) {
        $singles["text-{$color}-{$shade}"] = "text-{$sem}";
    }
    foreach ([200, 300] as $shade) {
        $singles["border-{$color}-{$shade}"] = "border-{$sem}-border";
    }
}

/* ============================================================
   Aplicación
   ============================================================ */
$mapping = $pairs + $semantic + $singles;
// Ordenar por longitud descendente para evitar reemplazos parciales
uksort($mapping, fn($a, $b) => strlen($b) <=> strlen($a));

$composites = [
    'rounded-xl border border-line bg-surface' => 'card',
    'rounded-xl border border-line bg-page'    => 'card',
    'bg-surface border border-line rounded-xl' => 'card',
    'bg-surface rounded-xl border border-line' => 'card',
    'border border-line bg-surface rounded-xl' => 'card',
];
uksort($composites, fn($a, $b) => strlen($b) <=> strlen($a));

$stats = [];
$changedFiles = 0;
$totalChanges = 0;

$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
$files = [];
foreach ($it as $f) {
    if ($f->getExtension() !== 'php') { continue; }
    $p = str_replace('\\', '/', $f->getPathname());
    $skip = false;
    foreach ($exclude as $ex) {
        if (str_ends_with($p, $ex)) { $skip = true; break; }
    }
    if ($skip) { continue; }
    if ($only !== null && !str_contains($p, $only)) { continue; }
    $files[] = $p;
}

foreach ($files as $file) {
    $src = file_get_contents($file);
    $fileChanges = 0;

    $out = preg_replace_callback('/class\s*=\s*"([^"]*)"/s', function ($m) use ($mapping, $composites, $src, &$fileChanges, &$stats) {
        $original = $m[1][0];
        $attrOffset = $m[0][1];
        $value = $original;

        // No tocar atributos con PHP interpolado (se resuelven en runtime)
        if (str_contains($value, '<?')) { return $m[0][0]; }

        foreach ($mapping as $from => $to) {
            if (!str_contains($value, $from)) { continue; }
            $value = preg_replace('/(?<![\w:-])' . preg_quote($from, '/') . '(?![\w:-])/', $to, $value, -1, $count);
            if ($count > 0) {
                $stats[$from] = ($stats[$from] ?? 0) + $count;
                $fileChanges += $count;
            }
        }

        // Composición de tarjeta (solo si conviven las tres piezas)
        foreach ($composites as $from => $to) {
            if (!str_contains($value, $from)) { continue; }
            $value = str_replace($from, $to, $value, $count);
            if ($count > 0) {
                $stats[$from] = ($stats[$from] ?? 0) + $count;
                $fileChanges += $count;
            }
        }

        if ($value === $original) { return $m[0][0]; }

        // Campos de formulario: fondo propio (--input-bg), no el de superficie
        $before = substr($src, max(0, $attrOffset - 400), min(400, $attrOffset));
        $lt = strrpos($before, '<');
        if ($lt !== false) {
            $open = substr($before, $lt);
            if (preg_match('/^<(input|select|textarea)\b/i', $open) && !str_contains($open, '>')) {
                $value = preg_replace('/(?<![\w:-])bg-surface(?![\w:-])/', 'bg-input', $value);
            }
        }

        // Limpiar duplicados y espacios
        $tokens = preg_split('/\s+/', trim($value)) ?: [];
        $tokens = array_values(array_unique(array_filter($tokens, fn($t) => $t !== '')));
        $value = implode(' ', $tokens);

        return 'class="' . $value . '"';
    }, $src, -1, $count, PREG_OFFSET_CAPTURE);

    if ($out !== null && $out !== $src) {
        $changedFiles++;
        $totalChanges += $fileChanges;
        if (!$dryRun) {
            file_put_contents($file, $out);
        }
    }
}

arsort($stats);
$lookup = $composites + $mapping;

echo ($dryRun ? 'DRY-RUN' : 'APLICADO') . ' · ficheros: ' . $changedFiles . ' · reemplazos: ' . $totalChanges . PHP_EOL;
echo str_repeat('-', 78) . PHP_EOL;
$i = 0;
foreach ($stats as $from => $n) {
    printf("%5d  %-46s -> %s\n", $n, $from, $lookup[$from] ?? '');
    if (++$i >= 60) { break; }
}
