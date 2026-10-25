<?php
/**
 * coverage.php — Clases usadas en el markup que no tienen regla en ningún CSS.
 * Uso: php tools/smoke/coverage.php [--all]
 */

declare(strict_types=1);

$root = dirname(__DIR__, 2);
$pub  = $root . '/public_html';
$showAll = in_array('--all', $argv, true);

$css = '';
foreach (['assets/css/app.css', 'assets/css/ui.css', 'assets/css/tw.css'] as $f) {
    $css .= file_get_contents($pub . '/' . $f) . "\n";
}
$css = str_replace('\\', '', $css);

// Hooks funcionales sin estilo propio (JS / semántica) y utilidades de páginas independientes
$hooks = [
    'auto-submit', 'no-print', 'print-hide', 'print-url', 'row-check', 'has-selection',
    'selection-mode', 'is-open', 'is-active', 'is-visible', 'is-leaving', 'is-selected',
    'dd-active', 'drawer-open', 'drawer-detail', 'transition-theme', 'ui-v2', 'app-shell',
    'app-body', 'app-sidebar', 'app-header', 'app-main', 'page-container', 'page-footer',
    'js-sort', 'js-sort-arrow', 'group', 'report-ai', 'badge-ok', 'badge-err', 'mono', 'muted',
    'spinner', 'line-clamp-2', 'badge-syncing', 'md-body', 'hide-on-small-only',
    'material-icons', 'icon-12', 'icon-14', 'icon-16', 'icon-18', 'icon-20', 'icon-24',
    'icon-32', 'progress', 'determinate', 'pagination', 'pager', 'pagination-info',
    'stat-strip', 'stat', 'stat-ico', 'stat-num', 'stat-label', 'data-table', 'dense',
    'col-secondary', 'row-actions', 'th-sort', 'input-field', 'helper-text', 'prefix',
    'check-inline', 'num-input', 'chip', 'chip-tabs', 'chip-count', 'chip-x', 'view-tab',
    'admin-tabs', 'alert', 'alert-error', 'alert-success', 'alert-warning', 'alert-info',
    'notice', 'hint-bar', 'hint', 'status-badge', 'tag-chip', 'role-chip', 'badge-new',
    'count-chip', 'card-head', 'card-sub', 'page-header', 'subtitle', 'spacer', 'btn',
    'btn-small', 'btn-large', 'btn-outline', 'btn-flat', 'btn-danger', 'btn-good',
    'btn-bad', 'btn-warning', 'btn-info', 'btn-tiny', 'icon-btn', 'card', 'is-clickable',
    'unread', 'filter-open', 'sidebar-nav', 'sidebar-group-label', 'sidebar-link',
    'sidebar-sublink', 'sidebar-submenu', 'sidebar-subgroup', 'sidebar-parent',
    'sidebar-caret', 'sidebar-brand', 'sidebar-logo', 'sidebar-footer', 'user-menu',
    'user-menu-panel', 'menu-sep', 'theme-toggle', 'shell-menu', 'shell-overlay',
    'filter-form', 'filter-toggle', 'filter-overlay', 'bulk-toolbar', 'action-menu',
    'action-menu-dropdown', 'detail-drawer', 'dd-head', 'dd-body', 'dd-title', 'dd-overlay',
    'back-to-top', 'tdl-toast-stack', 'tdl-toast', 'tdl-toast-body', 'tdl-toast-title',
    'tdl-toast-close', 'tdl-modal-overlay', 'tdl-modal', 'tdl-modal-head', 'tdl-modal-body',
    'tdl-modal-actions',
];

$missing = [];
$scanned = 0;

$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($pub, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    if (!in_array($f->getExtension(), ['php', 'js'], true)) { continue; }
    $src = file_get_contents($f->getPathname());
    if (!preg_match_all('/class\s*=\s*"([^"]*)"/s', $src, $m)) { continue; }
    foreach ($m[1] as $attr) {
        if (str_contains($attr, '<?')) { continue; }
        foreach (preg_split('/\s+/', trim($attr)) ?: [] as $c) {
            if ($c === '' || $c === "'" || $c === '+' || $c === '.' || $c === '?' || $c === ':' || $c === '>') { continue; }
            $scanned++;
            if (in_array($c, $hooks, true)) { continue; }
            $needle = '.' . $c;
            if (str_contains($css, $needle . '{')
                || str_contains($css, $needle . ':')
                || str_contains($css, $needle . ' ')
                || str_contains($css, $needle . ',')
                || str_contains($css, $needle . '>')
                || str_contains($css, $needle . '[')
            ) {
                continue;
            }
            $missing[$c] = ($missing[$c] ?? 0) + 1;
        }
    }
}

arsort($missing);
echo 'Clases escaneadas: ' . $scanned . ' · distintas sin regla: ' . count($missing) . PHP_EOL;
echo str_repeat('-', 60) . PHP_EOL;
$limit = $showAll ? count($missing) : 40;
$i = 0;
foreach ($missing as $c => $n) {
    printf("%5d  %s\n", $n, $c);
    if (++$i >= $limit) { break; }
}
