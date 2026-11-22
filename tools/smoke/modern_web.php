<?php
/**
 * modern_web.php — Guardias de la Fase 1 (Modern Web Guidance, v0.4.28.15).
 *
 *   php tools/smoke/modern_web.php
 *
 * Comprueba por código fuente los invariantes de la modernización:
 *   - modales con <dialog> nativo + fallback, sin cambiar la API App.*
 *   - CSP Report-Only con nonce por petición (nunca modo enforcement)
 *   - prefers-reduced-motion en CSS y en el scroll del JS
 *   - VERSION alineada con el release
 * No necesita base de datos ni servidor.
 */

declare(strict_types=1);

$root = dirname(__DIR__, 2);
$read = static function (string $rel) use ($root): string {
    return (string)@file_get_contents($root . '/' . $rel);
};

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    if ($ok) {
        echo "OK   {$label}\n";
        return;
    }
    $fail++;
    echo "FALLO {$label}" . ($detail !== '' ? ' — ' . $detail : '') . "\n";
}

$appJs   = $read('public_html/assets/js/app.js');
$uiJs    = $read('public_html/assets/js/ui.js');
$appCss  = $read('public_html/assets/css/app.css');
$uiCss   = $read('public_html/assets/css/ui.css');
$boot    = $read('public_html/config/bootstrap.php');
$version = trim($read('public_html/VERSION'));

// --- Modales -------------------------------------------------------------
check('Modal: detecta soporte de <dialog>', str_contains($appJs, "document.createElement('dialog')")
    && str_contains($appJs, 'typeof probe.showModal'));
check('Modal: usa showModal()', str_contains($appJs, 'root.showModal()'));
check('Modal: cierra con close() al desmontar', str_contains($appJs, 'root.close()'));
check('Modal: Escape gestionado por el evento cancel', str_contains($appJs, "'cancel', cancelHandler"));
check('Modal: conserva el fallback <div>', str_contains($appJs, "document.createElement(native ? 'dialog' : 'div')"));
check('Modal: API pública intacta (confirm/alert/prompt)',
    str_contains($appJs, 'App.confirm = function')
    && str_contains($appJs, 'App.alert = function')
    && str_contains($appJs, 'App.prompt = function'));
check('Modal: estilos del <dialog> como overlay',
    str_contains($uiCss, 'dialog.tdl-modal-overlay[open]')
    && str_contains($uiCss, 'dialog.tdl-modal-overlay::backdrop'));

// --- CSP -----------------------------------------------------------------
check('CSP: nonce generado por petición', str_contains($boot, "define('CSP_NONCE'")
    && str_contains($boot, 'random_bytes(16)'));
check('CSP: cabecera en modo REPORT-ONLY', str_contains($boot, 'Content-Security-Policy-Report-Only:'));
check('CSP: NO hay cabecera restrictiva accidental',
    !preg_match("/header\(\s*['\"]Content-Security-Policy:/", $boot));
foreach (['views/layout/header.php', 'views/layout/footer.php',
          'views/admin/login.php', 'views/errors/404.php',
          'views/partials/ti_sync.php'] as $view) {
    check('CSP: nonce en ' . $view,
        str_contains($read('public_html/' . $view), "<script nonce=\"<?= defined('CSP_NONCE')"));
}

// --- Movimiento reducido -------------------------------------------------
check('CSS: prefers-reduced-motion', str_contains($appCss, '@media (prefers-reduced-motion: reduce)'));
check('JS: scroll respeta prefers-reduced-motion',
    str_contains($uiJs, "matchMedia('(prefers-reduced-motion: reduce)')")
    && str_contains($uiJs, "behavior: reduce ? 'auto' : 'smooth'"));

// --- Versión -------------------------------------------------------------
check('VERSION = 0.4.28.15', $version === '0.4.28.15', $version);

echo PHP_EOL . ($fail === 0
    ? 'RESULTADO: OK (' . $total . ' comprobaciones)'
    : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
