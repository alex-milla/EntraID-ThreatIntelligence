<?php
/**
 * modern_web.php — Guardias de las fases 1 y 2 (Modern Web Guidance).
 *
 *   php tools/smoke/modern_web.php
 *
 * Comprueba por código fuente los invariantes de la modernización:
 *   - modales con <dialog> nativo + fallback, sin cambiar la API App.*
 *   - CSP Report-Only con nonce por petición (nunca modo enforcement)
 *   - prefers-reduced-motion en CSS y en el scroll del JS
 *   - Fase 2: Popover API + Anchor Positioning con fallback, container queries,
 *     prefetch al hover y medición de LCP/INP
 *   - Fase 3: WebAuthn opcional (off por defecto), defer y hallazgos del
 *     legacy-scan corregidos
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
$perfJs  = $read('public_html/assets/js/perf.js');
$appCss  = $read('public_html/assets/css/app.css');
$uiCss   = $read('public_html/assets/css/ui.css');
$boot    = $read('public_html/config/bootstrap.php');
$footer  = $read('public_html/views/layout/footer.php');
$groups  = $read('public_html/modules/exposed_report/views/_groups.php');
$aiRep   = $read('public_html/modules/cve/views/ai_report.php');
$webAuthn = $read('public_html/includes/webauthn.php');
$webJs   = $read('public_html/assets/js/webauthn.js');
$admin   = $read('public_html/admin/index.php');
$login   = $read('public_html/views/admin/login.php');
$envEx   = $read('public_html/.env.example');
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

// --- Fase 2: Popover + Anchor Positioning ---------------------------------
check('Popover: detecta showPopover/hidePopover',
    str_contains($uiJs, 'HTMLElement.prototype.showPopover')
    && str_contains($uiJs, 'HTMLElement.prototype.hidePopover'));
check('Popover: abre con showPopover()', str_contains($uiJs, 'menu.showPopover()'));
check('Popover: cierra con hidePopover()', str_contains($uiJs, 'openMenu.hidePopover()'));
check('Popover: sincroniza el light-dismiss', str_contains($uiJs, "'toggle', menuToggleHandler"));
check('Popover: fallback fixed conservado', str_contains($uiJs, 'function positionFallback'));
check('Popover: fallback también sin anchor', str_contains($uiJs, 'if (!openPopover || !supportsAnchor)'));
check('Anchor: position-anchor y anchor(bottom)',
    str_contains($uiJs, "CSS.supports('anchor-name'")
    && str_contains($uiJs, "'position-anchor', name")
    && str_contains($uiJs, "'anchor(bottom)'"));
check('CSS: @supports selector(:popover-open)', str_contains($uiCss, '@supports selector(:popover-open)'));
check('CSS: inset auto en el dropdown', str_contains($uiCss, 'inset: auto;'));

// --- Fase 2: container queries --------------------------------------------
check('CSS: container-type en las KPI', str_contains($uiCss, 'container-type: inline-size'));
check('CSS: @container eiti-stat', str_contains($uiCss, '@container eiti-stat (max-width: 190px)'));

// --- Fase 2: prefetch ------------------------------------------------------
check('Prefetch: enlaces data-prefetch', str_contains($uiJs, "a[data-prefetch]"));
check('Prefetch: link rel=prefetch as=document',
    str_contains($uiJs, "link.rel = 'prefetch'") && str_contains($uiJs, "link.as = 'document'"));
check('Prefetch: respeta save-data', str_contains($uiJs, 'navigator.connection.saveData'));
check('Prefetch: tope de 8 URLs', str_contains($uiJs, 'PREFETCH_MAX = 8'));
check('Prefetch: solo mismo origen', str_contains($uiJs, 'u.origin !== window.location.origin'));
check('Prefetch: hover y foco',
    str_contains($uiJs, "'pointerover'") && str_contains($uiJs, "'focusin'"));
check('Prefetch: marcado en grupos', substr_count($groups, 'data-prefetch') >= 2);
check('Prefetch: marcado en informe CVE', str_contains($aiRep, 'data-prefetch'));

// --- Fase 2: métricas ------------------------------------------------------
check('Métricas: perf.js cargado en el layout', str_contains($footer, 'js/perf.js'));
check('Métricas: LCP con PerformanceObserver',
    str_contains($perfJs, "'largest-contentful-paint'") && str_contains($perfJs, 'new PerformanceObserver'));
check('Métricas: INP por eventos con interactionId',
    str_contains($perfJs, "type: 'event'") && str_contains($perfJs, 'entry.interactionId'));
check('Métricas: API pública EitiVitals', str_contains($perfJs, 'window.EitiVitals = copy()'));
check('Métricas: beacon solo si hay endpoint', str_contains($perfJs, 'data-vitals-endpoint'));

// --- Fase 3: WebAuthn -----------------------------------------------------
check('WebAuthn: flag por defecto desactivado',
    str_contains($envEx, 'WEBAUTHN_ENABLED=0') && str_contains($webAuthn, "getenv('WEBAUTHN_ENABLED') === '1'"));
check('WebAuthn: challenge en sesión con TTL', str_contains($webAuthn, "CHALLENGE_TTL = 120"));
check('WebAuthn: CBOR/COSE y verificación ES256',
    str_contains($webAuthn, 'cborDecode') && str_contains($webAuthn, 'pemFromCose')
    && str_contains($webAuthn, 'derSignature') && str_contains($webAuthn, "OPENSSL_ALGO_SHA256"));
check('WebAuthn: loginById en Auth', str_contains($read('public_html/includes/auth.php'), 'function loginById'));
check('WebAuthn: tabla de credenciales', str_contains($read('public_html/config/database.php'), 'webauthn_credentials'));
check('WebAuthn: rutas de admin',
    str_contains($admin, "webauthn/register-options") && str_contains($admin, "webauthn/auth-verify"));
check('WebAuthn: botón en login', str_contains($login, 'id="webauthn-login"'));
check('WebAuthn: cliente JS', str_contains($webJs, 'window.EitiWebAuthn')
    && str_contains($webJs, 'isSecureContext'));
check('WebAuthn: carga condicional en el layout',
    str_contains($footer, 'js/webauthn.js') && str_contains($footer, 'WebAuthn::enabled()'));

// --- Fase 3: scripts y legacy-scan ----------------------------------------
check('Scripts: perf.js con defer', str_contains($footer, 'defer src="<?= asset_url(\'js/perf.js\')'));
check('Legacy: meta color-scheme en layout/login/404',
    str_contains($read('public_html/views/layout/header.php'), '<meta name="color-scheme"')
    && str_contains($login, '<meta name="color-scheme"')
    && str_contains($read('public_html/views/errors/404.php'), '<meta name="color-scheme"'));
check('Legacy: autocomplete en formularios de contraseña',
    str_contains($read('public_html/views/admin/change_password.php'), 'autocomplete="current-password"')
    && substr_count($read('public_html/admin-recovery.php'), 'autocomplete="new-password"') === 2);
check('Legacy: scrollbar estándar', str_contains($appCss, 'scrollbar-color:')
    && str_contains($appCss, 'scrollbar-width:'));
check('Legacy: Enter respeta IME',
    str_contains($read('public_html/assets/js/ioc-extractor.js'), 'ev.keyCode !== 229')
    && str_contains($read('public_html/modules/remediation/views/assistant.php'), 'e.keyCode !== 229'));

// --- Versión -------------------------------------------------------------
check('VERSION = 0.4.28.18', $version === '0.4.28.18', $version);

echo PHP_EOL . ($fail === 0
    ? 'RESULTADO: OK (' . $total . ' comprobaciones)'
    : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
