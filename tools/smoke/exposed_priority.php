<?php
/**
 * exposed_priority.php — Prioridad de remediación determinista (v0.4.26.2).
 *
 *   php tools/smoke/exposed_priority.php
 *
 * Sin red y sin base de datos: clasificación de tiers, motivos, ventanas,
 * orden de trabajo y extracción de bloques de la descripción de Defender.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

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

function row(array $overrides = []): array
{
    return array_merge([
        'cve_id' => 'CVE-2026-0001',
        'severity' => 'high',
        'cvss' => 8.8,
        'epss' => 0.05,
        'age_days' => 100,
        'exposed_machines' => 5,
        'has_exploit' => 0,
        'has_known_threats' => 0,
        'has_alerts' => 0,
        'is_kev' => 0,
        'tvm_status' => 'RemediationRequired',
    ], $overrides);
}

/* =====================================================================
 * 1. Tiers
 * ================================================================== */

$p = ExposedPriority::classify(row(['is_kev' => 1]));
check('tier: KEV es P1', $p['tier'] === 'p1' && str_contains($p['reason'], 'KEV'));

$p = ExposedPriority::classify(row(['has_alerts' => 1]));
check('tier: alerta activa es P1', $p['tier'] === 'p1' && str_contains($p['reason'], 'alerta'));

$p = ExposedPriority::classify(row(['has_exploit' => 1, 'exposed_machines' => 60]));
check('tier: exploit + 60 equipos es P1', $p['tier'] === 'p1' && str_contains($p['reason'], '60 equipos'));

$p = ExposedPriority::classify(row(['epss' => 0.62, 'exposed_machines' => 3]));
check('tier: EPSS alto con exposición es P1', $p['tier'] === 'p1' && str_contains($p['reason'], 'EPSS'));

$p = ExposedPriority::classify(row(['has_exploit' => 1, 'exposed_machines' => 4]));
check('tier: exploit con poca exposición es P2', $p['tier'] === 'p2' && $p['reason'] === 'exploit disponible');

$p = ExposedPriority::classify(row(['severity' => 'critical', 'exposed_machines' => 20]));
check('tier: crítica con exposición es P2', $p['tier'] === 'p2' && str_contains($p['reason'], 'crítica'));

$p = ExposedPriority::classify(row(['has_known_threats' => 1, 'exposed_machines' => 0]));
check('tier: amenazas conocidas es P2', $p['tier'] === 'p2');

$p = ExposedPriority::classify(row(['epss' => 0.2, 'exposed_machines' => 2]));
check('tier: EPSS medio es P2', $p['tier'] === 'p2' && str_contains($p['reason'], 'EPSS'));

$p = ExposedPriority::classify(row(['severity' => 'critical', 'exposed_machines' => 3]));
check('tier: crítica sin umbral es P3', $p['tier'] === 'p3' && str_contains($p['reason'], 'crítica'));

$p = ExposedPriority::classify(row(['severity' => 'low', 'exposed_machines' => 0]));
check('tier: sin exposición es P4', $p['tier'] === 'p4');

check('tier: etiquetas y ventanas', ExposedPriority::TIERS['p1']['label'] === 'P1 · Immediate'
    && ExposedPriority::TIERS['p1']['window'] === '24-72 h'
    && ExposedPriority::TIERS['p4']['label'] === 'P4 · Defer');

check('tier: CVSS no manda sobre KEV', ExposedPriority::classify(row(['cvss' => 3.1, 'is_kev' => 1]))['tier'] === 'p1');
check('tier: CVSS 10 sin exposición no es P1',
    ExposedPriority::classify(row(['cvss' => 10.0, 'severity' => 'critical', 'exposed_machines' => 0]))['tier'] === 'p4');

/* =====================================================================
 * 2. Umbrales configurables
 * ================================================================== */

$p = ExposedPriority::classify(row(['has_exploit' => 1, 'exposed_machines' => 12]), ['p1_machines' => 10]);
check('umbral: P1 con 10 equipos si se configura', $p['tier'] === 'p1');

$p = ExposedPriority::classify(row(['epss' => 0.3, 'exposed_machines' => 5]), ['epss_p2' => 0.4]);
check('umbral: EPSS 0.3 ya no es P2 con umbral 0.4', $p['tier'] !== 'p2');

/* =====================================================================
 * 3. Excepciones y orden
 * ================================================================== */

check('excepción: UnderException marcada',
    ExposedPriority::classify(row(['tvm_status' => 'UnderException']))['exception'] === true);
check('excepción: RemediationRequired no es excepción',
    ExposedPriority::classify(row())['exception'] === false);

check('orden: P1 antes que P4',
    ExposedPriority::rank('p1') < ExposedPriority::rank('p2')
    && ExposedPriority::rank('p2') < ExposedPriority::rank('p3')
    && ExposedPriority::rank('p3') < ExposedPriority::rank('p4'));

/* =====================================================================
 * 4. Descripción: bloques y versión
 * ================================================================== */

$desc = ExposedPriority::describe(
    'Summary: RCE por deserialización en OpenWire. Permite ejecutar código. '
    . 'Impact: compromiso total del broker. Remediation: actualizar a 5.18.3 antes de exponerlo. '
    . 'AdditionalInformation: ver CVE-2026-0002. Generated by AI'
);
check('descripción: summary', str_contains($desc['summary'], 'deserialización'));
check('descripción: impacto', str_contains($desc['impact'], 'compromiso total'));
check('descripción: remediación', str_contains($desc['remediation'], 'actualizar a 5.18.3'));
check('descripción: versión inferida', $desc['fix'] === '5.18.3', $desc['fix']);
check('descripción: sin «Generated by AI»', !str_contains($desc['summary'], 'Generated by AI'));

$desc2 = ExposedPriority::describe('Summary: fallo sin bloques. Solo texto.');
check('descripción: sin bloques usa el texto', str_contains($desc2['summary'], 'fallo sin bloques'));
check('descripción: sin versión', $desc2['fix'] === '');

$long = ExposedPriority::describe('Summary: ' . str_repeat('Frase de prueba. ', 10));
check('descripción: recorta a dos frases', substr_count($long['summary'], '.') <= 3);

check('frases: vacío devuelve vacío', ExposedPriority::sentences('', 2) === '');

echo "\n" . ($total - $fail) . "/{$total} pruebas correctas\n";
echo $fail === 0 ? "OK\n" : "FALLOS: {$fail}\n";
exit($fail === 0 ? 0 : 1);
