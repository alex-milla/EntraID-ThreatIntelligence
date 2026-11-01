<?php
/**
 * vm-findings.php — Pruebas de hallazgos por activo (v0.3.9).
 *
 *   php tools/smoke/vm-findings.php
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

// ============================================================
// 1. Estados del flujo ampliado
// ============================================================
check('Estados: incluye Asignada', VmCases::isStatus('assigned'));
check('Estados: incluye Mitigada', VmCases::isStatus('mitigated'));
check('Estados: total 10', count(VmCases::STATUSES) === 10, (string)count(VmCases::STATUSES));
check('Fuentes de hallazgo disponibles', isset(VmCases::FINDING_SOURCES['manual'], VmCases::FINDING_SOURCES['defender-tvm']));

// ============================================================
// 2. Validación de hallazgos
// ============================================================
$base = [
    'asset_or_service' => 'srv-01',
    'environment' => 'Producción',
    'product' => 'Apache HTTP Server',
    'product_version' => '2.4.58',
    'owner_name' => 'Equipo de sistemas',
    'source' => 'manual',
    'status' => 'detected',
    'first_detected_at' => '2026-10-01',
    'last_detected_at' => '2026-10-30',
    'notes' => '',
];
check('Hallazgo: válido', VmCases::validateFinding($base) === null);
check('Hallazgo: sin activo también válido', VmCases::validateFinding(array_merge($base, ['asset_or_service' => ''])) === null);
check('Hallazgo: estado inválido rechazado', VmCases::validateFinding(array_merge($base, ['status' => 'inventado'])) !== null);
check('Hallazgo: fuente inválida rechazada', VmCases::validateFinding(array_merge($base, ['source' => 'magia'])) !== null);
check('Hallazgo: fecha absurda rechazada', VmCases::validateFinding(array_merge($base, ['first_detected_at' => '1900-01-01'])) !== null);
check('Hallazgo: última anterior a primera', VmCases::validateFinding(array_merge($base, ['last_detected_at' => '2026-09-01'])) !== null);
check('Hallazgo: campo demasiado largo', VmCases::validateFinding(array_merge($base, ['asset_or_service' => str_repeat('x', 201)])) !== null);

check('Fechas: 2026 válida', VmCases::isSensibleDate('2026-10-30'));
check('Fechas: 1900 no válida', !VmCases::isSensibleDate('1900-01-01'));
check('Fechas: 9999 no válida', !VmCases::isSensibleDate('9999-12-31'));
check('Fechas: vacío no válido', !VmCases::isSensibleDate(''));

// ============================================================
// 3. Esquema y semilla de hallazgos
// ============================================================
$tables = CveDatabase::fetchAll("SELECT name FROM sqlite_master WHERE type = 'table'");
$names = array_column($tables, 'name');
check('Esquema: vm_findings', in_array('vm_findings', $names, true));
check('Esquema: vm_migrations', in_array('vm_migrations', $names, true));

$migration = CveDatabase::fetchOne(
    "SELECT key FROM vm_migrations WHERE key = 'findings_seed_v1'"
);
check('Migración: semilla de hallazgos marcada', $migration !== null);

$caseCount = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS n FROM vm_cases")['n'] ?? 0);
$casesWithoutFinding = (int)(CveDatabase::fetchOne(
    "SELECT COUNT(*) AS n FROM vm_cases c
     WHERE NOT EXISTS (SELECT 1 FROM vm_findings f WHERE f.case_id = c.id)"
)['n'] ?? 0);
check('Migración: cada caso existente tiene hallazgo', $casesWithoutFinding === 0, "casos={$caseCount} sin_hallazgo={$casesWithoutFinding}");

// ============================================================
// 4. Varios hallazgos por caso (transacción + rollback)
// ============================================================
$db = CveDatabase::getInstance();
$testGroup = -999998;
$testCve = 'CVE-1999-99998';
$twoFindings = false;
$rolledBack = false;
try {
    $db->beginTransaction();
    CveDatabase::query(
        "INSERT INTO vm_cases (group_id, cve_id, status, priority) VALUES (?, ?, 'detected', 'medium')",
        [$testGroup, $testCve]
    );
    $caseId = (int)$db->lastInsertId();
    CveDatabase::query(
        "INSERT INTO vm_findings (case_id, asset_or_service, source, status) VALUES (?, 'srv-A', 'manual', 'detected')",
        [$caseId]
    );
    CveDatabase::query(
        "INSERT INTO vm_findings (case_id, asset_or_service, source, status) VALUES (?, 'srv-B', 'manual', 'mitigated')",
        [$caseId]
    );
    $n = (int)(CveDatabase::fetchOne(
        "SELECT COUNT(*) AS n FROM vm_findings WHERE case_id = ?",
        [$caseId]
    )['n'] ?? 0);
    $twoFindings = $n === 2;
    $db->rollBack();
    $rolledBack = true;
} catch (Throwable $e) {
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    check('Hallazgos: prueba ejecutable', false, $e->getMessage());
}
check('Hallazgos: un CVE con varios activos', $twoFindings);
check('Hallazgos: la prueba no deja datos', $rolledBack && (int)(CveDatabase::fetchOne(
    "SELECT COUNT(*) AS n FROM vm_cases WHERE group_id = ?",
    [$testGroup]
)['n'] ?? 0) === 0);

echo PHP_EOL . ($fail === 0 ? 'RESULTADO: OK (' . $total . ' comprobaciones)' : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
