<?php
/**
 * vm-cases.php — Pruebas del seguimiento de vulnerabilidades (v0.3.0).
 *
 *   php tools/smoke/vm-cases.php
 *
 * Verifica sin red y sin dejar datos en la base:
 *   · reglas puras de VmCases (estados, prioridad, plazos, KPIs)
 *   · que una importación nunca cierra ni duplica casos
 *   · validación de verificación manual y riesgo aceptado
 *   · esquema vm_cases / vm_case_events / vm_case_evidence
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

$today = date('Y-m-d');
$plus = static fn(int $days): string => date('Y-m-d', strtotime(($days >= 0 ? '+' : '') . $days . ' days'));
$minus = static fn(int $days): string => date('Y-m-d', strtotime('-' . $days . ' days'));

// ============================================================
// 1. Estados
// ============================================================
check('Estados: 10 definidos', count(VmCases::STATUSES) === 10, (string)count(VmCases::STATUSES));
check('Estados: detectada', VmCases::statusLabel('detected') === 'Detectada');
check('Estados: corregida y verificada', VmCases::statusLabel('resolved_verified') === 'Corregida y verificada');
check('Estados: riesgo aceptado', VmCases::statusLabel('risk_accepted') === 'Riesgo aceptado temporalmente');
check('Estados: estado inválido rechazado', !VmCases::isStatus('closed'));

// ============================================================
// 2. Ámbito y deduplicación
// ============================================================
check('Ámbito: clave empresa + CVE', VmCases::scopeKey(7, 'cve-2026-1234') === '7|CVE-2026-1234');

$row = [
    'cve_id' => 'CVE-2026-1111',
    'severity' => 'high',
    'cvss' => 8.1,
    'epss' => 0.2,
    'updated_at' => '2026-10-29',
    'has_exploit' => 1,
];
$planNew = VmCases::reconcile('done', null, $row, '2026-10-30');
check('Reconcile: primera vez crea', $planNew['action'] === 'create', json_encode($planNew));

$existingOpen = ['id' => 1, 'status' => 'in_progress'];
$planAgain = VmCases::reconcile('done', $existingOpen, $row, '2026-10-30');
check('Reconcile: segunda importación no crea', $planAgain['action'] === 'observe', json_encode($planAgain));
check('Reconcile: observación normal', $planAgain['event'] === 'observed');
check('Reconcile: fecha de observación del CSV', $planAgain['observed_at'] === '2026-10-29', $planAgain['observed_at']);

$existingClosed = ['id' => 2, 'status' => 'resolved_verified'];
$planClosed = VmCases::reconcile('done', $existingClosed, $row, '2026-10-30');
check('Reconcile: caso cerrado no se reabre solo', $planClosed['action'] === 'observe' && $planClosed['event'] === 'reobserved', json_encode($planClosed));

$planPartial = VmCases::reconcile('processing', $existingOpen, $row, '2026-10-30');
check('Reconcile: importación parcial no toca nada', $planPartial['action'] === 'skip', json_encode($planPartial));

$neverCloses = true;
foreach (array_keys(VmCases::STATUSES) as $status) {
    $plan = VmCases::reconcile('done', ['id' => 9, 'status' => $status], $row, '2026-10-30');
    if ($plan['action'] === 'close') {
        $neverCloses = false;
    }
}
check('Reconcile: nunca devuelve cierre automático', $neverCloses);

// ============================================================
// 3. Prioridad
// ============================================================
$critical = VmCases::priorityFactors([
    'severity' => 'critical', 'cvss' => 9.8, 'epss' => 0.97, 'kev' => true,
    'has_exploit' => 1, 'exposed_machines' => 4800,
]);
check('Prioridad: CVSS 9.8 + KEV + exploit → crítica', $critical['priority'] === 'critical', $critical['priority']);
check('Prioridad: motivos incluyen KEV', in_array('En CISA KEV', $critical['reasons'], true));
check('Prioridad: motivos incluyen EPSS', (bool)array_filter($critical['reasons'], static fn($r) => str_starts_with($r, 'EPSS:')));
check('Prioridad: motivos incluyen equipos del CSV', (bool)array_filter($critical['reasons'], static fn($r) => str_contains($r, 'equipos expuestos')));

$noCvss = VmCases::priorityFactors(['severity' => 'high']);
check('Prioridad: sin CVSS usa la severidad importada', $noCvss['priority'] === 'high', $noCvss['priority']);
check('Prioridad: sin datos no inventa CVSS', $noCvss['cvss'] === null && $noCvss['epss'] === null);
check('Prioridad: sin datos no inventa EPSS ni exploits', $noCvss['epss'] === null && $noCvss['exploit'] === false);

$low = VmCases::priorityFactors(['severity' => 'low', 'cvss' => 3.1]);
check('Prioridad: CVSS 3.1 → baja', $low['priority'] === 'low', $low['priority']);

$catalogCritical = VmCases::factorsFromCatalog([
    'severity' => 'Critical',
    'cvss_v3_score' => 9.8,
    'kev_id' => 'CVE-2026-1111',
    'exploit_total' => 2,
]);
check('Catálogo: severidad con mayúscula → crítica', $catalogCritical['priority'] === 'critical', $catalogCritical['priority']);
check('Catálogo: exploit del índice cuenta', in_array('Exploit público conocido', $catalogCritical['reasons'], true));
check('Catálogo: sin exposición inventada', (int)$catalogCritical['exposed_machines'] === 0);
check('Catálogo: sin alertas inventadas', $catalogCritical['alerts'] === false && $catalogCritical['threats'] === false);

$catalogHigh = VmCases::factorsFromCatalog(['severity' => 'High']);
check('Catálogo: sin CVSS usa la severidad', $catalogHigh['priority'] === 'high', $catalogHigh['priority']);
check('Catálogo: no inventa CVSS ni EPSS', $catalogHigh['cvss'] === null && $catalogHigh['epss'] === null);

// ============================================================
// 4. Plazos
// ============================================================
check('SLA: crítica por defecto 14 días', VmCases::slaDays('critical') === 14, (string)VmCases::slaDays('critical'));
check('SLA: baja por defecto 90 días', VmCases::slaDays('low') === 90, (string)VmCases::slaDays('low'));
check('Plazo: fecha calculada desde prioridad', VmCases::dueDate('critical', '2026-10-01') === '2026-10-15', VmCases::dueDate('critical', '2026-10-01'));
check('Plazo: días restantes', VmCases::daysUntil($plus(3), $today) === 3, (string)VmCases::daysUntil($plus(3), $today));
check('Plazo: vencido', VmCases::deadlineState($minus(2), 'in_progress', null, $today) === 'expired');
check('Plazo: próximo', VmCases::deadlineState($plus(3), 'in_progress', null, $today) === 'due_soon');
check('Plazo: en plazo', VmCases::deadlineState($plus(30), 'in_progress', null, $today) === 'ok');
check('Plazo: cerrado', VmCases::deadlineState($minus(30), 'resolved_verified', null, $today) === 'closed');
check('Plazo: excepción caducada', VmCases::deadlineState($minus(10), 'risk_accepted', $minus(1), $today) === 'exception_expired');
check('Plazo: excepción vigente', VmCases::deadlineState($minus(10), 'risk_accepted', $plus(10), $today) === 'ok');
check('Plazo: sin fecha', VmCases::deadlineState('', 'detected', null, $today) === 'none');

// ============================================================
// 5. Validación de cambios
// ============================================================
$current = ['id' => 1, 'status' => 'in_progress', 'priority' => 'high', 'due_date' => $plus(10)];

check(
    'Cierre: exige verificación manual',
    VmCases::validateUpdate($current, ['status' => 'resolved_verified'], false) !== null
);
check(
    'Cierre: acepta verificación registrada',
    VmCases::validateUpdate($current, ['status' => 'resolved_verified'], true) === null
);
check(
    'Riesgo: exige motivo',
    VmCases::validateUpdate($current, ['status' => 'risk_accepted', 'accepted_until' => $plus(10)], true) !== null
);
check(
    'Riesgo: exige caducidad',
    VmCases::validateUpdate($current, ['status' => 'risk_accepted', 'accepted_reason' => 'Cambio planificado'], true) !== null
);
check(
    'Riesgo: caducidad pasada rechazada',
    VmCases::validateUpdate($current, ['status' => 'risk_accepted', 'accepted_reason' => 'x', 'accepted_until' => $minus(1)], true) !== null
);
check(
    'Riesgo: motivo + caducidad válidos',
    VmCases::validateUpdate($current, ['status' => 'risk_accepted', 'accepted_reason' => 'Cambio planificado', 'accepted_until' => $plus(10)], true) === null
);
check(
    'Estado: inválido rechazado',
    VmCases::validateUpdate($current, ['status' => 'inventado'], true) !== null
);
check(
    'Fecha: inválida rechazada',
    VmCases::validateUpdate($current, ['status' => 'in_progress', 'due_date' => '31/02/2026'], true) !== null
);

// ============================================================
// 6. KPIs sobre el conjunto importado
// ============================================================
$kpiCases = [
    ['status' => 'detected', 'priority' => 'high', 'due_date' => $minus(2)],
    ['status' => 'in_progress', 'priority' => 'critical', 'due_date' => $plus(3)],
    ['status' => 'planned', 'priority' => 'medium', 'due_date' => ''],
    ['status' => 'risk_accepted', 'priority' => 'low', 'due_date' => $minus(20), 'accepted_until' => $minus(1)],
    ['status' => 'resolved_verified', 'priority' => 'high', 'due_date' => $minus(40)],
    ['status' => 'false_positive', 'priority' => 'low', 'due_date' => $minus(5)],
];
$kpi = VmCases::kpis($kpiCases, $today);
check('KPI: total', $kpi['total'] === 6, (string)$kpi['total']);
check('KPI: abiertos (excluye verificados y falsos positivos)', $kpi['open'] === 4, (string)$kpi['open']);
check('KPI: vencidos', $kpi['overdue'] === 2, (string)$kpi['overdue']);
check('KPI: próximos', $kpi['due_soon'] === 1, (string)$kpi['due_soon']);
check('KPI: verificados', $kpi['resolved_verified'] === 1, (string)$kpi['resolved_verified']);
check('KPI: excepciones caducadas', $kpi['exception_expired'] === 1, (string)$kpi['exception_expired']);
check('KPI: desglose por prioridad', (int)$kpi['by_priority']['critical'] === 1);

// ============================================================
// 7. Esquema y UNIQUE (sin dejar datos: transacción + rollback)
// ============================================================
$tables = CveDatabase::fetchAll("SELECT name FROM sqlite_master WHERE type = 'table'");
$names = array_column($tables, 'name');
check('Esquema: vm_cases', in_array('vm_cases', $names, true));
check('Esquema: vm_case_events', in_array('vm_case_events', $names, true));
check('Esquema: vm_case_evidence', in_array('vm_case_evidence', $names, true));

$indexes = CveDatabase::fetchAll("PRAGMA index_list(vm_cases)");
$uniqueIndex = false;
foreach ($indexes as $index) {
    if ((int)($index['unique'] ?? 0) === 1) {
        $uniqueIndex = true;
        break;
    }
}
check('Esquema: UNIQUE de ámbito en vm_cases', $uniqueIndex);

$testGroup = -999999;
$testCve = 'CVE-1999-99999';
$db = CveDatabase::getInstance();
$duplicateBlocked = false;
try {
    $db->beginTransaction();
    CveDatabase::query(
        "INSERT INTO vm_cases (group_id, cve_id, status, priority, due_date)
         VALUES (?, ?, 'detected', 'high', ?)",
        [$testGroup, $testCve, $plus(30)]
    );
    try {
        CveDatabase::query(
            "INSERT INTO vm_cases (group_id, cve_id, status, priority, due_date)
             VALUES (?, ?, 'detected', 'high', ?)",
            [$testGroup, $testCve, $plus(30)]
        );
    } catch (PDOException $e) {
        $duplicateBlocked = true;
    }
    $db->rollBack();
} catch (Throwable $e) {
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    check('Esquema: prueba de duplicado ejecutable', false, $e->getMessage());
}
check('Esquema: mismo ámbito no se duplica', $duplicateBlocked);

$leftover = CveDatabase::fetchOne(
    "SELECT COUNT(*) AS n FROM vm_cases WHERE group_id = ?",
    [$testGroup]
);
check('Esquema: la prueba no deja datos', (int)($leftover['n'] ?? 0) === 0);

echo PHP_EOL . ($fail === 0 ? 'RESULTADO: OK (' . $total . ' comprobaciones)' : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
