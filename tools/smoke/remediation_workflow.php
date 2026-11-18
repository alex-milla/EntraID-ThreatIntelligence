<?php
/**
 * Smoke — workflow de Remediación (CVE Desk, F0).
 *
 *   php tools/smoke/remediation_workflow.php
 *
 * Comprueba el esquema aditivo, la máquina de estados, el registro inmutable,
 * la ETA con retrasos/bloqueos y las aceptaciones de riesgo. Limpia lo que crea.
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

$orgId = 0;
$taskIds = [];

try {
    /* -----------------------------------------------------------------
     * 1. Esquema
     * -------------------------------------------------------------- */
    $tables = array_column(
        Database::fetchAll("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'remediation_%'"),
        'name'
    );
    foreach ([
        'remediation_task_logs',
        'remediation_task_assets',
        'remediation_risk_acceptances',
        'remediation_reports',
        'remediation_report_items',
        'remediation_roles',
    ] as $table) {
        check('esquema: tabla ' . $table, in_array($table, $tables, true));
    }

    $taskCols = array_column(Database::fetchAll("PRAGMA table_info(remediation_tasks)"), 'name');
    foreach ([
        'estado', 'eta_original', 'eta_actual', 'ventana_parcheo',
        'responsable_user_id', 'importado', 'bloqueado_desde', 'cierre_actor_id',
    ] as $column) {
        check('esquema: columna ' . $column, in_array($column, $taskCols, true));
    }

    /* -----------------------------------------------------------------
     * 2. Mapa de estados heredados
     * -------------------------------------------------------------- */
    $map = [
        'open' => 'ticket_creado',
        'in_progress' => 'en_curso',
        'patched' => 'cerrado',
        'mitigated' => 'cerrado',
        'accepted' => 'riesgo_aceptado',
        'false_positive' => 'cerrado',
    ];
    foreach ($map as $status => $expected) {
        check('mapa: ' . $status . ' → ' . $expected, RemediationWorkflow::stateForStatus($status) === $expected);
    }
    check('mapa inverso: cerrado → patched', RemediationWorkflow::statusForState('cerrado') === 'patched');
    check('mapa inverso: cerrado → mitigated', RemediationWorkflow::statusForState('cerrado', 'mitigated') === 'mitigated');
    check('mapa inverso: riesgo → accepted', RemediationWorkflow::statusForState('riesgo_aceptado') === 'accepted');

    /* -----------------------------------------------------------------
     * 3. Alta y registro inicial
     * -------------------------------------------------------------- */
    $orgId = Database::insert(
        "INSERT INTO remediation_orgs (name, kind, notes, created_by) VALUES (?, 'manual', ?, 1)",
        ['Smoke workflow ' . bin2hex(random_bytes(4)), 'Smoke de F0']
    );
    $due = date('Y-m-d', strtotime('+10 days'));
    $taskId = Database::insert(
        "INSERT INTO remediation_tasks
         (org_id, cve_id, title, severity, cvss, status, due_at, created_at, source, created_by)
         VALUES (?, 'CVE-2026-97001', 'Smoke workflow', 'High', 8.8, 'open', ?, datetime('now', '-2 days'), 'manual', 1)",
        [$orgId, $due]
    );
    $taskIds[] = $taskId;
    RemediationWorkflow::initTask($taskId, 'open', $due, 1, 'Alta de prueba');

    $task = Database::fetchOne("SELECT * FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('alta: estado ticket_creado', (string)($task['estado'] ?? '') === 'ticket_creado');
    check('alta: importado relleno', (string)($task['importado'] ?? '') !== '');
    check('alta: ETA inicial', (string)($task['eta_original'] ?? '') === $due
        && (string)($task['eta_actual'] ?? '') === $due);
    $log = RemediationWorkflow::logFor($taskId);
    check('alta: entrada de registro', count($log) === 1 && (string)$log[0]['tipo'] === 'cambio_estado');

    /* -----------------------------------------------------------------
     * 4. Cambio de estado heredado (formulario actual)
     * -------------------------------------------------------------- */
    $res = RemediationWorkflow::recordLegacyChange($taskId, 'open', 'in_progress', ['nota' => 'Empieza el parcheo'], 1);
    check('cambio heredado: ok', !empty($res['ok']) && $res['state'] === 'en_curso');
    $task = Database::fetchOne("SELECT * FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('cambio heredado: status sincronizado', (string)$task['status'] === 'in_progress');
    $log = RemediationWorkflow::logFor($taskId);
    check('cambio heredado: origen y destino en el registro',
        (string)$log[0]['estado_origen'] === 'ticket_creado' && (string)$log[0]['estado_destino'] === 'en_curso');

    $closed = RemediationWorkflow::recordLegacyChange($taskId, 'in_progress', 'patched', ['evidencia' => 'KB5040442'], 1);
    check('cierre heredado: ok', !empty($closed['ok']) && $closed['state'] === 'cerrado');
    $task = Database::fetchOne("SELECT * FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('cierre heredado: resolved_at', (string)($task['resolved_at'] ?? '') !== '');
    check('cierre heredado: status patched', (string)$task['status'] === 'patched');

    RemediationWorkflow::recordLegacyChange($taskId, 'patched', 'open', ['nota' => 'Reaparece'], 1);
    $task = Database::fetchOne("SELECT * FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('reapertura: estado ticket_creado', (string)$task['estado'] === 'ticket_creado');
    check('reapertura: resolved_at limpio', (string)($task['resolved_at'] ?? '') === '');
    $log = RemediationWorkflow::logFor($taskId);
    check('reapertura: tipo reapertura', (string)$log[0]['tipo'] === 'reapertura');

    /* -----------------------------------------------------------------
     * 5. Entradas: retraso y bloqueo (ETA acumulada)
     * -------------------------------------------------------------- */
    $before = date('Y-m-d', strtotime($due . ' +0 days'));
    $delay = RemediationWorkflow::addEntry($taskId, 'retraso', 'Ventana denegada por cambio en FW', 2, 1);
    check('retraso: ok', !empty($delay['ok']));
    $task = Database::fetchOne("SELECT eta_actual, due_at FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('retraso: ETA +2', (string)$task['eta_actual'] === date('Y-m-d', strtotime($before . ' +2 days'))
        && (string)$task['due_at'] === (string)$task['eta_actual']);

    $noDays = RemediationWorkflow::addEntry($taskId, 'retraso', 'Sin días', 0, 1);
    check('retraso: exige días', empty($noDays['ok']));

    $block = RemediationWorkflow::addEntry($taskId, 'bloqueo', 'Vendor sin parche; mitigado por WAF', 3, 1);
    check('bloqueo: ok', !empty($block['ok']) && $block['state'] === 'bloqueado');
    $task = Database::fetchOne("SELECT * FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('bloqueo: estado y fecha', (string)$task['estado'] === 'bloqueado' && (string)($task['bloqueado_desde'] ?? '') !== '');
    check('bloqueo: ETA +3', (string)$task['eta_actual'] === date('Y-m-d', strtotime($before . ' +5 days')));

    $react = RemediationWorkflow::transition($taskId, 'reactivar', [], 1);
    check('reactivar: ok', !empty($react['ok']) && $react['state'] === 'en_curso');
    $task = Database::fetchOne("SELECT estado, bloqueado_desde FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('reactivar: limpia bloqueo', (string)$task['estado'] === 'en_curso' && (string)($task['bloqueado_desde'] ?? '') === '');

    /* -----------------------------------------------------------------
     * 6. Máquina de estados estricta
     * -------------------------------------------------------------- */
    $invalid = RemediationWorkflow::transition($taskId, 'iniciar', [], 1);
    check('transición ilegal: rechazada', empty($invalid['ok']));

    check('transición a verificación', !empty(RemediationWorkflow::transition($taskId, 'pasar_verificacion', [], 1)['ok']));
    $failVerify = RemediationWorkflow::transition($taskId, 'verificacion_fallida', ['motivo' => 'Sigue vulnerable'], 1);
    check('verificación fallida: vuelve a en_curso', !empty($failVerify['ok']) && $failVerify['state'] === 'en_curso');
    check('verificación fallida: exige motivo',
        empty(RemediationWorkflow::transition($taskId, 'verificacion_fallida', [], 1)['ok']));

    $closed = RemediationWorkflow::transition($taskId, 'cerrar', ['evidencia' => 'KB5040442 aplicada', 'resolucion' => 'patched'], 1);
    check('cerrar estricto: ok', !empty($closed['ok']) && $closed['state'] === 'cerrado');
    $task = Database::fetchOne("SELECT * FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('cerrar estricto: evidencia guardada', (string)$task['evidence'] === 'KB5040442 aplicada');
    check('cerrar estricto: status patched', (string)$task['status'] === 'patched');
    check('cerrar sin evidencia: API lo exige', (function () use ($taskId): bool {
        RemediationWorkflow::transition($taskId, 'reabrir', [], 1);
        RemediationWorkflow::transition($taskId, 'planificar', ['ventana_parcheo' => 'dom 22:00'], 1);
        RemediationWorkflow::transition($taskId, 'iniciar', [], 1);
        $res = RemediationWorkflow::transition($taskId, 'cerrar', [], 1);
        return empty($res['ok']);
    })());
    // Se cierra con evidencia para poder probar la reapertura estricta.
    RemediationWorkflow::transition($taskId, 'cerrar', ['evidencia' => 'KB5040443'], 1);

    /* -----------------------------------------------------------------
     * 7. Planificar e iniciar (API)
     * -------------------------------------------------------------- */
    check('reabrir', !empty(RemediationWorkflow::transition($taskId, 'reabrir', [], 1)['ok']));
    check('planificar', !empty(RemediationWorkflow::transition($taskId, 'planificar', ['ventana_parcheo' => 'dom 22:00'], 1)['ok']));
    $task = Database::fetchOne("SELECT estado, ventana_parcheo FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('planificar: ventana guardada', (string)$task['estado'] === 'planificado'
        && (string)$task['ventana_parcheo'] === 'dom 22:00');
    check('iniciar', !empty(RemediationWorkflow::transition($taskId, 'iniciar', [], 1)['ok']));

    /* -----------------------------------------------------------------
     * 8. Aceptación de riesgo
     * -------------------------------------------------------------- */
    $tooLong = RemediationWorkflow::acceptRisk($taskId, 'Sin parche del vendor', date('Y-m-d', strtotime('+120 days')), 1);
    check('riesgo: caducidad > 90 días rechazada', empty($tooLong['ok']));
    $noJust = RemediationWorkflow::acceptRisk($taskId, '', date('Y-m-d', strtotime('+30 days')), 1);
    check('riesgo: justificación obligatoria', empty($noJust['ok']));

    Database::update("UPDATE remediation_tasks SET cvss = 9.5 WHERE id = ?", [$taskId]);
    $needsSecond = RemediationWorkflow::acceptRisk($taskId, 'Compensado con WAF', date('Y-m-d', strtotime('+30 days')), 1);
    check('riesgo: CVSS ≥ 9 exige segundo aprobador', empty($needsSecond['ok']));

    $accepted = RemediationWorkflow::acceptRisk(
        $taskId,
        'Compensado con WAF y sin exposición directa',
        date('Y-m-d', strtotime('+30 days')),
        1,
        2
    );
    check('riesgo: aceptado', !empty($accepted['ok']) && $accepted['state'] === 'riesgo_aceptado');
    $acceptance = Database::fetchOne(
        "SELECT * FROM remediation_risk_acceptances WHERE task_id = ? AND estado = 'vigente' ORDER BY id DESC LIMIT 1",
        [$taskId]
    );
    check('riesgo: aceptación guardada', $acceptance !== null && (int)($acceptance['segundo_aprobador'] ?? 0) === 2);
    $task = Database::fetchOne("SELECT status, exception_until FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('riesgo: status accepted', (string)$task['status'] === 'accepted' && (string)$task['exception_until'] !== '');

    // Caducidad: una aceptación vencida devuelve la tarea a la cola.
    Database::update(
        "UPDATE remediation_risk_acceptances SET caducidad = date('now', '-1 day') WHERE task_id = ? AND estado = 'vigente'",
        [$taskId]
    );
    $expired = RemediationWorkflow::expireRisks();
    check('riesgo: caducidad procesada', $expired >= 1);
    $task = Database::fetchOne("SELECT estado, status, exception_until FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('riesgo: vuelve a la cola', (string)$task['estado'] === 'ticket_creado'
        && (string)$task['status'] === 'open' && (string)($task['exception_until'] ?? '') === '');

    /* -----------------------------------------------------------------
     * 9. Aceptación desde el formulario heredado
     * -------------------------------------------------------------- */
    $legacyTask = Database::insert(
        "INSERT INTO remediation_tasks
         (org_id, cve_id, title, severity, cvss, status, due_at, source, created_by)
         VALUES (?, 'CVE-2026-97002', 'Legacy risk', 'Medium', 5.5, 'open', ?, 'manual', 1)",
        [$orgId, date('Y-m-d', strtotime('+20 days'))]
    );
    $taskIds[] = $legacyTask;
    RemediationWorkflow::initTask($legacyTask, 'open', date('Y-m-d', strtotime('+20 days')), 1, 'Alta legacy');
    $legacy = RemediationWorkflow::recordLegacyChange(
        $legacyTask,
        'open',
        'accepted',
        ['nota' => 'Aceptado por negocio', 'exception_until' => date('Y-m-d', strtotime('+15 days'))],
        1
    );
    check('riesgo heredado: ok', !empty($legacy['ok']));
    $task = Database::fetchOne("SELECT estado, status FROM remediation_tasks WHERE id = ?", [$legacyTask]);
    check('riesgo heredado: estado y status', (string)$task['estado'] === 'riesgo_aceptado'
        && (string)$task['status'] === 'accepted');
    $legacyAcceptance = Database::fetchOne(
        "SELECT * FROM remediation_risk_acceptances WHERE task_id = ? ORDER BY id DESC LIMIT 1",
        [$legacyTask]
    );
    check('riesgo heredado: aceptación creada', $legacyAcceptance !== null);

    /* -----------------------------------------------------------------
     * 10. Inmutabilidad del registro
     * -------------------------------------------------------------- */
    $source = (string)file_get_contents(dirname(__DIR__, 2) . '/public_html/includes/remediation_workflow.php');
    check('registro: sin UPDATE', !str_contains($source, 'UPDATE remediation_task_logs'));
    check('registro: sin DELETE', !str_contains($source, 'DELETE FROM remediation_task_logs'));
    check('registro: sin API de borrado', !method_exists(RemediationWorkflow::class, 'deleteLog')
        && !method_exists(RemediationWorkflow::class, 'updateLog'));

    $countBefore = (int)(Database::fetchOne(
        "SELECT COUNT(*) AS c FROM remediation_task_logs WHERE task_id = ?",
        [$taskId]
    )['c'] ?? 0);
    RemediationWorkflow::recordLegacyChange($taskId, 'open', 'in_progress', ['nota' => 'Intento'], 1);
    $countAfter = (int)(Database::fetchOne(
        "SELECT COUNT(*) AS c FROM remediation_task_logs WHERE task_id = ?",
        [$taskId]
    )['c'] ?? 0);
    check('registro: solo crece', $countAfter > $countBefore);
} finally {
    foreach ($taskIds as $id) {
        Database::query("DELETE FROM remediation_task_logs WHERE task_id = ?", [$id]);
        Database::query("DELETE FROM remediation_task_assets WHERE task_id = ?", [$id]);
        Database::query("DELETE FROM remediation_risk_acceptances WHERE task_id = ?", [$id]);
        Database::query("DELETE FROM remediation_task_checks WHERE task_id = ?", [$id]);
        Database::query("DELETE FROM remediation_tasks WHERE id = ?", [$id]);
    }
    if ($orgId > 0) {
        Database::query("DELETE FROM remediation_orgs WHERE id = ?", [$orgId]);
    }
}

echo "\n{$total} comprobaciones · " . ($fail === 0 ? 'TODO OK' : $fail . ' FALLOS') . "\n";
exit($fail === 0 ? 0 : 1);
