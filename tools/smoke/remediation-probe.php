<?php
/**
 * Probe CLI del E2E del asistente de remediación.
 *
 *   php tools/smoke/remediation-probe.php seed
 *   php tools/smoke/remediation-probe.php task <task_id>
 *   php tools/smoke/remediation-probe.php cleanup <org_id>
 *
 * Crea una organización manual y una tarea para el E2E. El E2E lo borra al
 * terminar.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$cmd = (string)($argv[1] ?? '');

if ($cmd === 'seed') {
    $name = 'E2E Remediación ' . bin2hex(random_bytes(4));
    $orgId = Database::insert(
        "INSERT INTO remediation_orgs (name, kind, notes, created_by) VALUES (?, 'manual', ?, ?)",
        [$name, 'Organización de prueba E2E', 1]
    );

    $taskId = Database::insert(
        "INSERT INTO remediation_tasks
            (org_id, cve_id, title, severity, cvss, status, machine_count, source, created_by)
         VALUES (?, ?, ?, 'High', 8.1, 'open', 0, 'manual', ?)",
        [$orgId, 'CVE-2026-99002', 'E2E tarea de remediación', 1]
    );

    echo json_encode([
        'org_id'  => $orgId,
        'task_id' => $taskId,
        'name'    => $name,
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'task') {
    $id = (int)($argv[2] ?? 0);
    $task = $id > 0
        ? Database::fetchOne(
            "SELECT id, org_id, cve_id, patch_kb, fixed_version, notes FROM remediation_tasks WHERE id = ?",
            [$id]
        )
        : null;
    echo json_encode([
        'exists'        => $task !== null,
        'patch_kb'      => (string)($task['patch_kb'] ?? ''),
        'fixed_version' => (string)($task['fixed_version'] ?? ''),
        'notes'         => (string)($task['notes'] ?? ''),
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'chat-token') {
    $id = (int)($argv[2] ?? 0);
    $chat = $id > 0
        ? Database::fetchOne("SELECT id, token, status, last_error FROM remediation_chats WHERE id = ?", [$id])
        : null;
    echo json_encode([
        'exists' => $chat !== null,
        'token'  => (string)($chat['token'] ?? ''),
        'status' => (string)($chat['status'] ?? ''),
        'error'  => (string)($chat['last_error'] ?? ''),
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'chat-messages') {
    $id = (int)($argv[2] ?? 0);
    $rows = $id > 0
        ? Database::fetchAll("SELECT role, content, model FROM remediation_messages WHERE chat_id = ? ORDER BY id", [$id])
        : [];
    echo json_encode(['messages' => $rows], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'seed-chat') {
    $orgId = (int)($argv[2] ?? 0);
    $taskId = (int)($argv[3] ?? 0);
    $status = (string)($argv[4] ?? 'pending');
    if ($orgId <= 0 || $taskId <= 0) {
        fwrite(STDERR, "Uso: seed-chat <org_id> <task_id> <pending|running>\n");
        exit(2);
    }
    $chatId = Database::insert(
        "INSERT INTO remediation_chats (org_id, user_id, context_type, context_ref, title, status)
         VALUES (?, 1, 'task', ?, ?, ?)",
        [$orgId, (string)$taskId, 'E2E chat colgado', $status]
    );
    Database::insert(
        "INSERT INTO remediation_messages (chat_id, role, content) VALUES (?, 'user', '¿Cómo aplico el parche?')",
        [$chatId]
    );
    // Envejecer la fila para que la app la considere colgada (> 10 min).
    Database::update(
        "UPDATE remediation_chats SET updated_at = datetime('now', '-20 minutes') WHERE id = ?",
        [$chatId]
    );
    echo json_encode(['chat_id' => $chatId, 'status' => $status], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'cleanup') {
    $orgId = (int)($argv[2] ?? 0);
    if ($orgId > 0) {
        $chats = Database::fetchAll("SELECT id FROM remediation_chats WHERE org_id = ?", [$orgId]);
        foreach ($chats as $chat) {
            Database::query("DELETE FROM remediation_messages WHERE chat_id = ?", [(int)$chat['id']]);
        }
        $tasks = Database::fetchAll("SELECT id FROM remediation_tasks WHERE org_id = ?", [$orgId]);
        foreach ($tasks as $task) {
            $tid = (int)$task['id'];
            Database::query("DELETE FROM remediation_task_logs WHERE task_id = ?", [$tid]);
            Database::query("DELETE FROM remediation_task_assets WHERE task_id = ?", [$tid]);
            Database::query("DELETE FROM remediation_risk_acceptances WHERE task_id = ?", [$tid]);
            Database::query("DELETE FROM remediation_task_checks WHERE task_id = ?", [$tid]);
        }
        Database::query("DELETE FROM remediation_chats WHERE org_id = ?", [$orgId]);
        Database::query("DELETE FROM remediation_tasks WHERE org_id = ?", [$orgId]);
        Database::query("DELETE FROM remediation_orgs WHERE id = ?", [$orgId]);
    }
    echo json_encode(['deleted' => $orgId], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'seed-workflow') {
    $name = 'E2E Workflow ' . bin2hex(random_bytes(4));
    $orgId = Database::insert(
        "INSERT INTO remediation_orgs (name, kind, notes, created_by) VALUES (?, 'manual', ?, 1)",
        [$name, 'Organización de prueba del workflow F0']
    );
    $due = date('Y-m-d', strtotime('+10 days'));
    $taskId = Database::insert(
        "INSERT INTO remediation_tasks
            (org_id, cve_id, title, severity, cvss, status, due_at, source, created_by)
         VALUES (?, 'CVE-2026-98001', 'E2E workflow F0', 'High', 8.8, 'open', ?, 'manual', 1)",
        [$orgId, $due]
    );
    RemediationWorkflow::initTask((int)$taskId, 'open', $due, 1, 'Alta E2E');
    echo json_encode([
        'org_id'  => $orgId,
        'task_id' => $taskId,
        'name'    => $name,
        'due_at'  => $due,
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'workflow') {
    $id = (int)($argv[2] ?? 0);
    $task = $id > 0 ? Database::fetchOne("SELECT * FROM remediation_tasks WHERE id = ?", [$id]) : null;
    $log = $id > 0 ? RemediationWorkflow::logFor($id, 100) : [];
    echo json_encode([
        'exists'       => $task !== null,
        'estado'       => (string)($task['estado'] ?? ''),
        'status'       => (string)($task['status'] ?? ''),
        'evidence'     => (string)($task['evidence'] ?? ''),
        'resolved_at'  => (string)($task['resolved_at'] ?? ''),
        'eta_actual'   => (string)($task['eta_actual'] ?? ''),
        'log_count'    => count($log),
        'last_type'    => (string)($log[0]['tipo'] ?? ''),
        'last_origin'  => (string)($log[0]['estado_origen'] ?? ''),
        'last_target'  => (string)($log[0]['estado_destino'] ?? ''),
    ], JSON_UNESCAPED_UNICODE);
    exit(0);
}

fwrite(STDERR, "Comando no soportado: {$cmd}\n");
exit(2);
