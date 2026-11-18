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
        $orgRow = Database::fetchOne("SELECT tenant_id FROM remediation_orgs WHERE id = ?", [$orgId]);
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
        Database::query("DELETE FROM remediation_queue_marks WHERE org_id = ?", [$orgId]);
        Database::query("DELETE FROM remediation_queue_seen WHERE org_id = ?", [$orgId]);
        Database::query("DELETE FROM remediation_chats WHERE org_id = ?", [$orgId]);
        Database::query("DELETE FROM remediation_tasks WHERE org_id = ?", [$orgId]);
        Database::query("DELETE FROM remediation_orgs WHERE id = ?", [$orgId]);
        if ($orgRow !== null && (int)($orgRow['tenant_id'] ?? 0) > 0) {
            $tenantId = (int)$orgRow['tenant_id'];
            Database::query("DELETE FROM vulnerabilities WHERE tenant_id = ?", [$tenantId]);
            Database::query("DELETE FROM machines WHERE tenant_id = ?", [$tenantId]);
            Database::query("DELETE FROM tenants WHERE id = ?", [$tenantId]);
        }
    }
    echo json_encode(['deleted' => $orgId], JSON_UNESCAPED_UNICODE);
    exit(0);
}

if ($cmd === 'seed-queue') {
    $suffix = bin2hex(random_bytes(4));
    $tenantId = Database::insert(
        "INSERT INTO tenants (name, slug, tenant_id, client_id, client_secret_encrypted, client_secret_iv, permissions)
         VALUES (?, ?, ?, 'client-e2e', 'enc', 'iv', '[]')",
        ['E2E F1 ' . $suffix, 'e2e-f1-' . $suffix, 'tenant-e2e-' . $suffix]
    );
    $machineA = Database::insert(
        "INSERT INTO machines (tenant_id, machine_id, computer_dns_name, os_platform, os_version, exposure_level)
         VALUES (?, ?, 'WEB-01', 'Windows', '11', 'High')",
        [$tenantId, 'e2e-a-' . $suffix]
    );
    $machineB = Database::insert(
        "INSERT INTO machines (tenant_id, machine_id, computer_dns_name, os_platform, os_version, exposure_level)
         VALUES (?, ?, 'APP-02', 'Windows', 'Server 2022', 'Medium')",
        [$tenantId, 'e2e-b-' . $suffix]
    );
    Database::query(
        "INSERT INTO vulnerabilities
         (tenant_id, machine_id, cve_id, product_name, severity, cvss_v3, epss, published_on)
         VALUES (?, ?, 'CVE-2026-98201', 'Contoso Server', 'Critical', 9.8, 0.42, '2026-09-01')",
        [$tenantId, $machineA]
    );
    Database::query(
        "INSERT INTO vulnerabilities
         (tenant_id, machine_id, cve_id, product_name, severity, cvss_v3, epss, published_on)
         VALUES (?, ?, 'CVE-2026-98201', 'Contoso Server', 'Critical', 9.8, 0.42, '2026-09-01')",
        [$tenantId, $machineB]
    );
    Database::query(
        "INSERT INTO vulnerabilities
         (tenant_id, machine_id, cve_id, product_name, severity, cvss_v3, epss, published_on)
         VALUES (?, ?, 'CVE-2026-98202', 'Fabrikam App', 'High', 7.5, 0.10, '2026-10-01')",
        [$tenantId, $machineA]
    );

    $orgId = Database::insert(
        "INSERT INTO remediation_orgs (name, kind, tenant_id, created_by) VALUES (?, 'tenant', ?, 1)",
        ['E2E F1 org ' . $suffix, $tenantId]
    );
    $taskId = Database::insert(
        "INSERT INTO remediation_tasks
         (org_id, cve_id, title, severity, cvss, status, source, created_by, importado)
         VALUES (?, 'CVE-2026-98201', 'E2E F1 ticket', 'Critical', 9.8, 'open', 'defender', 1, datetime('now', '-6 days'))",
        [$orgId]
    );
    $org = Database::fetchOne("SELECT * FROM remediation_orgs WHERE id = ?", [$orgId]);
    RemediationWorkflow::initTask((int)$taskId, 'open', null, 1, 'Alta E2E F1');
    Database::query(
        "UPDATE remediation_tasks SET importado = datetime('now', '-6 days') WHERE id = ?",
        [$taskId]
    );
    RemediationQueue::syncTaskAssets((int)$taskId, $org, 'CVE-2026-98201', null);
    $asset = Database::fetchOne(
        "SELECT id FROM remediation_task_assets WHERE task_id = ? AND asset_name = 'WEB-01'",
        [$taskId]
    );

    echo json_encode([
        'tenant_id' => $tenantId,
        'org_id'    => $orgId,
        'task_id'   => $taskId,
        'asset_id'  => (int)($asset['id'] ?? 0),
        'suffix'    => $suffix,
        'due_at'    => date('Y-m-d', strtotime('+7 days')),
    ], JSON_UNESCAPED_UNICODE);
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
