<?php
/**
 * Smoke — informes, métricas y roles de Remediación (CVE Desk, F3).
 *
 *   php tools/smoke/remediation_report.php
 *
 * Crea un tenant sintético, marcas de cola, un informe, una tarea cerrada,
 * un retraso y una aceptación de riesgo. Limpia todo lo que crea.
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

$tenantId = 0;
$orgId = 0;
$reportId = 0;
$taskId = 0;
$userId = 0;

try {
    $suffix = bin2hex(random_bytes(4));
    $tenantId = Database::insert(
        "INSERT INTO tenants (name, slug, tenant_id, client_id, client_secret_encrypted, client_secret_iv, permissions)
         VALUES (?, ?, ?, 'client-report', 'enc', 'iv', '[]')",
        ['Smoke F3 ' . $suffix, 'smoke-f3-' . $suffix, 'tenant-f3-' . $suffix]
    );
    $machine = Database::insert(
        "INSERT INTO machines (tenant_id, machine_id, computer_dns_name, os_platform, os_version, exposure_level)
         VALUES (?, ?, 'SRV-01', 'Windows', 'Server 2022', 'High')",
        [$tenantId, 'machine-f3-' . $suffix]
    );
    foreach ([
        ['CVE-2026-98301', 'Critical', 9.8],
        ['CVE-2026-98302', 'High', 7.5],
    ] as [$cve, $severity, $cvss]) {
        Database::query(
            "INSERT INTO vulnerabilities
             (tenant_id, machine_id, cve_id, product_name, severity, cvss_v3, epss, published_on)
             VALUES (?, ?, ?, 'Contoso Server', ?, ?, 0.2, '2026-09-01')",
            [$tenantId, $machine, $cve, $severity, $cvss]
        );
    }
    $orgId = Database::insert(
        "INSERT INTO remediation_orgs (name, kind, tenant_id, created_by) VALUES (?, 'tenant', ?, 1)",
        ['Smoke F3 org ' . $suffix, $tenantId]
    );
    $org = Database::fetchOne("SELECT * FROM remediation_orgs WHERE id = ?", [$orgId]);

    /* -----------------------------------------------------------------
     * 1. Cola y borrador
     * -------------------------------------------------------------- */
    check('cola: marcar CVE', !empty(RemediationQueue::mark($orgId, $org, 'CVE-2026-98301', true, 1)['ok']));
    $period = date('Y-m');
    $draft = RemediationReport::createDraft($orgId, $period, 1);
    $reportId = (int)$draft['id'];
    check('informe: borrador creado', !empty($draft['ok']) && $reportId > 0);
    check('informe: copia las marcas', (int)$draft['copied'] === 1, (string)$draft['copied']);
    $items = RemediationReport::items($reportId);
    check('informe: un CVE', count($items) === 1);
    check('informe: instantánea de severidad', (string)($items[0]['severity'] ?? '') === 'Critical');

    $dup = RemediationReport::createDraft($orgId, $period, 1);
    check('informe: no duplica el periodo', empty($dup['ok']));

    $add = RemediationReport::addItem($orgId, $reportId, 'CVE-2026-98302', 1);
    check('informe: añadir CVE', !empty($add['ok']) && count(RemediationReport::items($reportId)) === 2);
    $remove = RemediationReport::removeItem($orgId, $reportId, 'CVE-2026-98302');
    check('informe: quitar CVE', !empty($remove['ok']) && count(RemediationReport::items($reportId)) === 1);

    /* -----------------------------------------------------------------
     * 2. Métricas del periodo (tarea cerrada, retraso y riesgo)
     * -------------------------------------------------------------- */
    $taskId = Database::insert(
        "INSERT INTO remediation_tasks
         (org_id, cve_id, title, severity, cvss, status, estado, due_at, resolved_at, importado,
          created_at, source, created_by)
         VALUES (?, 'CVE-2026-98301', 'Smoke F3', 'Critical', 9.8, 'patched', 'cerrado',
                 date('now', '+1 day'), datetime('now'), datetime('now', '-5 days'),
                 datetime('now', '-5 days'), 'defender', 1)",
        [$orgId]
    );
    Database::query(
        "INSERT INTO remediation_task_logs (task_id, tipo, texto, impacto_dias, autor_id, autor)
         VALUES (?, 'retraso', 'Ventana denegada', 2, 1, 'Admin')",
        [$taskId]
    );
    Database::query(
        "INSERT INTO remediation_risk_acceptances (task_id, justificacion, caducidad, aprobado_por, estado)
         VALUES (?, 'Compensado con WAF', date('now', '+5 days'), 1, 'vigente')",
        [$taskId]
    );

    $metrics = RemediationReport::metricsForPeriod($orgId, $period);
    check('métricas: tareas creadas', (int)$metrics['created'] >= 1, (string)$metrics['created']);
    check('métricas: tareas cerradas', (int)$metrics['closed'] >= 1, (string)$metrics['closed']);
    check('métricas: MTTR', $metrics['mttr'] !== null && (float)$metrics['mttr'] > 0);
    check('métricas: SLA en plazo', (int)$metrics['sla_total'] >= 1 && (int)$metrics['sla_on_time'] >= 1);
    check('métricas: retraso contado', (int)$metrics['delays']['retraso']['days'] >= 2);
    check('métricas: riesgo vigente', count($metrics['risks']) >= 1);
    check('métricas: riesgo por caducar', (int)$metrics['risks_expiring'] >= 1);
    check('métricas: MTTR por severidad', ($metrics['mttr_by_severity'] ?? []) !== []);

    /* -----------------------------------------------------------------
     * 3. Publicación congelada
     * -------------------------------------------------------------- */
    $publish = RemediationReport::publish($orgId, $reportId, 1);
    check('publicar: ok', !empty($publish['ok']));
    $published = RemediationReport::get($orgId, $reportId);
    check('publicar: estado', (string)($published['estado'] ?? '') === 'publicado');
    check('publicar: snapshot markdown', str_contains((string)($published['snapshot_md'] ?? ''), 'CVE-2026-98301'));
    check('publicar: snapshot html', str_contains((string)($published['snapshot_html'] ?? ''), 'Informe de remediación'));
    check('publicar: snapshot con métricas', str_contains((string)($published['snapshot_md'] ?? ''), 'Servicio del periodo'));
    check('publicar: inmutable (añadir)', empty(RemediationReport::addItem($orgId, $reportId, 'CVE-2026-98302', 1)['ok']));
    check('publicar: inmutable (quitar)', empty(RemediationReport::removeItem($orgId, $reportId, 'CVE-2026-98301')['ok']));

    /* -----------------------------------------------------------------
     * 4. Roles
     * -------------------------------------------------------------- */
    $userId = Database::insert(
        "INSERT INTO users (username, email, password_hash, display_name, role, must_change_password)
         VALUES (?, ?, 'x', 'Usuario F3', 'user', 0)",
        ['smoke-f3-' . $suffix, 'smoke-f3-' . $suffix . '@example.test']
    );
    check('roles: sin configurar no restringe', RemediationRoles::canWrite($userId) && RemediationRoles::canApproveRisk($userId));
    check('roles: asignar lector', RemediationRoles::assign($userId, 'lector'));
    check('roles: lector no escribe', !RemediationRoles::canWrite($userId));
    check('roles: lector no aprueba', !RemediationRoles::canApproveRisk($userId));
    check('roles: asignar aprobador', RemediationRoles::assign($userId, 'aprobador'));
    check('roles: aprobador escribe', RemediationRoles::canWrite($userId));
    check('roles: aprobador aprueba', RemediationRoles::canApproveRisk($userId));
    check('roles: admin siempre', RemediationRoles::canWrite(1) && RemediationRoles::canApproveRisk(1));
} finally {
    if ($reportId > 0) {
        Database::query("DELETE FROM remediation_report_items WHERE report_id = ?", [$reportId]);
        Database::query("DELETE FROM remediation_reports WHERE id = ?", [$reportId]);
    }
    if ($taskId > 0) {
        Database::query("DELETE FROM remediation_task_logs WHERE task_id = ?", [$taskId]);
        Database::query("DELETE FROM remediation_task_assets WHERE task_id = ?", [$taskId]);
        Database::query("DELETE FROM remediation_risk_acceptances WHERE task_id = ?", [$taskId]);
        Database::query("DELETE FROM remediation_task_checks WHERE task_id = ?", [$taskId]);
        Database::query("DELETE FROM remediation_tasks WHERE id = ?", [$taskId]);
    }
    if ($orgId > 0) {
        Database::query("DELETE FROM remediation_queue_marks WHERE org_id = ?", [$orgId]);
        Database::query("DELETE FROM remediation_queue_seen WHERE org_id = ?", [$orgId]);
        Database::query("DELETE FROM remediation_orgs WHERE id = ?", [$orgId]);
    }
    if ($userId > 0) {
        Database::query("DELETE FROM remediation_roles WHERE user_id = ?", [$userId]);
        Database::query("DELETE FROM users WHERE id = ?", [$userId]);
    }
    if ($tenantId > 0) {
        Database::query("DELETE FROM vulnerabilities WHERE tenant_id = ?", [$tenantId]);
        Database::query("DELETE FROM machines WHERE tenant_id = ?", [$tenantId]);
        Database::query("DELETE FROM tenants WHERE id = ?", [$tenantId]);
    }
}

echo "\n{$total} comprobaciones · " . ($fail === 0 ? 'TODO OK' : $fail . ' FALLOS') . "\n";
exit($fail === 0 ? 0 : 1);
