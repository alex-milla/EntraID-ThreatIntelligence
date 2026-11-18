<?php
/**
 * Smoke — SLA y cola de Remediación (CVE Desk, F1).
 *
 *   php tools/smoke/remediation_queue.php
 *
 * Crea un tenant sintético con equipos y vulnerabilidades, comprueba la cola,
 * las marcas de informe, el SLA (base y reforzado) y la sincronización de
 * activos. Limpia todo lo que crea.
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
$taskId = 0;

try {
    /* -----------------------------------------------------------------
     * 1. SLA base y reforzado
     * -------------------------------------------------------------- */
    $settings = RemediationSla::settings();
    check('SLA: crítica 7 días', (int)$settings['critical'] === 7, (string)$settings['critical']);
    check('SLA: alta 15 días', (int)$settings['high'] === 15, (string)$settings['high']);
    check('SLA: media 30 días', (int)$settings['medium'] === 30, (string)$settings['medium']);
    check('SLA: baja 60 días', (int)$settings['low'] === 60, (string)$settings['low']);
    $critical = RemediationSla::criticalSettings();
    check('SLA reforzado: crítica 3 días', (int)$critical['critical'] === 3, (string)$critical['critical']);

    check('severidad: Critical', RemediationSla::severityKey('Critical') === 'critical');
    check('severidad: Crítica', RemediationSla::severityKey('Crítica') === 'critical');
    check('severidad: por CVSS', RemediationSla::severityKey('', 8.1) === 'high');
    check('severidad: desconocida cae a media', RemediationSla::severityKey('') === 'medium');

    $today = gmdate('Y-m-d');
    $slaHoy = RemediationSla::forDate($today, 'Critical');
    check('SLA hoy: día 1 de 7', $slaHoy['label'] === 'día 1 de 7', $slaHoy['label']);
    check('SLA hoy: en plazo', $slaHoy['state'] === 'en_plazo', $slaHoy['state']);

    $slaRisk = RemediationSla::forDate(gmdate('Y-m-d', strtotime('-6 days')), 'Critical');
    check('SLA 6/7: en riesgo', $slaRisk['state'] === 'en_riesgo', $slaRisk['state']);

    $slaLate = RemediationSla::forDate(gmdate('Y-m-d', strtotime('-7 days')), 'Critical');
    check('SLA 7/7: vencido', $slaLate['state'] === 'vencido', $slaLate['state']);
    $slaLateCrit = RemediationSla::forDate(gmdate('Y-m-d', strtotime('-4 days')), 'Critical', 9.8, true);
    check('SLA activo crítico: 3 días', (int)$slaLateCrit['days'] === 3 && $slaLateCrit['state'] === 'vencido');

    $closed = RemediationSla::forDate(gmdate('Y-m-d', strtotime('-10 days')), 'High', 8.0, false, gmdate('Y-m-d', strtotime('-2 days')));
    check('SLA cerrado: etiqueta de cierre', $closed['state'] === 'cerrado' && str_contains($closed['label'], 'cerrado en'));
    check('SLA sin fecha', RemediationSla::forDate('', 'High')['state'] === 'sin_datos');

    /* -----------------------------------------------------------------
     * 2. Tenant sintético con equipos y vulnerabilidades
     * -------------------------------------------------------------- */
    $suffix = bin2hex(random_bytes(4));
    $tenantId = Database::insert(
        "INSERT INTO tenants (name, slug, tenant_id, client_id, client_secret_encrypted, client_secret_iv, permissions)
         VALUES (?, ?, ?, 'client-smoke', 'enc', 'iv', '[]')",
        ['Smoke F1 ' . $suffix, 'smoke-f1-' . $suffix, 'tenant-smoke-' . $suffix]
    );
    $machineA = Database::insert(
        "INSERT INTO machines (tenant_id, machine_id, computer_dns_name, os_platform, os_version, exposure_level)
         VALUES (?, ?, 'WEB-01', 'Windows', '11', 'High')",
        [$tenantId, 'machine-a-' . $suffix]
    );
    $machineB = Database::insert(
        "INSERT INTO machines (tenant_id, machine_id, computer_dns_name, os_platform, os_version, exposure_level)
         VALUES (?, ?, 'APP-02', 'Windows', 'Server 2022', 'Medium')",
        [$tenantId, 'machine-b-' . $suffix]
    );
    Database::insert(
        "INSERT INTO vulnerabilities
         (tenant_id, machine_id, cve_id, product_name, severity, cvss_v3, epss, published_on)
         VALUES (?, ?, 'CVE-2026-98101', 'Contoso Server', 'Critical', 9.8, 0.42, '2026-09-01')",
        [$tenantId, $machineA]
    );
    Database::insert(
        "INSERT INTO vulnerabilities
         (tenant_id, machine_id, cve_id, product_name, severity, cvss_v3, epss, published_on)
         VALUES (?, ?, 'CVE-2026-98101', 'Contoso Server', 'Critical', 9.8, 0.42, '2026-09-01')",
        [$tenantId, $machineB]
    );
    Database::insert(
        "INSERT INTO vulnerabilities
         (tenant_id, machine_id, cve_id, product_name, severity, cvss_v3, epss, published_on)
         VALUES (?, ?, 'CVE-2026-98102', 'Fabrikam App', 'High', 7.5, 0.10, '2026-10-01')",
        [$tenantId, $machineA]
    );

    $orgId = Database::insert(
        "INSERT INTO remediation_orgs (name, kind, tenant_id, created_by) VALUES (?, 'tenant', ?, 1)",
        ['Smoke org F1 ' . $suffix, $tenantId]
    );
    $org = Database::fetchOne("SELECT * FROM remediation_orgs WHERE id = ?", [$orgId]);

    /* -----------------------------------------------------------------
     * 3. Cola
     * -------------------------------------------------------------- */
    check('cola: organización de tenant', RemediationQueue::isTenantOrg($org));
    $counts = RemediationQueue::counts($orgId, $org);
    check('cola: dos CVEs sin ticket', (int)$counts['total'] === 2, (string)$counts['total']);
    check('cola: ambos nuevos', (int)$counts['nuevo'] === 2 && (int)$counts['en_informe'] === 0);

    $rows = RemediationQueue::rows($orgId, $org);
    check('cola: filas', count($rows) === 2, (string)count($rows));
    $first = $rows[0];
    check('cola: orden por severidad', $first['cve_id'] === 'CVE-2026-98101');
    check('cola: equipos agregados', (int)$first['machines'] === 2, (string)$first['machines']);
    check('cola: SLA calculado', ($first['sla']['state'] ?? '') === 'en_plazo');

    $mark = RemediationQueue::mark($orgId, $org, 'CVE-2026-98101', true, 1);
    check('cola: marcar en informe', !empty($mark['ok']));
    $counts = RemediationQueue::counts($orgId, $org);
    check('cola: contador en informe', (int)$counts['en_informe'] === 1 && (int)$counts['nuevo'] === 1);
    $onlyMarked = RemediationQueue::rows($orgId, $org, ['state' => 'en_informe']);
    check('cola: filtro en informe', count($onlyMarked) === 1 && $onlyMarked[0]['cve_id'] === 'CVE-2026-98101');

    $unmark = RemediationQueue::mark($orgId, $org, 'CVE-2026-98101', false, 1);
    check('cola: desmarcar', !empty($unmark['ok'])
        && (int)RemediationQueue::counts($orgId, $org)['en_informe'] === 0);
    $bad = RemediationQueue::mark($orgId, $org, 'NO-ES-CVE', true, 1);
    check('cola: CVE inválido rechazado', empty($bad['ok']));

    // Antigüedad: si el CVE se vio hace 10 días, el SLA de 7 ya venció.
    Database::update(
        "UPDATE remediation_queue_seen SET first_seen_at = datetime('now', '-10 days') WHERE org_id = ? AND cve_id = 'CVE-2026-98101'",
        [$orgId]
    );
    $aged = RemediationQueue::rows($orgId, $org);
    $agedById = [];
    foreach ($aged as $row) {
        $agedById[$row['cve_id']] = $row;
    }
    check('cola: SLA vencido por antigüedad', ($agedById['CVE-2026-98101']['sla']['state'] ?? '') === 'vencido');

    /* -----------------------------------------------------------------
     * 4. Activos del ticket y SLA reforzado
     * -------------------------------------------------------------- */
    $taskId = Database::insert(
        "INSERT INTO remediation_tasks
         (org_id, cve_id, title, severity, cvss, status, source, created_by)
         VALUES (?, 'CVE-2026-98101', 'Smoke F1', 'Critical', 9.8, 'open', 'defender', 1)",
        [$orgId]
    );
    RemediationWorkflow::initTask($taskId, 'open', null, 1, 'Alta smoke F1');
    $synced = RemediationQueue::syncTaskAssets($taskId, $org, 'CVE-2026-98101', null);
    check('activos: sincronizados del tenant', $synced === 2, (string)$synced);
    $assets = Database::fetchAll("SELECT * FROM remediation_task_assets WHERE task_id = ?", [$taskId]);
    check('activos: filas', count($assets) === 2, (string)count($assets));
    $task = Database::fetchOne("SELECT machine_count, machines_json FROM remediation_tasks WHERE id = ?", [$taskId]);
    check('activos: machine_count heredado', (int)$task['machine_count'] === 2);

    $webAsset = null;
    foreach ($assets as $asset) {
        if ((string)$asset['asset_name'] === 'WEB-01') {
            $webAsset = $asset;
        }
    }
    check('activos: WEB-01 presente', $webAsset !== null);
    Database::update(
        "UPDATE remediation_task_assets SET environment = 'prod', criticality = 'alta' WHERE id = ?",
        [(int)$webAsset['id']]
    );
    $criticalMap = RemediationSla::criticalAssetsByTask([$taskId]);
    check('SLA: activo crítico detectado', isset($criticalMap[$taskId]));
    check('SLA: plazo reforzado 3 días', RemediationSla::daysFor('Critical', true) === 3);

    // Un ticket existente desaparece de la cola.
    $counts = RemediationQueue::counts($orgId, $org);
    check('cola: el CVE con ticket sale', (int)$counts['total'] === 1, (string)$counts['total']);
} finally {
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
    if ($tenantId > 0) {
        Database::query("DELETE FROM vulnerabilities WHERE tenant_id = ?", [$tenantId]);
        Database::query("DELETE FROM machines WHERE tenant_id = ?", [$tenantId]);
        Database::query("DELETE FROM tenants WHERE id = ?", [$tenantId]);
    }
}

echo "\n{$total} comprobaciones · " . ($fail === 0 ? 'TODO OK' : $fail . ' FALLOS') . "\n";
exit($fail === 0 ? 0 : 1);
