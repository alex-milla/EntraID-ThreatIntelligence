<?php
/**
 * remediation_report.php — informes por periodo y métricas de servicio (CVE Desk, F3).
 *
 * Un informe es un activo: se crea en borrador para un periodo (YYYY-MM),
 * consume las marcas `en_informe` de la cola y, al publicarse, congela una
 * foto (HTML/Markdown) que ya no cambia. Las métricas se calculan siempre de
 * los datos existentes; no se introducen a mano.
 */

declare(strict_types=1);

final class RemediationReport
{
    public static function periodFromRequest(string $value): string
    {
        $value = trim($value);
        if (!preg_match('/^\d{4}-(0[1-9]|1[0-2])$/', $value)) {
            return date('Y-m');
        }
        return $value;
    }

    public static function listForOrg(int $orgId, int $limit = 24): array
    {
        if ($orgId <= 0) {
            return [];
        }
        return Database::fetchAll(
            "SELECT r.*,
                    o.name AS org_name,
                    (SELECT COUNT(*) FROM remediation_report_items i WHERE i.report_id = r.id) AS item_count,
                    u.display_name AS author_name,
                    u.username AS author_username
             FROM remediation_reports r
             LEFT JOIN remediation_orgs o ON o.id = r.org_id
             LEFT JOIN users u ON u.id = r.created_by
             WHERE r.org_id = ?
             ORDER BY r.periodo DESC, r.id DESC
             LIMIT " . max(1, min(60, $limit)),
            [$orgId]
        );
    }

    public static function get(int $orgId, int $reportId): ?array
    {
        if ($orgId <= 0 || $reportId <= 0) {
            return null;
        }
        $report = Database::fetchOne(
            "SELECT r.*, o.name AS org_name, u.display_name AS author_name, u.username AS author_username
             FROM remediation_reports r
             LEFT JOIN remediation_orgs o ON o.id = r.org_id
             LEFT JOIN users u ON u.id = r.created_by
             WHERE r.id = ? AND r.org_id = ?",
            [$reportId, $orgId]
        );
        return $report;
    }

    /** @return array<int,array<string,mixed>> */
    public static function items(int $reportId): array
    {
        if ($reportId <= 0) {
            return [];
        }
        $rows = Database::fetchAll(
            "SELECT * FROM remediation_report_items WHERE report_id = ? ORDER BY cve_id ASC",
            [$reportId]
        );
        foreach ($rows as $index => $row) {
            $snapshot = safe_json_decode((string)($row['snapshot_json'] ?? ''), []);
            $rows[$index] = array_merge(is_array($snapshot) ? $snapshot : [], $row);
        }
        return $rows;
    }

    /**
     * Crea un borrador para el periodo y copia las marcas `en_informe`.
     *
     * @return array{ok:bool,error:string,id:int,copied:int}
     */
    public static function createDraft(int $orgId, string $period, int $userId = 0): array
    {
        $out = ['ok' => false, 'error' => '', 'id' => 0, 'copied' => 0];
        if ($orgId <= 0) {
            $out['error'] = 'La organización no existe.';
            return $out;
        }
        $period = self::periodFromRequest($period);
        $existing = Database::fetchOne(
            "SELECT id FROM remediation_reports WHERE org_id = ? AND periodo = ? LIMIT 1",
            [$orgId, $period]
        );
        if ($existing !== null) {
            $out['error'] = 'Ya existe un informe para ' . $period . '.';
            return $out;
        }

        $reportId = Database::insert(
            "INSERT INTO remediation_reports (org_id, periodo, estado, created_by)
             VALUES (?, ?, 'borrador', ?)",
            [$orgId, $period, $userId > 0 ? $userId : null]
        );
        $out['id'] = (int)$reportId;

        $marks = Database::fetchAll(
            "SELECT cve_id FROM remediation_queue_marks WHERE org_id = ? ORDER BY cve_id",
            [$orgId]
        );
        foreach ($marks as $mark) {
            $res = self::addItem($orgId, (int)$reportId, (string)$mark['cve_id'], $userId, false);
            if (!empty($res['ok'])) {
                $out['copied']++;
            }
        }

        $out['ok'] = true;
        return $out;
    }

    /**
     * Añade un CVE al borrador. Acepta CVEs de la cola del tenant o tareas.
     *
     * @return array{ok:bool,error:string}
     */
    public static function addItem(
        int $orgId,
        int $reportId,
        string $cveId,
        int $userId = 0,
        bool $mark = true
    ): array {
        $report = self::get($orgId, $reportId);
        if ($report === null) {
            return ['ok' => false, 'error' => 'El informe no existe.'];
        }
        if ((string)$report['estado'] !== 'borrador') {
            return ['ok' => false, 'error' => 'Un informe publicado es inmutable.'];
        }
        $cveId = strtoupper(trim($cveId));
        if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId)) {
            return ['ok' => false, 'error' => 'CVE no válido.'];
        }

        $snapshot = self::snapshotForCve($orgId, $cveId);
        if ($snapshot === null) {
            return ['ok' => false, 'error' => 'Ese CVE no está en el tenant ni tiene ticket.'];
        }

        $existing = Database::fetchOne(
            "SELECT id FROM remediation_report_items WHERE report_id = ? AND cve_id = ?",
            [$reportId, $cveId]
        );
        $json = json_encode($snapshot, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($existing !== null) {
            Database::update(
                "UPDATE remediation_report_items SET snapshot_json = ?, task_id = ? WHERE id = ?",
                [$json, $snapshot['task_id'] ?? null, (int)$existing['id']]
            );
        } else {
            Database::insert(
                "INSERT INTO remediation_report_items (report_id, task_id, cve_id, snapshot_json)
                 VALUES (?, ?, ?, ?)",
                [$reportId, $snapshot['task_id'] ?? null, $cveId, $json]
            );
        }

        if ($mark) {
            $org = Database::fetchOne("SELECT * FROM remediation_orgs WHERE id = ?", [$orgId]);
            if ($org !== null) {
                RemediationQueue::mark($orgId, $org, $cveId, true, $userId);
            }
        }

        return ['ok' => true, 'error' => ''];
    }

    /** @return array{ok:bool,error:string} */
    public static function removeItem(int $orgId, int $reportId, string $cveId): array
    {
        $report = self::get($orgId, $reportId);
        if ($report === null) {
            return ['ok' => false, 'error' => 'El informe no existe.'];
        }
        if ((string)$report['estado'] !== 'borrador') {
            return ['ok' => false, 'error' => 'Un informe publicado es inmutable.'];
        }
        $cveId = strtoupper(trim($cveId));
        Database::query(
            "DELETE FROM remediation_report_items WHERE report_id = ? AND cve_id = ?",
            [$reportId, $cveId]
        );
        // Al sacarlo del borrador vuelve a la cola de nuevos.
        $org = Database::fetchOne("SELECT * FROM remediation_orgs WHERE id = ?", [$orgId]);
        if ($org !== null) {
            RemediationQueue::mark($orgId, $org, $cveId, false, 0);
        }
        return ['ok' => true, 'error' => ''];
    }

    /** Congela la foto del informe. @return array{ok:bool,error:string} */
    public static function publish(int $orgId, int $reportId, int $userId = 0): array
    {
        $report = self::get($orgId, $reportId);
        if ($report === null) {
            return ['ok' => false, 'error' => 'El informe no existe.'];
        }
        if ((string)$report['estado'] !== 'borrador') {
            return ['ok' => false, 'error' => 'El informe ya está publicado.'];
        }
        $items = self::items($reportId);
        if ($items === []) {
            return ['ok' => false, 'error' => 'El informe no tiene CVEs: añade al menos uno.'];
        }
        $report['estado'] = 'publicado';
        $report['published_at'] = date('Y-m-d H:i:s');
        $metrics = self::metricsForPeriod($orgId, (string)$report['periodo']);
        $md = self::renderMarkdown($report, $items, $metrics);
        $html = self::renderHtml($report, $items, $metrics);

        Database::update(
            "UPDATE remediation_reports
             SET estado = 'publicado', published_at = datetime('now'),
                 snapshot_md = ?, snapshot_html = ?, updated_at = datetime('now')
             WHERE id = ? AND org_id = ?",
            [$md, $html, $reportId, $orgId]
        );
        return ['ok' => true, 'error' => ''];
    }

    /**
     * Métricas de servicio de un periodo. Todo sale de datos existentes.
     *
     * @return array<string,mixed>
     */
    public static function metricsForPeriod(int $orgId, string $period): array
    {
        $period = self::periodFromRequest($period);
        $start = $period . '-01';
        $end = date('Y-m-t', strtotime($start));
        $startDt = $start . ' 00:00:00';
        $endDt = $end . ' 23:59:59';

        $out = [
            'period' => $period,
            'start'  => $start,
            'end'    => $end,
            'created'=> 0,
            'closed' => 0,
            'open'   => 0,
            'mttr'   => null,
            'mttr_by_severity' => [],
            'sla_total' => 0,
            'sla_on_time' => 0,
            'sla_pct' => 0,
            'delays' => [
                'retraso' => ['count' => 0, 'days' => 0],
                'bloqueo' => ['count' => 0, 'days' => 0],
            ],
            'delay_total_days' => 0,
            'risks' => [],
            'risks_expiring' => 0,
        ];
        if ($orgId <= 0) {
            return $out;
        }

        $out['created'] = (int)(Database::fetchOne(
            "SELECT COUNT(*) AS c FROM remediation_tasks WHERE org_id = ? AND created_at BETWEEN ? AND ?",
            [$orgId, $startDt, $endDt]
        )['c'] ?? 0);
        $out['closed'] = (int)(Database::fetchOne(
            "SELECT COUNT(*) AS c FROM remediation_tasks
             WHERE org_id = ? AND resolved_at IS NOT NULL AND resolved_at BETWEEN ? AND ?",
            [$orgId, $startDt, $endDt]
        )['c'] ?? 0);
        $out['open'] = (int)(Database::fetchOne(
            "SELECT COUNT(*) AS c FROM remediation_tasks
             WHERE org_id = ? AND created_at <= ? AND (resolved_at IS NULL OR resolved_at > ?)",
            [$orgId, $endDt, $endDt]
        )['c'] ?? 0);

        $mttr = Database::fetchOne(
            "SELECT AVG(julianday(resolved_at) - julianday(COALESCE(NULLIF(importado, ''), created_at))) AS d
             FROM remediation_tasks
             WHERE org_id = ? AND resolved_at IS NOT NULL AND resolved_at BETWEEN ? AND ?",
            [$orgId, $startDt, $endDt]
        );
        $out['mttr'] = $mttr !== null && $mttr['d'] !== null ? round((float)$mttr['d'], 1) : null;

        foreach (Database::fetchAll(
            "SELECT COALESCE(NULLIF(severity, ''), 'sin datos') AS sev,
                    COUNT(*) AS c,
                    AVG(julianday(resolved_at) - julianday(COALESCE(NULLIF(importado, ''), created_at))) AS d
             FROM remediation_tasks
             WHERE org_id = ? AND resolved_at IS NOT NULL AND resolved_at BETWEEN ? AND ?
             GROUP BY sev ORDER BY c DESC",
            [$orgId, $startDt, $endDt]
        ) as $row) {
            $out['mttr_by_severity'][] = [
                'severity' => (string)$row['sev'],
                'count'    => (int)$row['c'],
                'days'     => $row['d'] !== null ? round((float)$row['d'], 1) : null,
            ];
        }

        $sla = Database::fetchOne(
            "SELECT COUNT(*) AS total,
                    SUM(CASE WHEN due_at IS NOT NULL AND date(resolved_at) <= due_at THEN 1 ELSE 0 END) AS on_time
             FROM remediation_tasks
             WHERE org_id = ? AND resolved_at IS NOT NULL AND resolved_at BETWEEN ? AND ?",
            [$orgId, $startDt, $endDt]
        );
        $out['sla_total'] = (int)($sla['total'] ?? 0);
        $out['sla_on_time'] = (int)($sla['on_time'] ?? 0);
        $out['sla_pct'] = $out['sla_total'] > 0
            ? (int)round($out['sla_on_time'] * 100 / $out['sla_total'])
            : 0;

        foreach (Database::fetchAll(
            "SELECT l.tipo, COUNT(*) AS c, SUM(l.impacto_dias) AS days
             FROM remediation_task_logs l
             JOIN remediation_tasks t ON t.id = l.task_id
             WHERE t.org_id = ? AND l.created_at BETWEEN ? AND ? AND l.tipo IN ('retraso', 'bloqueo')
             GROUP BY l.tipo",
            [$orgId, $startDt, $endDt]
        ) as $row) {
            $tipo = (string)$row['tipo'];
            if (isset($out['delays'][$tipo])) {
                $out['delays'][$tipo] = [
                    'count' => (int)$row['c'],
                    'days'  => (int)($row['days'] ?? 0),
                ];
            }
        }
        $out['delay_total_days'] = $out['delays']['retraso']['days'] + $out['delays']['bloqueo']['days'];

        foreach (Database::fetchAll(
            "SELECT a.caducidad, a.justificacion, t.cve_id, t.severity,
                    CAST(julianday(a.caducidad) - julianday(date('now')) AS INTEGER) AS days_left
             FROM remediation_risk_acceptances a
             JOIN remediation_tasks t ON t.id = a.task_id
             WHERE t.org_id = ? AND a.estado = 'vigente' AND a.caducidad >= date('now')
             ORDER BY a.caducidad ASC",
            [$orgId]
        ) as $row) {
            $daysLeft = (int)($row['days_left'] ?? 0);
            $out['risks'][] = [
                'cve_id'        => (string)$row['cve_id'],
                'severity'      => (string)($row['severity'] ?? ''),
                'caducidad'     => (string)($row['caducidad'] ?? ''),
                'days_left'     => $daysLeft,
                'justificacion' => (string)($row['justificacion'] ?? ''),
            ];
            if ($daysLeft <= 7) {
                $out['risks_expiring']++;
            }
        }

        return $out;
    }

    /**
     * Instantánea de un CVE: desde la tarea si existe o desde el tenant.
     *
     * @return array<string,mixed>|null
     */
    private static function snapshotForCve(int $orgId, string $cveId): ?array
    {
        $task = Database::fetchOne(
            "SELECT * FROM remediation_tasks WHERE org_id = ? AND cve_id = ?",
            [$orgId, $cveId]
        );
        if ($task !== null) {
            return [
                'cve_id'    => $cveId,
                'task_id'   => (int)$task['id'],
                'severity'  => (string)($task['severity'] ?? ''),
                'cvss'      => $task['cvss'] !== null ? (float)$task['cvss'] : null,
                'epss'      => $task['epss'] !== null ? (float)$task['epss'] : null,
                'kev'       => (int)($task['kev'] ?? 0) === 1,
                'machines'  => (int)($task['machine_count'] ?? 0),
                'product'   => '',
                'published' => '',
                'estado'    => (string)($task['estado'] ?? ''),
                'status'    => (string)($task['status'] ?? ''),
                'owner'     => (string)($task['owner'] ?? ''),
                'due_at'    => (string)($task['due_at'] ?? ''),
                'eta_actual'=> (string)($task['eta_actual'] ?? ''),
                'patch_kb'  => (string)($task['patch_kb'] ?? ''),
                'fixed_version' => (string)($task['fixed_version'] ?? ''),
                'resolved_at'   => (string)($task['resolved_at'] ?? ''),
            ];
        }

        $org = Database::fetchOne("SELECT * FROM remediation_orgs WHERE id = ?", [$orgId]);
        $tenantId = $org !== null ? (int)($org['tenant_id'] ?? 0) : 0;
        if ($tenantId <= 0) {
            return null;
        }
        $row = Database::fetchOne(
            "SELECT v.cve_id,
                    MAX(v.cvss_v3) AS cvss,
                    MAX(v.epss) AS epss,
                    MAX(v.public_exploit) AS public_exploit,
                    COUNT(DISTINCT v.machine_id) AS machines,
                    MIN(v.published_on) AS published_on,
                    MAX(v.product_name) AS product_name,
                    MAX(CASE UPPER(COALESCE(v.severity, ''))
                        WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2
                        WHEN 'LOW' THEN 1 ELSE 0 END) AS sev_rank
             FROM vulnerabilities v
             WHERE v.tenant_id = ? AND v.cve_id = ?
             GROUP BY v.cve_id",
            [$tenantId, $cveId]
        );
        if ($row === null) {
            return null;
        }
        $labels = [4 => 'Critical', 3 => 'High', 2 => 'Medium', 1 => 'Low', 0 => ''];
        $kev = false;
        try {
            $kev = CveDatabase::fetchOne("SELECT cve_id FROM cve_kev WHERE cve_id = ?", [$cveId]) !== null;
        } catch (Throwable $e) {
            $kev = false;
        }
        return [
            'cve_id'    => $cveId,
            'task_id'   => null,
            'severity'  => $labels[(int)($row['sev_rank'] ?? 0)] ?? '',
            'cvss'      => $row['cvss'] !== null ? (float)$row['cvss'] : null,
            'epss'      => $row['epss'] !== null ? (float)$row['epss'] : null,
            'kev'       => $kev,
            'machines'  => (int)($row['machines'] ?? 0),
            'product'   => (string)($row['product_name'] ?? ''),
            'published' => (string)($row['published_on'] ?? ''),
            'estado'    => 'ticket_creado',
            'status'    => 'open',
            'owner'     => '',
            'due_at'    => '',
            'eta_actual'=> '',
            'patch_kb'  => '',
            'fixed_version' => '',
            'resolved_at'   => '',
        ];
    }

    /**
     * @param array<string,mixed> $report
     * @param array<int,array<string,mixed>> $items
     * @param array<string,mixed> $metrics
     */
    public static function renderMarkdown(array $report, array $items, array $metrics): string
    {
        $org = (string)($report['org_name'] ?? '');
        $period = (string)($report['periodo'] ?? '');
        $state = (string)($report['estado'] ?? 'borrador');
        $critical = 0;
        $kev = 0;
        $machines = 0;
        foreach ($items as $item) {
            if (strtolower((string)($item['severity'] ?? '')) === 'critical') {
                $critical++;
            }
            if (!empty($item['kev'])) {
                $kev++;
            }
            $machines += (int)($item['machines'] ?? 0);
        }

        $md = [];
        $md[] = '# Informe de remediación · ' . $period;
        $md[] = '';
        $md[] = '- Organización: ' . ($org !== '' ? $org : '—');
        $md[] = '- Estado: ' . ($state === 'publicado' ? 'publicado' : 'borrador');
        $md[] = '- CVE incluidos: ' . count($items) . ' (críticos ' . $critical . ' · KEV ' . $kev . ')';
        $md[] = '- Equipos afectados (suma TVM): ' . $machines;
        $md[] = '';
        $md[] = '## Vulnerabilidades incluidas';
        $md[] = '';
        $md[] = '| CVE | Severidad | CVSS | EPSS | Equipos | Estado | ETA | Producto |';
        $md[] = '| --- | --- | --- | --- | --- | --- | --- | --- |';
        foreach ($items as $item) {
            $cvss = $item['cvss'] !== null ? number_format((float)$item['cvss'], 1, '.', '') : '—';
            $epss = $item['epss'] !== null ? number_format((float)$item['epss'] * 100, 2, ',', '') . ' %' : '—';
            $eta = (string)($item['eta_actual'] ?? '') !== '' ? (string)$item['eta_actual'] : (string)($item['due_at'] ?? '');
            $md[] = '| ' . (string)$item['cve_id']
                . ' | ' . ((string)($item['severity'] ?? '') !== '' ? (string)$item['severity'] : '—')
                . ' | ' . $cvss
                . ' | ' . $epss
                . ' | ' . (int)($item['machines'] ?? 0)
                . ' | ' . ((string)($item['estado'] ?? '') !== '' ? (string)$item['estado'] : '—')
                . ' | ' . ($eta !== '' ? $eta : '—')
                . ' | ' . ((string)($item['product'] ?? '') !== '' ? (string)$item['product'] : '—')
                . ' |';
        }
        $md[] = '';
        $md[] = '## Servicio del periodo';
        $md[] = '';
        $md[] = '- Tareas creadas: ' . (int)($metrics['created'] ?? 0);
        $md[] = '- Tareas cerradas: ' . (int)($metrics['closed'] ?? 0);
        $md[] = '- Tareas abiertas al cierre del periodo: ' . (int)($metrics['open'] ?? 0);
        $md[] = '- MTTR: ' . ($metrics['mttr'] !== null ? number_format((float)$metrics['mttr'], 1, ',', '') . ' días' : 'sin datos');
        $md[] = '- Cumplimiento de SLA: ' . (int)($metrics['sla_pct'] ?? 0) . ' % ('
            . (int)($metrics['sla_on_time'] ?? 0) . '/' . (int)($metrics['sla_total'] ?? 0) . ')';
        $md[] = '- Retrasos: ' . (int)($metrics['delays']['retraso']['days'] ?? 0) . ' días en '
            . (int)($metrics['delays']['retraso']['count'] ?? 0) . ' entrada(s)'
            . ' · Bloqueos: ' . (int)($metrics['delays']['bloqueo']['days'] ?? 0) . ' días en '
            . (int)($metrics['delays']['bloqueo']['count'] ?? 0) . ' entrada(s)';
        $md[] = '';
        if (($metrics['mttr_by_severity'] ?? []) !== []) {
            $md[] = '### MTTR por severidad';
            $md[] = '';
            $md[] = '| Severidad | Cerradas | Días |';
            $md[] = '| --- | --- | --- |';
            foreach ($metrics['mttr_by_severity'] as $row) {
                $md[] = '| ' . (string)$row['severity'] . ' | ' . (int)$row['count'] . ' | '
                    . ($row['days'] !== null ? number_format((float)$row['days'], 1, ',', '') : '—') . ' |';
            }
            $md[] = '';
        }
        $md[] = '## Riesgos aceptados vigentes';
        $md[] = '';
        if (($metrics['risks'] ?? []) === []) {
            $md[] = 'No hay aceptaciones de riesgo vigentes.';
        } else {
            $md[] = '| CVE | Caducidad | Días | Justificación |';
            $md[] = '| --- | --- | --- | --- |';
            foreach ($metrics['risks'] as $risk) {
                $md[] = '| ' . (string)$risk['cve_id'] . ' | ' . (string)$risk['caducidad'] . ' | '
                    . (int)$risk['days_left'] . ' | ' . (string)$risk['justificacion'] . ' |';
            }
        }
        $md[] = '';
        return implode("\n", $md) . "\n";
    }

    /**
     * @param array<string,mixed> $report
     * @param array<int,array<string,mixed>> $items
     * @param array<string,mixed> $metrics
     */
    public static function renderHtml(array $report, array $items, array $metrics): string
    {
        $esc = static fn(mixed $value): string => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $org = (string)($report['org_name'] ?? '');
        $period = (string)($report['periodo'] ?? '');
        $state = (string)($report['estado'] ?? 'borrador');
        $critical = 0;
        $kev = 0;
        $machines = 0;
        foreach ($items as $item) {
            if (strtolower((string)($item['severity'] ?? '')) === 'critical') {
                $critical++;
            }
            if (!empty($item['kev'])) {
                $kev++;
            }
            $machines += (int)($item['machines'] ?? 0);
        }

        $h = [];
        $h[] = '<div style="font-family:Segoe UI,Arial,sans-serif;color:#0f172a;font-size:13px;">';
        $h[] = '<h1 style="font-size:22px;margin:0 0 6px;">Informe de remediación · ' . $esc($period) . '</h1>';
        $h[] = '<p style="margin:0;color:#4b5563;font-size:12px;">' . $esc($org) . ' · '
            . ($state === 'publicado' ? 'publicado' : 'borrador') . '</p>';
        $h[] = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin:14px 0;">';
        foreach ([
            'CVE' => count($items),
            'Críticos' => $critical,
            'KEV' => $kev,
            'Equipos' => $machines,
        ] as $label => $value) {
            $h[] = '<div style="border:1px solid #e5e7eb;border-radius:8px;padding:8px 12px;min-width:90px;">'
                . '<div style="font-size:10px;text-transform:uppercase;color:#6b7280;letter-spacing:.06em;">' . $esc($label) . '</div>'
                . '<div style="font-size:20px;font-weight:700;">' . (int)$value . '</div></div>';
        }
        $h[] = '</div>';
        $h[] = '<h2 style="font-size:15px;margin:18px 0 8px;">Vulnerabilidades incluidas</h2>';
        $h[] = '<table style="width:100%;border-collapse:collapse;font-size:12px;">';
        $h[] = '<thead><tr style="background:#f3f4f6;">'
            . '<th style="border:1px solid #d1d5db;padding:6px;text-align:left;">CVE</th>'
            . '<th style="border:1px solid #d1d5db;padding:6px;text-align:left;">Severidad</th>'
            . '<th style="border:1px solid #d1d5db;padding:6px;text-align:right;">CVSS</th>'
            . '<th style="border:1px solid #d1d5db;padding:6px;text-align:right;">EPSS</th>'
            . '<th style="border:1px solid #d1d5db;padding:6px;text-align:right;">Equipos</th>'
            . '<th style="border:1px solid #d1d5db;padding:6px;text-align:left;">Estado</th>'
            . '<th style="border:1px solid #d1d5db;padding:6px;text-align:left;">ETA</th>'
            . '<th style="border:1px solid #d1d5db;padding:6px;text-align:left;">Producto</th>'
            . '</tr></thead><tbody>';
        foreach ($items as $item) {
            $cvss = $item['cvss'] !== null ? number_format((float)$item['cvss'], 1, '.', '') : '—';
            $epss = $item['epss'] !== null ? number_format((float)$item['epss'] * 100, 2, ',', '') . ' %' : '—';
            $eta = (string)($item['eta_actual'] ?? '') !== '' ? (string)$item['eta_actual'] : (string)($item['due_at'] ?? '');
            $h[] = '<tr>'
                . '<td style="border:1px solid #d1d5db;padding:5px;font-family:Consolas,monospace;">' . $esc($item['cve_id'] ?? '') . '</td>'
                . '<td style="border:1px solid #d1d5db;padding:5px;">' . $esc($item['severity'] ?? '—') . '</td>'
                . '<td style="border:1px solid #d1d5db;padding:5px;text-align:right;">' . $esc($cvss) . '</td>'
                . '<td style="border:1px solid #d1d5db;padding:5px;text-align:right;">' . $esc($epss) . '</td>'
                . '<td style="border:1px solid #d1d5db;padding:5px;text-align:right;">' . (int)($item['machines'] ?? 0) . '</td>'
                . '<td style="border:1px solid #d1d5db;padding:5px;">' . $esc($item['estado'] ?? '—') . '</td>'
                . '<td style="border:1px solid #d1d5db;padding:5px;">' . $esc($eta !== '' ? $eta : '—') . '</td>'
                . '<td style="border:1px solid #d1d5db;padding:5px;">' . $esc($item['product'] ?? '—') . '</td>'
                . '</tr>';
        }
        $h[] = '</tbody></table>';

        $h[] = '<h2 style="font-size:15px;margin:18px 0 8px;">Servicio del periodo</h2>';
        $h[] = '<ul style="margin:0 0 0 18px;padding:0;">';
        $h[] = '<li>Tareas creadas: <strong>' . (int)($metrics['created'] ?? 0) . '</strong></li>';
        $h[] = '<li>Tareas cerradas: <strong>' . (int)($metrics['closed'] ?? 0) . '</strong></li>';
        $h[] = '<li>Abiertas al cierre del periodo: <strong>' . (int)($metrics['open'] ?? 0) . '</strong></li>';
        $h[] = '<li>MTTR: <strong>' . ($metrics['mttr'] !== null
            ? number_format((float)$metrics['mttr'], 1, ',', '') . ' días'
            : 'sin datos') . '</strong></li>';
        $h[] = '<li>Cumplimiento de SLA: <strong>' . (int)($metrics['sla_pct'] ?? 0) . ' %</strong> ('
            . (int)($metrics['sla_on_time'] ?? 0) . '/' . (int)($metrics['sla_total'] ?? 0) . ')</li>';
        $h[] = '<li>Retrasos: <strong>' . (int)($metrics['delays']['retraso']['days'] ?? 0) . ' días</strong> · '
            . 'Bloqueos: <strong>' . (int)($metrics['delays']['bloqueo']['days'] ?? 0) . ' días</strong></li>';
        $h[] = '</ul>';

        if (($metrics['mttr_by_severity'] ?? []) !== []) {
            $h[] = '<h3 style="font-size:13px;margin:14px 0 6px;">MTTR por severidad</h3>';
            $h[] = '<table style="border-collapse:collapse;font-size:12px;">'
                . '<thead><tr style="background:#f3f4f6;">'
                . '<th style="border:1px solid #d1d5db;padding:5px;text-align:left;">Severidad</th>'
                . '<th style="border:1px solid #d1d5db;padding:5px;text-align:right;">Cerradas</th>'
                . '<th style="border:1px solid #d1d5db;padding:5px;text-align:right;">Días</th>'
                . '</tr></thead><tbody>';
            foreach ($metrics['mttr_by_severity'] as $row) {
                $h[] = '<tr>'
                    . '<td style="border:1px solid #d1d5db;padding:5px;">' . $esc($row['severity']) . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px;text-align:right;">' . (int)$row['count'] . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px;text-align:right;">'
                    . ($row['days'] !== null ? $esc(number_format((float)$row['days'], 1, ',', '')) : '—') . '</td>'
                    . '</tr>';
            }
            $h[] = '</tbody></table>';
        }

        $h[] = '<h2 style="font-size:15px;margin:18px 0 8px;">Riesgos aceptados vigentes</h2>';
        if (($metrics['risks'] ?? []) === []) {
            $h[] = '<p style="margin:0;color:#4b5563;">No hay aceptaciones de riesgo vigentes.</p>';
        } else {
            $h[] = '<table style="width:100%;border-collapse:collapse;font-size:12px;">'
                . '<thead><tr style="background:#f3f4f6;">'
                . '<th style="border:1px solid #d1d5db;padding:5px;text-align:left;">CVE</th>'
                . '<th style="border:1px solid #d1d5db;padding:5px;text-align:left;">Caducidad</th>'
                . '<th style="border:1px solid #d1d5db;padding:5px;text-align:right;">Días</th>'
                . '<th style="border:1px solid #d1d5db;padding:5px;text-align:left;">Justificación</th>'
                . '</tr></thead><tbody>';
            foreach ($metrics['risks'] as $risk) {
                $h[] = '<tr>'
                    . '<td style="border:1px solid #d1d5db;padding:5px;font-family:Consolas,monospace;">' . $esc($risk['cve_id']) . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px;">' . $esc($risk['caducidad']) . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px;text-align:right;">' . (int)$risk['days_left'] . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px;">' . $esc($risk['justificacion']) . '</td>'
                    . '</tr>';
            }
            $h[] = '</tbody></table>';
        }
        $h[] = '</div>';
        return implode('', $h);
    }
}
