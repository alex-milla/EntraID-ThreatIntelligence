<?php
/**
 * remediation_queue.php — cola de CVEs del tenant sin ticket (CVE Desk, F1).
 *
 * La cola NO duplica vulnerabilidades: se calcula desde `vulnerabilities`
 * (una fila por equipo/CVE) agrupando por CVE y excluyendo lo que ya tiene
 * ticket en la organización. `remediation_queue_seen` guarda la primera vez
 * que la app ve cada CVE (punto de inicio del SLA) y
 * `remediation_queue_marks` la selección para el próximo informe.
 *
 * Los metadatos de activo (entorno, criticidad, dueño) no vienen de Defender:
 * se guardan en `remediation_task_assets` y se pueden editar en la ficha.
 */

declare(strict_types=1);

final class RemediationQueue
{
    public static function isTenantOrg(array $org): bool
    {
        return (string)($org['kind'] ?? '') === 'tenant' && (int)($org['tenant_id'] ?? 0) > 0;
    }

    public static function tenantId(array $org): int
    {
        return self::isTenantOrg($org) ? (int)$org['tenant_id'] : 0;
    }

    /**
     * Contadores de la cola: nuevos, en informe y total.
     *
     * @return array{nuevo:int,en_informe:int,total:int,tenant:bool}
     */
    public static function counts(int $orgId, array $org): array
    {
        $out = ['nuevo' => 0, 'en_informe' => 0, 'total' => 0, 'tenant' => self::isTenantOrg($org)];
        $tenantId = self::tenantId($org);
        if ($tenantId <= 0 || $orgId <= 0) {
            return $out;
        }

        $total = (int)(Database::fetchOne(
            "SELECT COUNT(DISTINCT v.cve_id) AS c
             FROM vulnerabilities v
             WHERE v.tenant_id = ?
               AND NOT EXISTS (SELECT 1 FROM remediation_tasks t WHERE t.org_id = ? AND t.cve_id = v.cve_id)",
            [$tenantId, $orgId]
        )['c'] ?? 0);

        $marked = (int)(Database::fetchOne(
            "SELECT COUNT(*) AS c
             FROM remediation_queue_marks m
             WHERE m.org_id = ? AND m.state = 'en_informe'
               AND EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.tenant_id = ? AND v.cve_id = m.cve_id)
               AND NOT EXISTS (SELECT 1 FROM remediation_tasks t WHERE t.org_id = m.org_id AND t.cve_id = m.cve_id)",
            [$orgId, $tenantId]
        )['c'] ?? 0);

        $out['total'] = $total;
        $out['en_informe'] = min($marked, $total);
        $out['nuevo'] = max(0, $total - $out['en_informe']);
        return $out;
    }

    /**
     * Filas de la cola (máximo 300), ya con estado, KEV y SLA.
     *
     * @param array<string,mixed> $org
     * @param array{state?:string,severity?:string,q?:string} $filters
     * @return array<int,array<string,mixed>>
     */
    public static function rows(int $orgId, array $org, array $filters = []): array
    {
        $tenantId = self::tenantId($org);
        if ($tenantId <= 0 || $orgId <= 0) {
            return [];
        }

        $where = ['v.tenant_id = ?'];
        $params = [$tenantId];

        $severity = strtoupper(trim((string)($filters['severity'] ?? '')));
        if (in_array($severity, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], true)) {
            $where[] = 'UPPER(v.severity) = ?';
            $params[] = $severity;
        }
        $q = trim((string)($filters['q'] ?? ''));
        if ($q !== '') {
            $where[] = '(v.cve_id LIKE ? OR v.product_name LIKE ?)';
            $like = '%' . $q . '%';
            $params[] = $like;
            $params[] = $like;
        }
        $where[] = 'NOT EXISTS (SELECT 1 FROM remediation_tasks t WHERE t.org_id = ? AND t.cve_id = v.cve_id)';
        $params[] = $orgId;

        $rows = Database::fetchAll(
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
             WHERE " . implode(' AND ', $where) . "
             GROUP BY v.cve_id
             ORDER BY sev_rank DESC, machines DESC, v.cve_id ASC
             LIMIT 300",
            $params
        );
        if ($rows === []) {
            return [];
        }

        $cveIds = array_map(static fn(array $row): string => (string)$row['cve_id'], $rows);
        $firstSeen = self::ensureSeen($orgId, $cveIds);
        $marks = self::marks($orgId);
        $kev = self::kevSet($cveIds);

        $labels = [4 => 'Critical', 3 => 'High', 2 => 'Medium', 1 => 'Low', 0 => ''];
        $stateFilter = (string)($filters['state'] ?? '');
        $out = [];
        foreach ($rows as $row) {
            $cveId = (string)$row['cve_id'];
            $state = isset($marks[$cveId]) ? 'en_informe' : 'nuevo';
            if ($stateFilter === 'nuevo' && $state !== 'nuevo') {
                continue;
            }
            if ($stateFilter === 'en_informe' && $state !== 'en_informe') {
                continue;
            }

            $severityLabel = $labels[(int)($row['sev_rank'] ?? 0)] ?? '';
            $cvss = $row['cvss'] !== null ? (float)$row['cvss'] : null;
            $start = $firstSeen[$cveId] ?? date('Y-m-d H:i:s');
            $sla = RemediationSla::forDate($start, $severityLabel, $cvss);

            $out[] = [
                'cve_id'        => $cveId,
                'severity'      => $severityLabel,
                'cvss'          => $cvss,
                'epss'          => $row['epss'] !== null ? (float)$row['epss'] : null,
                'public_exploit'=> (int)($row['public_exploit'] ?? 0) === 1,
                'machines'      => (int)($row['machines'] ?? 0),
                'published_on'  => (string)($row['published_on'] ?? ''),
                'product_name'  => (string)($row['product_name'] ?? ''),
                'kev'           => isset($kev[$cveId]),
                'state'         => $state,
                'first_seen_at' => $start,
                'sla'           => $sla,
            ];
        }

        return $out;
    }

    /**
     * Marca o desmarca un CVE para el próximo informe.
     *
     * @return array{ok:bool,error:string}
     */
    public static function mark(int $orgId, array $org, string $cveId, bool $mark, int $userId = 0): array
    {
        $cveId = strtoupper(trim($cveId));
        if ($orgId <= 0 || !preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId)) {
            return ['ok' => false, 'error' => 'CVE no válido.'];
        }
        if (!self::isTenantOrg($org)) {
            return ['ok' => false, 'error' => 'La cola solo está disponible en organizaciones vinculadas a un tenant.'];
        }
        $exists = Database::fetchOne(
            "SELECT 1 FROM vulnerabilities WHERE tenant_id = ? AND cve_id = ? LIMIT 1",
            [self::tenantId($org), $cveId]
        );
        if ($exists === null) {
            return ['ok' => false, 'error' => 'Ese CVE no está en las vulnerabilidades del tenant.'];
        }

        if (!$mark) {
            Database::query(
                "DELETE FROM remediation_queue_marks WHERE org_id = ? AND cve_id = ?",
                [$orgId, $cveId]
            );
            return ['ok' => true, 'error' => ''];
        }

        Database::query(
            "INSERT INTO remediation_queue_marks (org_id, cve_id, state, marked_by)
             VALUES (?, ?, 'en_informe', ?)
             ON CONFLICT(org_id, cve_id) DO UPDATE SET state = 'en_informe',
                 marked_by = excluded.marked_by, updated_at = datetime('now')",
            [$orgId, $cveId, $userId > 0 ? $userId : null]
        );
        return ['ok' => true, 'error' => ''];
    }

    /**
     * Primera vez visto por CVE (SLA). Inserta solo lo que falta.
     *
     * @param string[] $cveIds
     * @return array<string,string>
     */
    public static function ensureSeen(int $orgId, array $cveIds): array
    {
        $cveIds = array_values(array_unique(array_filter(array_map('strtoupper', $cveIds))));
        if ($orgId <= 0 || $cveIds === []) {
            return [];
        }
        $existing = [];
        foreach (array_chunk($cveIds, 500) as $chunk) {
            foreach (Database::fetchAll(
                "SELECT cve_id, first_seen_at FROM remediation_queue_seen
                 WHERE org_id = ? AND cve_id IN (" . implode(',', array_fill(0, count($chunk), '?')) . ")",
                array_merge([$orgId], $chunk)
            ) as $row) {
                $existing[(string)$row['cve_id']] = (string)$row['first_seen_at'];
            }
        }

        $missing = array_values(array_diff($cveIds, array_keys($existing)));
        foreach ($missing as $cveId) {
            Database::query(
                "INSERT OR IGNORE INTO remediation_queue_seen (org_id, cve_id) VALUES (?, ?)",
                [$orgId, $cveId]
            );
        }
        if ($missing !== []) {
            foreach (array_chunk($missing, 500) as $chunk) {
                foreach (Database::fetchAll(
                    "SELECT cve_id, first_seen_at FROM remediation_queue_seen
                     WHERE org_id = ? AND cve_id IN (" . implode(',', array_fill(0, count($chunk), '?')) . ")",
                    array_merge([$orgId], $chunk)
                ) as $row) {
                    $existing[(string)$row['cve_id']] = (string)$row['first_seen_at'];
                }
            }
        }

        return $existing;
    }

    /**
     * Vuelca los equipos del tenant (o los escritos a mano) a
     * `remediation_task_assets` sin pisar entorno/criticidad/dueño. También
     * actualiza machine_count/machines_json para la vista heredada.
     *
     * @param array<string,mixed> $org
     * @param array<int,array<string,mixed>>|null $machines
     */
    public static function syncTaskAssets(int $taskId, array $org, string $cveId, ?array $machines = null): int
    {
        if ($taskId <= 0) {
            return 0;
        }

        if ($machines === null) {
            $machines = [];
            $tenantId = self::tenantId($org);
            if ($tenantId > 0) {
                foreach (Database::fetchAll(
                    "SELECT m.id AS machine_id, m.computer_dns_name, m.os_platform, m.os_version, m.exposure_level
                     FROM vulnerabilities v
                     JOIN machines m ON m.id = v.machine_id
                     WHERE v.tenant_id = ? AND v.cve_id = ?
                     GROUP BY m.id
                     ORDER BY m.exposure_level DESC, m.computer_dns_name
                     LIMIT 200",
                    [$tenantId, $cveId]
                ) as $machine) {
                    $machines[] = [
                        'machine_id' => (int)$machine['machine_id'],
                        'name'       => (string)($machine['computer_dns_name'] ?? ''),
                        'os'         => trim((string)($machine['os_platform'] ?? '') . ' ' . (string)($machine['os_version'] ?? '')),
                        'exposure'   => (string)($machine['exposure_level'] ?? ''),
                    ];
                }
            }
        }

        $clean = [];
        foreach ($machines as $machine) {
            $name = trim((string)($machine['name'] ?? ''));
            if ($name === '') {
                continue;
            }
            $clean[] = [
                'machine_id' => isset($machine['machine_id']) && (int)$machine['machine_id'] > 0
                    ? (int)$machine['machine_id']
                    : null,
                'name'       => truncate($name, 200),
                'os'         => truncate((string)($machine['os'] ?? ''), 200),
                'exposure'   => truncate((string)($machine['exposure'] ?? ''), 80),
            ];
            if (count($clean) >= 200) {
                break;
            }
        }
        if ($clean === []) {
            return 0;
        }

        foreach ($clean as $asset) {
            $notes = [];
            if ($asset['os'] !== '') {
                $notes[] = 'SO: ' . $asset['os'];
            }
            if ($asset['exposure'] !== '') {
                $notes[] = 'Exposición: ' . $asset['exposure'];
            }
            Database::query(
                "INSERT OR IGNORE INTO remediation_task_assets
                 (task_id, machine_id, asset_name, asset_type, notes)
                 VALUES (?, ?, ?, 'equipo', ?)",
                [$taskId, $asset['machine_id'], $asset['name'], $notes !== [] ? implode(' · ', $notes) : null]
            );
            Database::query(
                "UPDATE remediation_task_assets SET machine_id = COALESCE(?, machine_id), notes = COALESCE(?, notes), updated_at = datetime('now')
                 WHERE task_id = ? AND asset_name = ?",
                [$asset['machine_id'], $notes !== [] ? implode(' · ', $notes) : null, $taskId, $asset['name']]
            );
        }

        $legacy = [];
        foreach ($clean as $asset) {
            $legacy[] = [
                'name'     => $asset['name'],
                'os'       => $asset['os'],
                'exposure' => $asset['exposure'],
            ];
        }
        $current = Database::fetchOne("SELECT machine_count FROM remediation_tasks WHERE id = ?", [$taskId]);
        $totalMachines = max((int)($current['machine_count'] ?? 0), count($legacy));
        Database::update(
            "UPDATE remediation_tasks
             SET machine_count = ?, machines_json = ?, updated_at = datetime('now')
             WHERE id = ?",
            [$totalMachines, json_encode($legacy, JSON_UNESCAPED_UNICODE), $taskId]
        );

        return count($legacy);
    }

    /** @return array<string,string> cve_id => state */
    private static function marks(int $orgId): array
    {
        $out = [];
        foreach (Database::fetchAll(
            "SELECT cve_id, state FROM remediation_queue_marks WHERE org_id = ?",
            [$orgId]
        ) as $row) {
            $out[(string)$row['cve_id']] = (string)$row['state'];
        }
        return $out;
    }

    /**
     * @param string[] $cveIds
     * @return array<string,true>
     */
    private static function kevSet(array $cveIds): array
    {
        if ($cveIds === []) {
            return [];
        }
        try {
            $rows = CveDatabase::fetchAll(
                "SELECT cve_id FROM cve_kev WHERE cve_id IN (" . implode(',', array_fill(0, count($cveIds), '?')) . ")",
                $cveIds
            );
        } catch (Throwable $e) {
            return [];
        }
        $out = [];
        foreach ($rows as $row) {
            $out[(string)$row['cve_id']] = true;
        }
        return $out;
    }
}
