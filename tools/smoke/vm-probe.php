<?php
/**
 * vm-probe.php — consultas de apoyo para el E2E de seguimiento (v0.3.0).
 *
 * Solo lectura. Uso interno desde tools/smoke/e2e-vm.ps1.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$cmd = (string)($argv[1] ?? '');
$out = [];

switch ($cmd) {
    case 'company':
        $name = (string)($argv[2] ?? '');
        $row = CveDatabase::fetchOne(
            "SELECT id FROM software_groups WHERE name = ? AND kind = 'company' ORDER BY id DESC LIMIT 1",
            [$name]
        );
        $out = ['id' => (int)($row['id'] ?? 0)];
        break;

    case 'imports':
        $companyId = (int)($argv[2] ?? 0);
        $out = [
            'imports' => CveDatabase::fetchAll(
                "SELECT id, status, rows_imported, rows_created, rows_matched, created_at
                 FROM cve_tvm_imports WHERE company_id = ? ORDER BY id DESC",
                [$companyId]
            ),
        ];
        break;

    case 'cases':
        $companyId = (int)($argv[2] ?? 0);
        $out = [
            'cases' => CveDatabase::fetchAll(
                "SELECT id, cve_id, status, priority, due_date, first_seen_at, last_seen_at,
                        last_seen_import_id, assignee_name, verification_kind, source
                 FROM vm_cases WHERE group_id = ? ORDER BY id",
                [$companyId]
            ),
        ];
        break;

    case 'case':
        $caseId = (int)($argv[2] ?? 0);
        $out = [
            'case' => CveDatabase::fetchOne("SELECT * FROM vm_cases WHERE id = ?", [$caseId]),
            'events' => CveDatabase::fetchAll(
                "SELECT event_type, old_value, new_value, comment FROM vm_case_events WHERE case_id = ? ORDER BY id",
                [$caseId]
            ),
            'evidence' => CveDatabase::fetchAll(
                "SELECT kind, source, comment, reference, username FROM vm_case_evidence WHERE case_id = ? ORDER BY id",
                [$caseId]
            ),
        ];
        break;

    case 'seed-assignment':
        // Solo para el E2E, que trabaja sobre copias temporales de la BD.
        $companyId = (int)($argv[2] ?? 0);
        $cveIds = array_slice($argv, 3);
        $seeded = [];
        foreach ($cveIds as $cveId) {
            $cveId = strtoupper(trim((string)$cveId));
            if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId) || $companyId <= 0) {
                continue;
            }
            CveDatabase::query(
                "INSERT OR IGNORE INTO cve_catalog
                 (cve_id, description, published_at, severity, cvss_v3_score, source_identifier)
                 VALUES (?, 'Fixture E2E de asignación', '2026-10-01', 'Critical', 9.8, 'e2e')",
                [$cveId]
            );
            $reportId = CveDatabase::insert(
                "INSERT INTO cve_ai_reports (cve_ids, title, status, no_ai, group_id, total_items)
                 VALUES (?, 'Fixture E2E', 'done', 1, ?, 1)",
                [$cveId, $companyId]
            );
            CveDatabase::query(
                "INSERT INTO cve_ai_report_items (report_id, cve_id, position, group_id, status)
                 VALUES (?, ?, 0, ?, 'done')",
                [$reportId, $cveId, $companyId]
            );
            $seeded[] = $cveId;
        }
        $out = ['seeded' => $seeded];
        break;

    default:
        fwrite(STDERR, "Comando desconocido.\n");
        exit(1);
}

echo json_encode($out, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
