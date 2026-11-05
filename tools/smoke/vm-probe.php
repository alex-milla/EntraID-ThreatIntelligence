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
                "SELECT id, kind, source, comment, reference, username, pinned
                 FROM vm_case_evidence WHERE case_id = ? ORDER BY id",
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

    case 'seed-assignment-raw':
        // Igual que seed-assignment pero SIN fila en el catálogo (CVE sin datos).
        $companyId = (int)($argv[2] ?? 0);
        $cveIds = array_slice($argv, 3);
        $seeded = [];
        foreach ($cveIds as $cveId) {
            $cveId = strtoupper(trim((string)$cveId));
            if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId) || $companyId <= 0) {
                continue;
            }
            $reportId = CveDatabase::insert(
                "INSERT INTO cve_ai_reports (cve_ids, title, status, no_ai, group_id, total_items)
                 VALUES (?, 'Fixture E2E sin catálogo', 'done', 1, ?, 1)",
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

    case 'seed-remediation-plan':
        // Solo para el E2E: crea organización vinculada + tarea con plan.
        $companyId = (int)($argv[2] ?? 0);
        $cveId = strtoupper(trim((string)($argv[3] ?? '')));
        if ($companyId <= 0 || !preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId)) {
            fwrite(STDERR, "Parámetros inválidos.\n");
            exit(1);
        }
        Database::query(
            "INSERT OR IGNORE INTO remediation_orgs (name, kind, software_group_id, created_by)
             VALUES ('E2E Remediation', 'manual', ?, 0)",
            [$companyId]
        );
        Database::query(
            "UPDATE remediation_orgs SET software_group_id = ? WHERE name = 'E2E Remediation'",
            [$companyId]
        );
        $org = Database::fetchOne("SELECT id FROM remediation_orgs WHERE name = 'E2E Remediation'");
        $orgId = (int)($org['id'] ?? 0);
        Database::query(
            "INSERT INTO remediation_tasks (org_id, cve_id, title, status, plan, source)
             VALUES (?, ?, 'Fixture plan E2E', 'open', ?, 'manual')
             ON CONFLICT(org_id, cve_id) DO UPDATE SET
                 plan = excluded.plan, status = 'open', updated_at = datetime('now')",
            [$orgId, $cveId, "# Plan de remediación E2E\n\n1. Paso 1: aplicar parche.\n2. Verificar versión."]
        );
        $task = Database::fetchOne(
            "SELECT id FROM remediation_tasks WHERE org_id = ? AND cve_id = ?",
            [$orgId, $cveId]
        );
        $out = ['org_id' => $orgId, 'task_id' => (int)($task['id'] ?? 0), 'cve_id' => $cveId];
        break;

    case 'seed-remediation-chat':
        // Chat de CVE vinculado a la organización de la empresa (para E2E).
        $companyId = (int)($argv[2] ?? 0);
        $cveId = strtoupper(trim((string)($argv[3] ?? '')));
        if ($companyId <= 0 || !preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId)) {
            fwrite(STDERR, "Parámetros inválidos.\n");
            exit(1);
        }
        Database::query(
            "INSERT OR IGNORE INTO remediation_orgs (name, kind, software_group_id, created_by)
             VALUES ('E2E Remediation', 'manual', ?, 0)",
            [$companyId]
        );
        $org = Database::fetchOne("SELECT id FROM remediation_orgs WHERE name = 'E2E Remediation'");
        $orgId = (int)($org['id'] ?? 0);
        $chatId = Database::insert(
            "INSERT INTO remediation_chats (org_id, user_id, context_type, context_ref, title)
             VALUES (?, 0, 'cve', ?, 'Fixture chat E2E')",
            [$orgId, $cveId]
        );
        Database::insert(
            "INSERT INTO remediation_messages (chat_id, role, content, model)
             VALUES (?, 'assistant', ?, 'e2e')",
            [$chatId, "# Respuesta E2E\n\nPaso AUTO: contenido sin guardar como plan."]
        );
        $out = ['org_id' => $orgId, 'chat_id' => $chatId, 'cve_id' => $cveId];
        break;

    case 'seed-plan-checklist':
        // Solo para el E2E: añade elementos marcables al plan ya sembrado.
        $companyId = (int)($argv[2] ?? 0);
        $cveId = strtoupper(trim((string)($argv[3] ?? '')));
        $org = Database::fetchOne("SELECT id FROM remediation_orgs WHERE name = 'E2E Remediation'");
        $task = $org !== null
            ? Database::fetchOne(
                "SELECT id, plan FROM remediation_tasks WHERE org_id = ? AND cve_id = ?",
                [(int)$org['id'], $cveId]
            )
            : null;
        if ($task === null || $companyId <= 0) {
            fwrite(STDERR, "No hay tarea E2E para ese CVE.\n");
            exit(1);
        }
        $plan = rtrim((string)$task['plan'])
            . "\n\n## Checklist E2E\n\n- [ ] Verificar versión corregida\n- [ ] Confirmar reinicio del servicio\n";
        Database::query(
            "UPDATE remediation_tasks SET plan = ?, updated_at = datetime('now') WHERE id = ?",
            [$plan, (int)$task['id']]
        );
        $out = ['task_id' => (int)$task['id'], 'cve_id' => $cveId];
        break;

    case 'findings':
        $caseId = (int)($argv[2] ?? 0);
        $out = [
            'findings' => CveDatabase::fetchAll(
                "SELECT id, asset_or_service, environment, product, product_version,
                        owner_name, source, status, first_detected_at, last_detected_at
                 FROM vm_findings WHERE case_id = ? ORDER BY id",
                [$caseId]
            ),
        ];
        break;

    default:
        fwrite(STDERR, "Comando desconocido.\n");
        exit(1);
}

echo json_encode($out, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
