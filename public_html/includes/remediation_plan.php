<?php
/**
 * RemediationPlan — creación y anexado de planes de remediación (v0.3.8).
 *
 * Centraliza la lógica que antes vivía en el handler savePlan, para poder
 * guardar un plan tanto desde el asistente como desde el caso de Seguimiento.
 * Un plan siempre vive en remediation_tasks.plan (BD principal).
 */

declare(strict_types=1);

final class RemediationPlan
{
    /** Tarea de una organización + CVE, si existe. */
    public static function findTask(int $orgId, string $cveId): ?array
    {
        if ($orgId <= 0 || $cveId === '') {
            return null;
        }
        return Database::fetchOne(
            "SELECT * FROM remediation_tasks WHERE org_id = ? AND cve_id = ?",
            [$orgId, $cveId]
        );
    }

    /**
     * Devuelve el id de la tarea org+CVE, creándola si no existe.
     * Los datos técnicos salen del catálogo; si no hay catálogo quedan nulos.
     */
    public static function ensureTask(int $orgId, string $cveId, int $userId = 0): int
    {
        $task = self::findTask($orgId, $cveId);
        if ($task !== null) {
            return (int)$task['id'];
        }

        $catalog = [];
        $kev = null;
        $epss = null;
        try {
            if (class_exists('CveDatabase')) {
                $catalog = CveDatabase::fetchOne(
                    "SELECT severity, cvss_v3_score FROM cve_catalog WHERE cve_id = ?",
                    [$cveId]
                ) ?? [];
                $kev = CveDatabase::fetchOne(
                    "SELECT cve_id FROM cve_kev WHERE cve_id = ?",
                    [$cveId]
                );
                $epssRow = CveDatabase::fetchOne(
                    "SELECT epss FROM cve_epss WHERE cve_id = ?",
                    [$cveId]
                );
                $epss = $epssRow !== null && $epssRow['epss'] !== null ? (float)$epssRow['epss'] : null;
            }
        } catch (Throwable $e) {
            $catalog = [];
            $kev = null;
            $epss = null;
        }

        return Database::insert(
            "INSERT INTO remediation_tasks
             (org_id, cve_id, title, severity, cvss, epss, kev, status, source, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'open', 'assistant', ?)",
            [
                $orgId,
                $cveId,
                'Remediación ' . $cveId,
                $catalog['severity'] ?? null,
                $catalog['cvss_v3_score'] ?? null,
                $epss,
                $kev !== null ? 1 : 0,
                $userId > 0 ? $userId : null,
            ]
        );
    }

    /** Anexa contenido al plan de una tarea existente (separador ---). */
    public static function append(int $taskId, string $content): void
    {
        $content = trim($content);
        if ($taskId <= 0 || $content === '') {
            return;
        }
        $task = Database::fetchOne(
            "SELECT id, plan FROM remediation_tasks WHERE id = ?",
            [$taskId]
        );
        if ($task === null) {
            return;
        }
        $plan = trim((string)($task['plan'] ?? ''));
        $plan = $plan !== '' ? $plan . "\n\n---\n\n" . $content : $content;

        Database::update(
            "UPDATE remediation_tasks SET plan = ?, updated_at = datetime('now') WHERE id = ?",
            [truncate($plan, 20000), $taskId]
        );
    }

    /** Anexa al plan de org+CVE creando la tarea si falta. Devuelve el task id. */
    public static function appendForCve(int $orgId, string $cveId, string $content, int $userId = 0): int
    {
        if ($orgId <= 0 || $cveId === '' || trim($content) === '') {
            return 0;
        }
        $taskId = self::ensureTask($orgId, $cveId, $userId);
        self::append($taskId, $content);
        return $taskId;
    }
}
