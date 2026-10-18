<?php
/**
 * CveReportSplit — separa un informe agrupado en un informe por CVE.
 *
 * Se usa en dos sitios:
 * - migración automática al actualizar (solo informes sin Defender);
 * - acción manual «Separar» (también para informes de Defender).
 *
 * Conserva el análisis por CVE ya generado. El informe original se archiva.
 */

declare(strict_types=1);

class CveReportSplit
{
    /**
     * Separa los informes agrupados antiguos que no son de Defender.
     * Solo procesa estados terminados; los pendientes/en curso se dejan para
     * una conexión posterior.
     */
    public static function splitLegacyReports(): int
    {
        $rows = CveDatabase::fetchAll(
            "SELECT id, cve_ids, status
             FROM cve_ai_reports
             WHERE archived = 0
               AND status NOT IN ('pending', 'running')
               AND (defender_json IS NULL OR defender_json = '')
             ORDER BY id ASC"
        );

        $split = 0;
        foreach ($rows as $row) {
            $ids = self::decodeCveIds((string)($row['cve_ids'] ?? ''));
            if (count($ids) <= 1) {
                continue;
            }
            try {
                self::splitReport((int)$row['id']);
                $split++;
            } catch (Throwable $e) {
                if (function_exists('app_log')) {
                    app_log('error', 'cve_ai', 'No se pudo separar un informe antiguo', [
                        'id'    => (int)$row['id'],
                        'error' => $e->getMessage(),
                    ]);
                }
            }
        }

        return $split;
    }

    /**
     * Separa un informe concreto. Devuelve los IDs creados y cuántos quedan
     * pendientes de generar.
     *
     * @return array{report_ids:array<int,int>,pending:int}
     */
    public static function splitReport(int $reportId, bool $archive = true): array
    {
        if ($reportId <= 0) {
            throw new InvalidArgumentException('Informe no válido.');
        }

        $row = CveDatabase::fetchOne("SELECT * FROM cve_ai_reports WHERE id = ?", [$reportId]);
        if ($row === null) {
            throw new InvalidArgumentException('Informe no encontrado.');
        }
        if ((int)($row['archived'] ?? 0) === 1) {
            throw new InvalidArgumentException('El informe ya está archivado.');
        }

        $cveIds = self::decodeCveIds((string)($row['cve_ids'] ?? ''));
        if (count($cveIds) <= 1) {
            throw new InvalidArgumentException('El informe ya tiene un solo CVE.');
        }
        if ((string)($row['status'] ?? '') === 'running') {
            throw new InvalidArgumentException('Espera a que el informe termine antes de separarlo.');
        }

        $items = [];
        foreach (CveDatabase::fetchAll(
            "SELECT * FROM cve_ai_report_items WHERE report_id = ? ORDER BY position, id",
            [$reportId]
        ) as $item) {
            $items[strtoupper((string)$item['cve_id'])] = $item;
        }

        $dataMap = [];
        $decodedData = json_decode((string)($row['data_json'] ?? ''), true);
        if (is_array($decodedData)) {
            foreach ($decodedData as $dataItem) {
                if (is_array($dataItem) && !empty($dataItem['cve_id'])) {
                    $dataMap[strtoupper((string)$dataItem['cve_id'])] = $dataItem;
                }
            }
        }

        $defender = null;
        if (!empty($row['defender_json'])) {
            $decodedDefender = json_decode((string)$row['defender_json'], true);
            if (is_array($decodedDefender)) {
                $defender = $decodedDefender;
            }
        }

        $noAi = !empty($row['no_ai']);
        $baseTime = (string)($row['created_at'] ?? '');
        $titleDate = $baseTime !== '' ? date('d/m/Y H:i', strtotime($baseTime) ?: time()) : date('d/m/Y H:i');

        $createdIds = [];
        $pending = 0;

        CveDatabase::transaction(function (PDO $db) use (
            $row, $reportId, $cveIds, $items, $dataMap, $defender, $noAi, $baseTime, $titleDate, $archive, &$createdIds, &$pending
        ): void {
            $insertReport = $db->prepare(
                "INSERT INTO cve_ai_reports
                 (cve_ids, title, status, data_json, content_text, ai_text, ai_profile_id, ai_model,
                  ai_error, ai_duration_ms, defender_json, token, generated_by, no_ai, revision,
                  archived, group_id, mode, tags, processed_items, total_items, started_at,
                  updated_at, created_at, finished_at)
                 VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 1, ?, datetime('now'), ?, ?)"
            );
            $insertItem = $db->prepare(
                "INSERT INTO cve_ai_report_items
                 (report_id, cve_id, position, tags, group_id, status, ai_text, sections_json,
                  ai_model, ai_error, started_at, finished_at, created_at, updated_at)
                 VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))"
            );

            foreach ($cveIds as $cveId) {
                $item = $items[$cveId] ?? null;
                $dataItem = $dataMap[$cveId] ?? null;
                $itemStatus = (string)($item['status'] ?? '');
                $aiText = trim((string)($item['ai_text'] ?? ''));
                $sectionsJson = (string)($item['sections_json'] ?? '');
                $sections = $sectionsJson !== '' ? json_decode($sectionsJson, true) : [];
                $hasContent = $aiText !== '' || (is_array($sections) && $sections !== []);

                if ($hasContent && is_array($dataItem)) {
                    $status = 'done';
                } elseif ($noAi) {
                    $status = 'done';
                } elseif ($itemStatus === 'error') {
                    $status = 'error';
                } else {
                    $status = 'pending';
                    $pending++;
                }

                if ($status !== 'done') {
                    $aiText = '';
                }
                if ($status === 'done' && !is_array($dataItem)) {
                    // Sin datos del catálogo no se puede reconstruir el cuerpo.
                    $status = 'pending';
                    $pending++;
                    $aiText = '';
                }

                $token = $status === 'pending' ? bin2hex(random_bytes(24)) : null;
                $groupId = $item !== null && array_key_exists('group_id', $item) && $item['group_id'] !== null
                    ? (int)$item['group_id']
                    : ((int)($row['group_id'] ?? 0) ?: null);
                $itemTags = (string)($item['tags'] ?? '');
                if (trim($itemTags) === '') {
                    $itemTags = (string)($row['tags'] ?? '');
                }
                $itemModel = (string)($item['ai_model'] ?? '');
                if ($itemModel === '') {
                    $itemModel = (string)($row['ai_model'] ?? '');
                }
                $itemError = $status === 'error' ? (string)($item['ai_error'] ?? $row['ai_error'] ?? '') : null;
                $itemStatusOut = $status === 'done' ? ($noAi ? 'skipped' : 'done') : $status;
                $dataJson = $status === 'done' && is_array($dataItem)
                    ? json_encode([$dataItem], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)
                    : null;
                $defenderJson = self::filterDefender($defender, $cveId);
                $title = 'Informe CVE IA · ' . $cveId . ' · ' . $titleDate;
                $processedItems = $status === 'done' ? 1 : 0;
                $startedAt = $status === 'done' ? ($row['started_at'] ?? $row['created_at'] ?? null) : null;
                $finishedAt = $status === 'done' ? ($row['finished_at'] ?? $row['created_at'] ?? null) : null;
                $createdAt = $baseTime !== '' ? $baseTime : date('Y-m-d H:i:s');

                $insertReport->execute([
                    json_encode([$cveId], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                    $title,
                    $status,
                    $dataJson,
                    $status === 'done' && $aiText !== '' ? $aiText : null,
                    (int)($row['ai_profile_id'] ?? 0) ?: null,
                    $itemModel !== '' ? $itemModel : null,
                    $itemError,
                    $defenderJson,
                    $token,
                    (int)($row['generated_by'] ?? 0) ?: null,
                    $noAi ? 1 : 0,
                    (int)($row['revision'] ?? 1),
                    $groupId,
                    (string)($row['mode'] ?? 'extended'),
                    $itemTags !== '' ? $itemTags : null,
                    $processedItems,
                    $startedAt,
                    $createdAt,
                    $finishedAt,
                ]);
                $newId = (int)$db->lastInsertId();
                $createdIds[] = $newId;

                $insertItem->execute([
                    $newId,
                    $cveId,
                    $itemTags !== '' ? $itemTags : null,
                    $groupId,
                    $itemStatusOut,
                    $status === 'done' && $aiText !== '' ? $aiText : null,
                    $status === 'done' && is_array($sections) && $sections !== []
                        ? json_encode($sections, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)
                        : null,
                    $itemModel !== '' ? $itemModel : null,
                    $itemError,
                    $startedAt,
                    $finishedAt,
                ]);
            }

            if ($archive) {
                $db->prepare(
                    "UPDATE cve_ai_reports
                     SET archived = 1,
                         token = NULL,
                         status = CASE WHEN status = 'pending' THEN 'canceled' ELSE status END,
                         updated_at = datetime('now')
                     WHERE id = ?"
                )->execute([$reportId]);
            }
        });

        if (function_exists('log_activity')) {
            try {
                log_activity('cve.ai_report_split', [
                    'report_id' => $reportId,
                    'created'   => count($createdIds),
                    'pending'   => $pending,
                ]);
            } catch (Throwable $e) {
                // El registro de actividad no debe romper la separación.
            }
        }

        return ['report_ids' => $createdIds, 'pending' => $pending];
    }

    /**
     * @return array<int,string>
     */
    private static function decodeCveIds(string $value): array
    {
        $decoded = json_decode($value, true);
        if (!is_array($decoded)) {
            $decoded = preg_split('/[\s,;]+/', $value) ?: [];
        }
        $out = [];
        foreach ($decoded as $id) {
            if (!is_scalar($id)) {
                continue;
            }
            $cveId = strtoupper(trim((string)$id));
            if (preg_match('/^CVE-\d{4}-\d{4,}$/', $cveId)) {
                $out[$cveId] = true;
            }
        }
        return array_keys($out);
    }

    private static function filterDefender(?array $defender, string $cveId): ?string
    {
        if ($defender === null) {
            return null;
        }
        if (isset($defender['cves']) && is_array($defender['cves'])) {
            $defender['cves'] = [
                $cveId => $defender['cves'][$cveId] ?? [
                    'machine_total'    => 0,
                    'exposed_machines' => 0,
                    'public_exploit'   => false,
                    'exploit_verified' => false,
                    'products'         => [],
                    'machines'         => [],
                    'tenants'          => [],
                ],
            ];
        }
        $json = json_encode($defender, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        return $json !== false ? $json : null;
    }
}
