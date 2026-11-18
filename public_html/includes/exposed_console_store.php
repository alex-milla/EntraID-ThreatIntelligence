<?php
/**
 * exposed_console_store.php — Consola de Equipos expuestos (v0.4.25.3).
 *
 * Una **única lista maestra** de vulnerabilidades del tenant en cve.sqlite
 * (`exposed_cves` con PK `cve_id`). Cada CSV que se sube se compara CVE a CVE
 * contra esa lista: lo nuevo se inserta, lo cambiado se actualiza y lo idéntico
 * se omite. Las subidas quedan como **historial de importaciones**
 * (`exposed_snapshots`), no como listas separadas.
 *
 * Sobre esa lista única funcionan los filtros tipo portal (Severity, Age,
 * Threats, Exposed devices, Status, Tags), los grupos de análisis y su plan de
 * actuación.
 *
 * Todo es aditivo: tablas `exposed_*` propias, sin tocar cve_tvm_imports (el
 * import por empresa del módulo CVE) ni el seguimiento vm_*.
 *
 * Puro respecto a la red: solo lee el CSV y la base local.
 */

declare(strict_types=1);

if (!class_exists('ExposedConsoleStore')) {
    final class ExposedConsoleStore
    {
        public const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

        public const AGE_BUCKETS = ['0-30', '30-60', '60-90', '90+'];

        public const THREATS = ['alert', 'exploit', 'known', 'verified', 'kev', 'kit'];

        public const TAGS = ['zero_day', 'no_security_update', 'security_update'];

        public const STATUSES = ['RemediationRequired', 'UnderException', 'NoActionRequired', 'PartialException'];

        public const SORTS = ['oldest', 'newest', 'machines', 'cvss', 'epss'];

        public const MACHINE_THRESHOLDS = [0, 10, 100, 500];

        public const PER_PAGE = 100;

        /** CVEs máximos que se pueden meter en un grupo de una vez. */
        public const MAX_GROUP_CVES = 2000;

        /* =================================================================
         * Límites de subida
         * ============================================================== */

        /**
         * Tope real de subida: el menor entre el límite propio y lo que permite
         * php.ini (upload_max_filesize y post_max_size). Si el servidor está en
         * 8 MB, la interfaz lo dice en vez de fallar con un CSRF críptico.
         */
        public static function maxUploadBytes(): int
        {
            $limit = CveTvmImport::CONSOLE_MAX_BYTES;
            foreach (['upload_max_filesize', 'post_max_size'] as $key) {
                $ini = self::iniBytes((string)ini_get($key));
                if ($ini > 0) {
                    $limit = min($limit, $ini);
                }
            }
            return $limit;
        }

        /** Convierte «2M»/«8M»/«512K» de php.ini a bytes. */
        public static function iniBytes(string $value): int
        {
            $value = trim($value);
            if ($value === '') {
                return 0;
            }
            $unit = strtolower(substr($value, -1));
            $number = (float)$value;
            return (int)match ($unit) {
                'g' => $number * 1073741824,
                'm' => $number * 1048576,
                'k' => $number * 1024,
                default => $number,
            };
        }

        /* =================================================================
         * Ingesta incremental en la lista maestra
         * ============================================================== */

        /**
         * Importa un CSV en la lista maestra del tenant.
         *
         * Compara CVE a CVE con una huella estable de los datos de Defender:
         *   · no está            → INSERT (nuevo)
         *   · está y cambió      → UPDATE (actualizado)
         *   · está idéntico      → se omite (sin cambios); solo se refresca la
         *                          antigüedad y `last_seen_at`, porque el tiempo
         *                          transcurrido no es un cambio de información.
         *
         * El cuarto argumento se acepta por compatibilidad con v0.4.25.2 y se
         * ignora: ya no hay snapshots separados.
         *
         * @return array{ok:bool,error:string,import_id:int,rows:int,skipped:int,
         *               inserted:int,updated:int,unchanged:int,total:int,
         *               truncated:bool,range:string}
         */
        public static function importCsv(string $csv, string $filename, int $userId = 0, int $ignoredSnapshotId = 0): array
        {
            $out = [
                'ok'          => false,
                'error'       => '',
                'import_id'   => 0,
                'rows'        => 0,
                'skipped'     => 0,
                'inserted'    => 0,
                'updated'     => 0,
                'unchanged'   => 0,
                'total'       => 0,
                'truncated'   => false,
                'range'       => '',
            ];

            if (trim($csv) === '') {
                $out['error'] = 'El fichero CSV está vacío.';
                return $out;
            }
            if (strlen($csv) > CveTvmImport::CONSOLE_MAX_BYTES) {
                $out['error'] = 'El CSV supera el límite de '
                    . self::formatBytes(CveTvmImport::CONSOLE_MAX_BYTES) . '.';
                return $out;
            }

            $parsed = CveTvmImport::parseCsv(
                $csv,
                CveTvmImport::CONSOLE_MAX_ROWS,
                ['software_pairs' => false]
            );

            if ($parsed['rows'] === []) {
                $out['error'] = 'No se ha encontrado ningún CVE válido. '
                    . 'Comprueba que es el export «Vulnerabilities Export» de Defender TVM.';
                return $out;
            }

            $db = CveDatabase::getInstance();
            try {
                $db->beginTransaction();

                $importId = CveDatabase::insert(
                    "INSERT INTO exposed_snapshots
                     (filename, export_date, bytes, rows_total, rows_imported, rows_skipped, imports, generated_by, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?, 1, ?, datetime('now'))",
                    [
                        $filename !== '' ? $filename : 'export-tvm.csv',
                        (string)($parsed['export_date'] ?? ''),
                        strlen($csv),
                        (int)($parsed['total'] ?? count($parsed['rows'])),
                        count($parsed['rows']),
                        (int)($parsed['skipped'] ?? 0),
                        $userId > 0 ? $userId : null,
                    ]
                );

                // Huellas existentes: una sola lectura de toda la lista maestra.
                $existing = [];
                $rows = CveDatabase::fetchAll(
                    "SELECT cve_id, fingerprint, age_days FROM exposed_cves"
                );
                foreach ($rows as $row) {
                    $existing[(string)$row['cve_id']] = $row;
                }

                $insertStmt = $db->prepare(
                    "INSERT INTO exposed_cves
                     (cve_id, severity, cvss, epss, age_days, published_at,
                      first_detected_at, updated_at, has_exploit, has_known_threats, has_alerts,
                      exposed_machines, tvm_status, related_software, software_labels,
                      software_tokens, software_total, zero_day, no_security_update,
                      security_update, exploit_kit, exploit_verified, description,
                      fingerprint, first_seen_at, last_seen_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))"
                );

                $updateStmt = $db->prepare(
                    "UPDATE exposed_cves
                     SET severity = ?, cvss = ?, epss = ?, age_days = ?, published_at = ?,
                         first_detected_at = ?, updated_at = ?, has_exploit = ?,
                         has_known_threats = ?, has_alerts = ?, exposed_machines = ?,
                         tvm_status = ?, related_software = ?, software_labels = ?,
                         software_tokens = ?, software_total = ?, zero_day = ?,
                         no_security_update = ?, security_update = ?, exploit_kit = ?,
                         exploit_verified = ?, description = ?, fingerprint = ?,
                         last_seen_at = datetime('now')
                     WHERE cve_id = ?"
                );

                $seenStmt = $db->prepare(
                    "UPDATE exposed_cves SET age_days = ?, last_seen_at = datetime('now') WHERE cve_id = ?"
                );

                $inserted = 0;
                $updated = 0;
                $unchanged = 0;
                $minCve = null;
                $maxCve = null;
                $minAge = null;
                $maxAge = null;

                foreach ($parsed['rows'] as $row) {
                    $cveId = (string)$row['cve_id'];
                    $payload = self::rowPayload($row);
                    $fingerprint = self::fingerprintRow($payload);

                    $minCve = $minCve === null || strcmp($cveId, $minCve) < 0 ? $cveId : $minCve;
                    $maxCve = $maxCve === null || strcmp($cveId, $maxCve) > 0 ? $cveId : $maxCve;
                    $age = (int)($row['age_days'] ?? 0);
                    $minAge = $minAge === null ? $age : min($minAge, $age);
                    $maxAge = $maxAge === null ? $age : max($maxAge, $age);

                    if (!isset($existing[$cveId])) {
                        $insertStmt->execute([
                            $cveId,
                            $payload['severity'],
                            $payload['cvss'],
                            $payload['epss'],
                            $age,
                            $payload['published_at'],
                            $payload['first_detected_at'],
                            $payload['updated_at'],
                            $payload['has_exploit'],
                            $payload['has_known_threats'],
                            $payload['has_alerts'],
                            $payload['exposed_machines'],
                            $payload['tvm_status'],
                            $payload['related_software'],
                            $payload['software_labels'],
                            $payload['software_tokens'],
                            $payload['software_total'],
                            $payload['zero_day'],
                            $payload['no_security_update'],
                            $payload['security_update'],
                            $payload['exploit_kit'],
                            $payload['exploit_verified'],
                            $payload['description'],
                            $fingerprint,
                        ]);
                        $inserted++;
                        continue;
                    }

                    $sameFingerprint = (string)($existing[$cveId]['fingerprint'] ?? '') === $fingerprint;
                    if ($sameFingerprint) {
                        $unchanged++;
                        $seenStmt->execute([$age, $cveId]);
                        continue;
                    }

                    $updateStmt->execute([
                        $payload['severity'],
                        $payload['cvss'],
                        $payload['epss'],
                        $age,
                        $payload['published_at'],
                        $payload['first_detected_at'],
                        $payload['updated_at'],
                        $payload['has_exploit'],
                        $payload['has_known_threats'],
                        $payload['has_alerts'],
                        $payload['exposed_machines'],
                        $payload['tvm_status'],
                        $payload['related_software'],
                        $payload['software_labels'],
                        $payload['software_tokens'],
                        $payload['software_total'],
                        $payload['zero_day'],
                        $payload['no_security_update'],
                        $payload['security_update'],
                        $payload['exploit_kit'],
                        $payload['exploit_verified'],
                        $payload['description'],
                        $fingerprint,
                        $cveId,
                    ]);
                    $updated++;
                }

                $total = CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM exposed_cves");

                CveDatabase::query(
                    "UPDATE exposed_snapshots
                     SET rows_inserted = ?, rows_updated = ?, rows_unchanged = ?
                     WHERE id = ?",
                    [$inserted, $updated, $unchanged, $importId]
                );

                $db->commit();

                $fileRows = (int)($parsed['total'] ?? count($parsed['rows']));
                $out['ok'] = true;
                $out['import_id'] = $importId;
                $out['rows'] = count($parsed['rows']);
                $out['skipped'] = (int)($parsed['skipped'] ?? 0);
                $out['inserted'] = $inserted;
                $out['updated'] = $updated;
                $out['unchanged'] = $unchanged;
                $out['total'] = (int)($total['c'] ?? 0);
                // Defender corta el export web en 6.000 filas: se avisa con el
                // rango cubierto para que se pueda completar con otro tramo.
                $out['truncated'] = $fileRows >= 6000;
                if ($out['truncated'] && $minCve !== null && $maxCve !== null) {
                    $out['range'] = $minCve . ' – ' . $maxCve
                        . ' · edades ' . (int)$minAge . '–' . (int)$maxAge . ' días';
                }
                return $out;
            } catch (Throwable $e) {
                if ($db->inTransaction()) {
                    $db->rollBack();
                }
                $out['error'] = 'No se pudo guardar el CSV: ' . $e->getMessage();
                return $out;
            }
        }

        /**
         * Campos de una fila del CSV tal y como se guardan en `exposed_cves`.
         *
         * @param array<string,mixed> $row
         * @return array<string,mixed>
         */
        private static function rowPayload(array $row): array
        {
            $tags = is_array($row['tags'] ?? null) ? $row['tags'] : [];
            $labels = is_array($row['software_labels'] ?? null) ? $row['software_labels'] : [];

            return [
                'severity'          => (string)($row['severity'] ?? ''),
                'cvss'              => $row['cvss'] !== null ? (float)$row['cvss'] : null,
                'epss'              => $row['epss'] !== null ? (float)$row['epss'] : null,
                'published_at'      => (string)($row['published_at'] ?? ''),
                'first_detected_at' => (string)($row['first_detected_at'] ?? ''),
                'updated_at'        => (string)($row['updated_at'] ?? ''),
                'has_exploit'       => (int)($row['has_exploit'] ?? 0),
                'has_known_threats' => (int)($row['has_known_threats'] ?? 0),
                'has_alerts'        => (int)($row['has_alerts'] ?? 0),
                'exposed_machines'  => (int)($row['exposed_machines'] ?? 0),
                'tvm_status'        => (string)($row['tvm_status'] ?? ''),
                'related_software'  => self::clip((string)($row['related_software'] ?? ''), 20000),
                'software_labels'   => implode(', ', array_slice(array_map('strval', $labels), 0, 6)),
                'software_tokens'   => (string)($row['software_tokens'] ?? ''),
                'software_total'    => (int)($row['software_total'] ?? 0),
                'zero_day'          => isset($tags['zero_day']) ? 1 : 0,
                'no_security_update' => isset($tags['no_security_update']) ? 1 : 0,
                'security_update'   => isset($tags['security_update']) ? 1 : 0,
                'exploit_kit'       => isset($tags['exploit_kit']) ? 1 : 0,
                'exploit_verified'  => isset($tags['exploit_verified']) ? 1 : 0,
                'description'       => self::clip((string)($row['description'] ?? ''), 8000),
            ];
        }

        /**
         * Huella estable de un CVE. Excluye `age_days` (tiempo transcurrido) para
         * que una reimportación idéntica no se cuente como cambio.
         *
         * @param array<string,mixed> $payload
         */
        private static function fingerprintRow(array $payload): string
        {
            $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            return sha1(is_string($json) ? $json : serialize($payload));
        }

        /* =================================================================
         * Historial de importaciones (antes «snapshots»)
         * ============================================================== */

        /**
         * Historial de CSV subidos, del más reciente al más antiguo.
         */
        public static function listSnapshots(int $limit = 25): array
        {
            return CveDatabase::fetchAll(
                "SELECT s.*
                 FROM exposed_snapshots s
                 ORDER BY s.created_at DESC, s.id DESC
                 LIMIT " . max(1, min(200, $limit))
            );
        }

        /** Alias semántico: el historial son importaciones, no snapshots. */
        public static function listImports(int $limit = 25): array
        {
            return self::listSnapshots($limit);
        }

        public static function getSnapshot(int $id): ?array
        {
            return $id > 0
                ? CveDatabase::fetchOne("SELECT * FROM exposed_snapshots WHERE id = ?", [$id])
                : null;
        }

        /** Última importación registrada (para la cabecera). */
        public static function latestSnapshot(): ?array
        {
            return CveDatabase::fetchOne(
                "SELECT * FROM exposed_snapshots ORDER BY created_at DESC, id DESC LIMIT 1"
            );
        }

        /**
         * Borra un registro del historial. **No toca las vulnerabilidades**: la
         * lista maestra es única y compartida por todas las importaciones.
         *
         * @return array{ok:bool,error:string}
         */
        public static function deleteSnapshot(int $id): array
        {
            if ($id <= 0) {
                return ['ok' => false, 'error' => 'Importación no válida.'];
            }
            try {
                CveDatabase::query("DELETE FROM exposed_snapshots WHERE id = ?", [$id]);
                return ['ok' => true, 'error' => ''];
            } catch (Throwable $e) {
                return ['ok' => false, 'error' => 'No se pudo borrar el registro: ' . $e->getMessage()];
            }
        }

        /**
         * Vacía la base de vulnerabilidades del tenant (y los grupos derivados).
         * Conserva el historial de importaciones.
         *
         * @return array{ok:bool,error:string,deleted:int}
         */
        public static function clearAll(): array
        {
            $db = CveDatabase::getInstance();
            try {
                $before = CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM exposed_cves");
                $db->beginTransaction();
                CveDatabase::query("DELETE FROM exposed_group_cves");
                CveDatabase::query("DELETE FROM exposed_group_plans");
                CveDatabase::query("DELETE FROM exposed_groups");
                CveDatabase::query("DELETE FROM exposed_cves");
                $db->commit();
                return ['ok' => true, 'error' => '', 'deleted' => (int)($before['c'] ?? 0)];
            } catch (Throwable $e) {
                if ($db->inTransaction()) {
                    $db->rollBack();
                }
                return ['ok' => false, 'error' => 'No se pudo vaciar la base: ' . $e->getMessage(), 'deleted' => 0];
            }
        }

        /* =================================================================
         * Filtros (mismos bloques que el portal de Defender)
         * ============================================================== */

        /**
         * Normaliza los filtros recibidos (GET o POST) y descarta valores raros.
         *
         * @param array<string,mixed> $src
         * @return array<string,mixed>
         */
        public static function filtersFromInput(array $src): array
        {
            $list = static function (string $key, array $allowed) use ($src): array {
                $raw = $src[$key] ?? [];
                if (is_string($raw)) {
                    $raw = [$raw];
                }
                if (!is_array($raw)) {
                    return [];
                }
                $out = [];
                foreach ($raw as $value) {
                    if (!is_scalar($value)) {
                        continue;
                    }
                    $value = (string)$value;
                    if (in_array($value, $allowed, true)) {
                        $out[$value] = true;
                    }
                }
                return array_keys($out);
            };

            $machines = (int)($src['machines'] ?? 0);
            if (!in_array($machines, self::MACHINE_THRESHOLDS, true)) {
                $machines = 0;
            }

            $sort = (string)($src['sort'] ?? 'oldest');
            if (!in_array($sort, self::SORTS, true)) {
                $sort = 'oldest';
            }

            $software = [];
            $rawSoftware = trim((string)($src['software'] ?? ''));
            if ($rawSoftware !== '') {
                foreach (preg_split('/\s+/', $rawSoftware) ?: [] as $word) {
                    $token = CveTvmImport::token((string)$word);
                    if ($token !== '' && strlen($token) >= 2 && count($software) < 3) {
                        $software[$token] = true;
                    }
                }
            }

            $q = strtoupper(trim((string)($src['q'] ?? '')));
            if ($q !== '' && preg_match('/^[A-Z0-9\-]+$/', $q) !== 1) {
                $q = '';
            }

            return [
                'severity' => $list('severity', self::SEVERITIES),
                'age'      => $list('age', self::AGE_BUCKETS),
                'threats'  => $list('threats', self::THREATS),
                'tags'     => $list('tags', self::TAGS),
                'status'   => $list('status', self::STATUSES),
                'machines' => $machines,
                // Tokens para el SQL (arrays) y texto original para la interfaz.
                // La vista NUNCA debe hacer (string) del array de tokens: PHP
                // devolvería «Array» y el formulario se autorellenaría con esa
                // palabra, dejando todos los filtros a cero (v0.4.25.1).
                'software' => array_keys($software),
                'software_text' => substr($rawSoftware, 0, 120),
                'q'        => substr($q, 0, 40),
                'sort'     => $sort,
            ];
        }

        /** Filtros serializables para la URL (sin sort). */
        public static function filtersToQuery(array $filters): array
        {
            $out = [];
            foreach (['severity', 'age', 'threats', 'tags', 'status'] as $key) {
                if (!empty($filters[$key])) {
                    $out[$key] = array_values((array)$filters[$key]);
                }
            }
            if ((int)($filters['machines'] ?? 0) > 0) {
                $out['machines'] = (int)$filters['machines'];
            }
            if (!empty($filters['software'])) {
                $out['software'] = is_array($filters['software'])
                    ? implode(' ', array_map('strval', $filters['software']))
                    : (string)$filters['software'];
            }
            if ((string)($filters['q'] ?? '') !== '') {
                $out['q'] = (string)$filters['q'];
            }
            return $out;
        }

        /**
         * WHERE sobre la lista maestra. OR dentro de cada bloque, AND entre
         * bloques (como el portal de Defender).
         *
         * @return array{0:string,1:array<int,mixed>}
         */
        public static function where(array $filters): array
        {
            $clauses = ['1 = 1'];
            $params = [];

            $severity = array_values(array_intersect((array)($filters['severity'] ?? []), self::SEVERITIES));
            if ($severity !== []) {
                $clauses[] = 'e.severity IN (' . implode(',', array_fill(0, count($severity), '?')) . ')';
                foreach ($severity as $value) {
                    $params[] = $value;
                }
            }

            $age = array_values(array_intersect((array)($filters['age'] ?? []), self::AGE_BUCKETS));
            if ($age !== []) {
                $ageSql = [];
                foreach ($age as $bucket) {
                    $ageSql[] = match ($bucket) {
                        '0-30'  => 'e.age_days BETWEEN 0 AND 30',
                        '30-60' => 'e.age_days > 30 AND e.age_days <= 60',
                        '60-90' => 'e.age_days > 60 AND e.age_days <= 90',
                        default => 'e.age_days > 90',
                    };
                }
                $clauses[] = '(' . implode(' OR ', $ageSql) . ')';
            }

            $threats = array_values(array_intersect((array)($filters['threats'] ?? []), self::THREATS));
            if ($threats !== []) {
                $threatSql = [];
                foreach ($threats as $threat) {
                    $threatSql[] = match ($threat) {
                        'alert'    => 'e.has_alerts = 1',
                        'exploit'  => 'e.has_exploit = 1',
                        'known'    => 'e.has_known_threats = 1',
                        'verified' => 'e.exploit_verified = 1',
                        'kit'      => 'e.exploit_kit = 1',
                        default    => 'EXISTS (SELECT 1 FROM cve_kev k WHERE k.cve_id = e.cve_id)',
                    };
                }
                $clauses[] = '(' . implode(' OR ', $threatSql) . ')';
            }

            $tags = array_values(array_intersect((array)($filters['tags'] ?? []), self::TAGS));
            if ($tags !== []) {
                $tagSql = [];
                foreach ($tags as $tag) {
                    $tagSql[] = match ($tag) {
                        'zero_day'           => 'e.zero_day = 1',
                        'no_security_update' => 'e.no_security_update = 1',
                        default              => 'e.security_update = 1',
                    };
                }
                $clauses[] = '(' . implode(' OR ', $tagSql) . ')';
            }

            $status = array_values(array_intersect((array)($filters['status'] ?? []), self::STATUSES));
            if ($status !== []) {
                $clauses[] = 'e.tvm_status IN (' . implode(',', array_fill(0, count($status), '?')) . ')';
                foreach ($status as $value) {
                    $params[] = $value;
                }
            }

            $machines = (int)($filters['machines'] ?? 0);
            if ($machines > 0) {
                $clauses[] = 'e.exposed_machines >= ?';
                $params[] = $machines;
            }

            foreach ((array)($filters['software'] ?? []) as $token) {
                $token = CveTvmImport::token((string)$token);
                if ($token === '') {
                    continue;
                }
                $clauses[] = 'e.software_tokens LIKE ?';
                $params[] = '%' . $token . '%';
            }

            $q = trim((string)($filters['q'] ?? ''));
            if ($q !== '') {
                $clauses[] = 'e.cve_id LIKE ?';
                $params[] = '%' . $q . '%';
            }

            return [' WHERE ' . implode(' AND ', $clauses), $params];
        }

        public static function orderBy(string $sort): string
        {
            return match ($sort) {
                'newest'   => 'e.age_days ASC, e.exposed_machines DESC, e.cve_id ASC',
                'machines' => 'e.exposed_machines DESC, e.age_days DESC, e.cve_id ASC',
                'cvss'     => 'e.cvss DESC, e.exposed_machines DESC, e.age_days DESC',
                'epss'     => 'e.epss DESC, e.exposed_machines DESC, e.age_days DESC',
                default    => 'e.age_days DESC, e.exposed_machines DESC, e.cve_id ASC',
            };
        }

        public static function count(array $filters): int
        {
            [$where, $params] = self::where($filters);
            $row = CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM exposed_cves e" . $where, $params);
            return (int)($row['c'] ?? 0);
        }

        /**
         * @return array<int,array<string,mixed>>
         */
        public static function rows(array $filters, int $limit = self::PER_PAGE, int $offset = 0): array
        {
            [$where, $params] = self::where($filters);
            $limit = max(1, min(500, $limit));
            $offset = max(0, $offset);
            return CveDatabase::fetchAll(
                "SELECT e.* FROM exposed_cves e" . $where
                . " ORDER BY " . self::orderBy((string)($filters['sort'] ?? 'oldest'))
                . " LIMIT " . $limit . " OFFSET " . $offset,
                $params
            );
        }

        /**
         * @return string[]
         */
        public static function allIds(array $filters, int $max = self::MAX_GROUP_CVES): array
        {
            [$where, $params] = self::where($filters);
            $rows = CveDatabase::fetchAll(
                "SELECT e.cve_id FROM exposed_cves e" . $where
                . " ORDER BY " . self::orderBy((string)($filters['sort'] ?? 'oldest'))
                . " LIMIT " . max(1, $max),
                $params
            );
            return array_map(static fn(array $row): string => (string)$row['cve_id'], $rows);
        }

        /**
         * KPIs deterministas del filtro activo.
         *
         * @return array<string,mixed>
         */
        public static function stats(array $filters): array
        {
            [$where, $params] = self::where($filters);
            $row = CveDatabase::fetchOne(
                "SELECT COUNT(*) AS total,
                        SUM(CASE WHEN e.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                        SUM(CASE WHEN e.severity = 'high' THEN 1 ELSE 0 END) AS high,
                        SUM(CASE WHEN e.has_exploit = 1 THEN 1 ELSE 0 END) AS exploitable,
                        SUM(CASE WHEN e.has_known_threats = 1 THEN 1 ELSE 0 END) AS threats,
                        SUM(CASE WHEN e.age_days > 90 THEN 1 ELSE 0 END) AS older90,
                        SUM(e.exposed_machines) AS machines_sum,
                        MAX(e.exposed_machines) AS machines_max,
                        MAX(e.age_days) AS age_max,
                        MIN(e.age_days) AS age_min,
                        MAX(e.cvss) AS cvss_max,
                        MAX(e.epss) AS epss_max
                 FROM exposed_cves e" . $where,
                $params
            ) ?? [];

            $total = (int)($row['total'] ?? 0);
            return [
                'total'         => $total,
                'critical'      => (int)($row['critical'] ?? 0),
                'high'          => (int)($row['high'] ?? 0),
                'exploitable'   => (int)($row['exploitable'] ?? 0),
                'threats'       => (int)($row['threats'] ?? 0),
                'older90'       => (int)($row['older90'] ?? 0),
                'machines_sum'  => (int)($row['machines_sum'] ?? 0),
                'machines_max'  => (int)($row['machines_max'] ?? 0),
                'age_max'       => (int)($row['age_max'] ?? 0),
                'age_min'       => (int)($row['age_min'] ?? 0),
                'cvss_max'      => $row['cvss_max'] !== null ? (float)$row['cvss_max'] : null,
                'epss_max'      => $row['epss_max'] !== null ? (float)$row['epss_max'] : null,
            ];
        }

        /**
         * Contadores por opción de cada bloque, aplicando el resto de filtros.
         *
         * @return array<string,array<string,int>>
         */
        public static function facets(array $filters): array
        {
            $countWith = static function (array $overrides) use ($filters): int {
                return self::count(array_merge($filters, $overrides));
            };

            $facets = ['severity' => [], 'age' => [], 'threats' => [], 'tags' => [], 'status' => []];

            foreach (self::SEVERITIES as $option) {
                $facets['severity'][$option] = $countWith(['severity' => [$option]]);
            }
            foreach (self::AGE_BUCKETS as $option) {
                $facets['age'][$option] = $countWith(['age' => [$option]]);
            }
            foreach (self::THREATS as $option) {
                $facets['threats'][$option] = $countWith(['threats' => [$option]]);
            }
            foreach (self::TAGS as $option) {
                $facets['tags'][$option] = $countWith(['tags' => [$option]]);
            }
            foreach (self::STATUSES as $option) {
                $facets['status'][$option] = $countWith(['status' => [$option]]);
            }

            return $facets;
        }

        /** Totales de la lista maestra completa (cabecera de la consola). */
        public static function masterTotals(): array
        {
            $row = CveDatabase::fetchOne(
                "SELECT COUNT(*) AS total,
                        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                        SUM(CASE WHEN has_exploit = 1 THEN 1 ELSE 0 END) AS exploitable,
                        MAX(exposed_machines) AS machines_max,
                        MAX(last_seen_at) AS last_seen_at
                 FROM exposed_cves"
            ) ?? [];

            return [
                'total'        => (int)($row['total'] ?? 0),
                'critical'     => (int)($row['critical'] ?? 0),
                'exploitable'  => (int)($row['exploitable'] ?? 0),
                'machines_max' => (int)($row['machines_max'] ?? 0),
                'last_seen_at' => (string)($row['last_seen_at'] ?? ''),
            ];
        }

        /** Opciones del 1 al N para un bloque (la interfaz usa etiquetas). */
        public static function severityRankSql(string $column = 'e.severity'): string
        {
            return "CASE {$column}
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4 END";
        }

        /* =================================================================
         * Grupos de análisis
         * ============================================================== */

        /**
         * @param string[] $cveIds
         * @return array{ok:bool,error:string,group_id:int}
         */
        public static function createGroup(string $name, array $filters, array $cveIds, int $userId = 0): array
        {
            $name = trim(preg_replace('/\s+/u', ' ', $name) ?? $name);
            if ($name === '') {
                return ['ok' => false, 'error' => 'Pon un nombre al grupo.', 'group_id' => 0];
            }
            if (self::strLen($name) > 120) {
                $name = self::strCut($name, 120);
            }

            $ids = self::cleanCveIds($cveIds);
            if ($ids === []) {
                return ['ok' => false, 'error' => 'Selecciona al menos un CVE.', 'group_id' => 0];
            }
            if (count($ids) > self::MAX_GROUP_CVES) {
                $ids = array_slice($ids, 0, self::MAX_GROUP_CVES);
            }

            $db = CveDatabase::getInstance();
            try {
                $db->beginTransaction();
                $groupId = CveDatabase::insert(
                    "INSERT INTO exposed_groups (name, filters_json, created_by)
                     VALUES (?, ?, ?)",
                    [
                        $name,
                        json_encode(self::filtersToQuery($filters), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                        $userId > 0 ? $userId : null,
                    ]
                );
                $stmt = $db->prepare(
                    "INSERT OR IGNORE INTO exposed_group_cves (group_id, cve_id) VALUES (?, ?)"
                );
                foreach ($ids as $id) {
                    $stmt->execute([$groupId, $id]);
                }
                $db->commit();
                return ['ok' => true, 'error' => '', 'group_id' => $groupId];
            } catch (Throwable $e) {
                if ($db->inTransaction()) {
                    $db->rollBack();
                }
                return ['ok' => false, 'error' => 'No se pudo crear el grupo: ' . $e->getMessage(), 'group_id' => 0];
            }
        }

        /**
         * @param string[] $cveIds
         * @return array{ok:bool,error:string,added:int}
         */
        public static function addCves(int $groupId, array $cveIds): array
        {
            if ($groupId <= 0 || self::getGroup($groupId) === null) {
                return ['ok' => false, 'error' => 'El grupo no existe.', 'added' => 0];
            }
            $ids = array_slice(self::cleanCveIds($cveIds), 0, self::MAX_GROUP_CVES);
            if ($ids === []) {
                return ['ok' => false, 'error' => 'No hay CVE válidos que añadir.', 'added' => 0];
            }

            $db = CveDatabase::getInstance();
            try {
                $db->beginTransaction();
                $stmt = $db->prepare(
                    "INSERT OR IGNORE INTO exposed_group_cves (group_id, cve_id) VALUES (?, ?)"
                );
                $added = 0;
                foreach ($ids as $id) {
                    $stmt->execute([$groupId, $id]);
                    $added += $stmt->rowCount();
                }
                CveDatabase::query(
                    "UPDATE exposed_groups SET updated_at = datetime('now') WHERE id = ?",
                    [$groupId]
                );
                $db->commit();
                return ['ok' => true, 'error' => '', 'added' => $added];
            } catch (Throwable $e) {
                if ($db->inTransaction()) {
                    $db->rollBack();
                }
                return ['ok' => false, 'error' => 'No se pudieron añadir los CVE: ' . $e->getMessage(), 'added' => 0];
            }
        }

        /** @return array{ok:bool,error:string} */
        public static function removeCve(int $groupId, string $cveId): array
        {
            $cveId = strtoupper(trim($cveId));
            if ($groupId <= 0 || preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId) !== 1) {
                return ['ok' => false, 'error' => 'Datos no válidos.'];
            }
            CveDatabase::query(
                "DELETE FROM exposed_group_cves WHERE group_id = ? AND cve_id = ?",
                [$groupId, $cveId]
            );
            CveDatabase::query(
                "UPDATE exposed_groups SET updated_at = datetime('now') WHERE id = ?",
                [$groupId]
            );
            return ['ok' => true, 'error' => ''];
        }

        /** @return array{ok:bool,error:string} */
        public static function deleteGroup(int $groupId): array
        {
            if ($groupId <= 0) {
                return ['ok' => false, 'error' => 'Grupo no válido.'];
            }
            try {
                CveDatabase::query("DELETE FROM exposed_group_cves WHERE group_id = ?", [$groupId]);
                CveDatabase::query("DELETE FROM exposed_group_plans WHERE group_id = ?", [$groupId]);
                CveDatabase::query("DELETE FROM exposed_groups WHERE id = ?", [$groupId]);
                return ['ok' => true, 'error' => ''];
            } catch (Throwable $e) {
                return ['ok' => false, 'error' => 'No se pudo eliminar el grupo: ' . $e->getMessage()];
            }
        }

        public static function listGroups(int $limit = 100): array
        {
            return CveDatabase::fetchAll(
                "SELECT g.*,
                        (SELECT COUNT(*) FROM exposed_group_cves gc WHERE gc.group_id = g.id) AS cve_count,
                        (SELECT p.generated_at FROM exposed_group_plans p WHERE p.group_id = g.id) AS plan_generated_at
                 FROM exposed_groups g
                 ORDER BY g.updated_at DESC, g.id DESC
                 LIMIT " . max(1, min(300, $limit))
            );
        }

        public static function getGroup(int $groupId): ?array
        {
            if ($groupId <= 0) {
                return null;
            }
            return CveDatabase::fetchOne(
                "SELECT g.*,
                        (SELECT COUNT(*) FROM exposed_group_cves gc WHERE gc.group_id = g.id) AS cve_count
                 FROM exposed_groups g
                 WHERE g.id = ?",
                [$groupId]
            );
        }

        /**
         * CVEs del grupo con sus datos TVM de la lista maestra.
         *
         * @return array<int,array<string,mixed>>
         */
        public static function groupRows(int $groupId, ?int $limit = null): array
        {
            $sql = "SELECT gc.cve_id,
                           e.severity, e.cvss, e.epss, e.age_days,
                           e.published_at, e.first_detected_at, e.has_exploit,
                           e.has_known_threats, e.has_alerts, e.exposed_machines,
                           e.tvm_status, e.software_labels, e.software_tokens,
                           e.software_total, e.zero_day, e.no_security_update,
                           e.security_update, e.exploit_kit, e.exploit_verified,
                           e.description, e.first_seen_at, e.last_seen_at,
                           " . self::severityRankSql('e.severity') . " AS severity_rank,
                           EXISTS (SELECT 1 FROM cve_kev k WHERE k.cve_id = gc.cve_id) AS is_kev
                    FROM exposed_group_cves gc
                    LEFT JOIN exposed_cves e ON e.cve_id = gc.cve_id
                    WHERE gc.group_id = ?
                    ORDER BY severity_rank ASC, e.exposed_machines DESC, e.age_days DESC, gc.cve_id ASC";

            if ($limit !== null) {
                $sql .= " LIMIT " . max(1, $limit);
            }

            return CveDatabase::fetchAll($sql, [$groupId]);
        }

        /**
         * CVE del grupo que existen en el catálogo local (para informes IA).
         *
         * @param string[] $cveIds
         * @return string[]
         */
        public static function catalogCves(array $cveIds): array
        {
            $ids = self::cleanCveIds($cveIds);
            if ($ids === []) {
                return [];
            }
            $found = [];
            foreach (array_chunk($ids, 200) as $chunk) {
                $rows = CveDatabase::fetchAll(
                    "SELECT cve_id FROM cve_catalog WHERE cve_id IN ("
                    . implode(',', array_fill(0, count($chunk), '?')) . ")",
                    $chunk
                );
                foreach ($rows as $row) {
                    $found[(string)$row['cve_id']] = true;
                }
            }
            return array_values(array_filter($ids, static fn(string $id): bool => isset($found[$id])));
        }

        /* =================================================================
         * Plan de actuación
         * ============================================================== */

        public static function savePlan(int $groupId, string $text, int $cveCount, string $model = '', int $profileId = 0): void
        {
            $html = function_exists('render_ai_markdown')
                ? render_ai_markdown($text)
                : (function_exists('render_markdown') ? render_markdown($text) : nl2br(e($text)));

            CveDatabase::query(
                "INSERT INTO exposed_group_plans
                 (group_id, content_text, content_html, cve_count, model, profile_id, generated_at)
                 VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                 ON CONFLICT(group_id) DO UPDATE SET
                    content_text = excluded.content_text,
                    content_html = excluded.content_html,
                    cve_count = excluded.cve_count,
                    model = excluded.model,
                    profile_id = excluded.profile_id,
                    generated_at = datetime('now')",
                [$groupId, $text, $html, $cveCount, $model, $profileId > 0 ? $profileId : null]
            );
        }

        public static function getPlan(int $groupId): ?array
        {
            if ($groupId <= 0) {
                return null;
            }
            return CveDatabase::fetchOne(
                "SELECT * FROM exposed_group_plans WHERE group_id = ?",
                [$groupId]
            );
        }

        /* =================================================================
         * Utilidades
         * ============================================================== */

        /**
         * @param array<int,mixed> $cveIds
         * @return string[]
         */
        public static function cleanCveIds(array $cveIds): array
        {
            $out = [];
            foreach ($cveIds as $value) {
                if (!is_scalar($value)) {
                    continue;
                }
                $id = strtoupper(trim((string)$value));
                if (preg_match('/^CVE-\d{4}-\d{4,7}$/', $id) === 1) {
                    $out[$id] = true;
                }
            }
            return array_keys($out);
        }

        public static function formatBytes(int $bytes): string
        {
            if ($bytes >= 1048576) {
                return rtrim(rtrim(number_format($bytes / 1048576, 1, ',', '.'), '0'), ',') . ' MB';
            }
            if ($bytes >= 1024) {
                return (int)round($bytes / 1024) . ' KB';
            }
            return max(0, $bytes) . ' B';
        }

        private static function clip(string $value, int $length): string
        {
            $value = trim($value);
            if ($length <= 0) {
                return '';
            }
            return self::strCut($value, $length);
        }

        /** Longitud en caracteres con o sin mbstring (CLI no siempre lo trae). */
        public static function strLen(string $value): int
        {
            return function_exists('mb_strlen') ? mb_strlen($value) : strlen($value);
        }

        /** Recorte por caracteres con o sin mbstring. */
        public static function strCut(string $value, int $length): string
        {
            return function_exists('mb_substr') ? mb_substr($value, 0, $length) : substr($value, 0, $length);
        }
    }
}
