<?php
/**
 * exposed_report_enrichment.php — Detalle de CVE para el informe de equipos
 * expuestos (anexo determinista, sin IA).
 *
 * Dos fuentes, ambas de solo lectura:
 *
 *   · V1 — catálogo local (cve.sqlite): cve_catalog + cve_epss + cve_kev +
 *     cve_exploit. Solo cubre los CVE que el CSV nombra (CVEsConExploit).
 *   · V2 — inventario TVM ya sincronizado (BD principal): machines +
 *     vulnerabilities, unidos por computer_dns_name = DeviceName. Permite el
 *     detalle completo por servidor, pero exige que el módulo Vulnerabilidades
 *     se haya sincronizado (licencia/Graph en el tenant).
 *
 * Nunca inventa: lo que no está en la fuente se muestra como «—» y se avisa.
 */

declare(strict_types=1);

if (!class_exists('ExposedReportEnrichment')) {
    final class ExposedReportEnrichment
    {
        public const SOURCE_NONE = 'none';
        public const SOURCE_CATALOG = 'catalog';
        public const SOURCE_INVENTORY = 'inventory';

        /** Filas máximas del anexo para no generar un documento inmanejable. */
        public const MAX_ANNEX_ROWS = 200;

        /** CVEs por consulta (límite de parámetros de SQLite). */
        private const CHUNK = 200;

        public const SOURCES = [
            self::SOURCE_NONE      => 'Sin detalle',
            self::SOURCE_CATALOG   => 'Catálogo local (NVD/EPSS/KEV)',
            self::SOURCE_INVENTORY => 'Inventario del tenant (TVM)',
        ];

        private const SEVERITY_LABELS = [
            'critical' => 'Crítica',
            'high'     => 'Alta',
            'medium'   => 'Media',
            'low'      => 'Baja',
            'info'     => 'Informativa',
        ];

        /** ¿Hay inventario TVM sincronizado en la BD principal? */
        public static function inventoryAvailable(): bool
        {
            try {
                $row = Database::fetchOne("SELECT COUNT(*) AS c FROM vulnerabilities");
                return $row !== null && (int)($row['c'] ?? 0) > 0;
            } catch (Throwable $e) {
                return false;
            }
        }

        /** ¿Existe el catálogo local con datos? */
        public static function catalogAvailable(): bool
        {
            if (!defined('CVE_DB_PATH') || !is_file(CVE_DB_PATH)) {
                return false;
            }
            try {
                $row = CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_catalog");
                return $row !== null && (int)($row['c'] ?? 0) > 0;
            } catch (Throwable $e) {
                return false;
            }
        }

        /**
         * CVE con exploit público que aparecen en el CSV, en orden de prioridad.
         *
         * @param array<int,array<string,mixed>> $rows
         * @return array<int,string>
         */
        public static function collectExploitCves(array $rows): array
        {
            $out = [];
            foreach ($rows as $row) {
                foreach ((array)($row['exploit_cves'] ?? []) as $cve) {
                    $cve = strtoupper(trim((string)$cve));
                    if (preg_match('/^CVE-\d{4}-\d{4,}$/', $cve) === 1) {
                        $out[$cve] = true;
                    }
                }
            }
            return array_keys($out);
        }

        /**
         * V1 — datos del catálogo local para los CVE indicados.
         *
         * @param array<int,string> $cveIds
         * @return array<string,array<string,mixed>>
         */
        public static function fromCatalog(array $cveIds): array
        {
            if (!self::catalogAvailable()) {
                return [];
            }

            $cveIds = array_values(array_unique(array_filter(array_map(
                static fn($id): string => strtoupper(trim((string)$id)),
                $cveIds
            ))));
            if ($cveIds === []) {
                return [];
            }

            $out = [];
            foreach (array_chunk($cveIds, self::CHUNK) as $chunk) {
                $in = implode(', ', array_fill(0, count($chunk), '?'));

                $catalog = CveDatabase::fetchAll(
                    "SELECT cve_id, severity, cvss_v3_score, description_es, description, published_at, nvd_url
                     FROM cve_catalog WHERE cve_id IN ($in)",
                    $chunk
                );
                foreach ($catalog as $row) {
                    $id = (string)$row['cve_id'];
                    $out[$id] = [
                        'cve_id'     => $id,
                        'severity'   => strtolower((string)($row['severity'] ?? '')),
                        'cvss'       => $row['cvss_v3_score'] !== null ? (float)$row['cvss_v3_score'] : null,
                        'description'=> (string)($row['description_es'] ?? '') !== ''
                            ? (string)$row['description_es']
                            : (string)($row['description'] ?? ''),
                        'published'  => (string)($row['published_at'] ?? ''),
                        'epss'       => null,
                        'percentile' => null,
                        'kev'        => false,
                        'kev_name'   => '',
                        'kev_ransomware' => '',
                        'kev_due'    => '',
                        'exploits'   => 0,
                    ];
                }

                $epss = CveDatabase::fetchAll(
                    "SELECT cve_id, epss, percentile FROM cve_epss WHERE cve_id IN ($in)",
                    $chunk
                );
                foreach ($epss as $row) {
                    $id = (string)$row['cve_id'];
                    if (isset($out[$id])) {
                        $out[$id]['epss'] = $row['epss'] !== null ? (float)$row['epss'] : null;
                        $out[$id]['percentile'] = $row['percentile'] !== null ? (float)$row['percentile'] : null;
                    }
                }

                $kev = CveDatabase::fetchAll(
                    "SELECT cve_id, vulnerability_name, known_ransomware, due_date FROM cve_kev WHERE cve_id IN ($in)",
                    $chunk
                );
                foreach ($kev as $row) {
                    $id = (string)$row['cve_id'];
                    if (isset($out[$id])) {
                        $out[$id]['kev'] = true;
                        $out[$id]['kev_name'] = (string)($row['vulnerability_name'] ?? '');
                        $out[$id]['kev_ransomware'] = (string)($row['known_ransomware'] ?? '');
                        $out[$id]['kev_due'] = (string)($row['due_date'] ?? '');
                    }
                }

                $exploits = CveDatabase::fetchAll(
                    "SELECT cve_id, COUNT(*) AS total FROM cve_exploit WHERE cve_id IN ($in) GROUP BY cve_id",
                    $chunk
                );
                foreach ($exploits as $row) {
                    $id = (string)$row['cve_id'];
                    if (isset($out[$id])) {
                        $out[$id]['exploits'] = (int)($row['total'] ?? 0);
                    }
                }
            }

            ksort($out);
            return $out;
        }

        /**
         * Anexo C del modo detallado con la fuente de catálogo (V1).
         *
         * @param array<int,array<string,mixed>> $rows
         * @param array<string,array<string,mixed>> $catalog
         * @return array{markdown:string,notice:?string}
         */
        public static function annexCatalog(array $rows, array $catalog): array
        {
            $lines = [];
            $lines[] = '### Anexo C. Detalle de los CVE con exploit público';
            $lines[] = '';
            $lines[] = '> Fuente: catálogo local (NVD, EPSS, CISA KEV y exploits registrados). '
                . 'Solo se desglosan los CVE que identifica el CSV; los recuentos agregados del resto '
                . 'no se pueden enumerar sin el inventario del tenant.';

            $total = 0;
            $missing = 0;
            $body = [];

            foreach ($rows as $row) {
                $device = (string)($row['device'] ?? '—');
                foreach ((array)($row['exploit_cves'] ?? []) as $rawCve) {
                    $cve = strtoupper(trim((string)$rawCve));
                    if (preg_match('/^CVE-\d{4}-\d{4,}$/', $cve) !== 1) {
                        continue;
                    }
                    $total++;
                    if ($total > self::MAX_ANNEX_ROWS) {
                        continue;
                    }

                    $data = $catalog[$cve] ?? null;
                    if ($data === null) {
                        $missing++;
                        $body[] = '| ' . self::cell($device) . ' | ' . self::cell($cve)
                            . ' | — | — | — | — | — | — |';
                        continue;
                    }

                    $body[] = '| ' . self::cell($device)
                        . ' | ' . self::cell($cve)
                        . ' | ' . self::cell(self::severityLabel((string)$data['severity']))
                        . ' | ' . self::cell(self::score($data['cvss']))
                        . ' | ' . self::cell(self::percent($data['epss']))
                        . ' | ' . self::cell($data['kev'] ? 'Sí' : 'No')
                        . ' | ' . self::cell(self::exploitLabel((int)$data['exploits']))
                        . ' | ' . self::cell(self::dateLabel((string)$data['published']))
                        . ' |';
                }
            }

            if ($body === []) {
                return ['markdown' => '', 'notice' => 'El CSV no enumera ningún CVE con exploit público.'];
            }

            $shown = min($total, self::MAX_ANNEX_ROWS);

            // Si el catálogo no tiene NINGUNO de los CVE, no se pinta una tabla
            // de guiones: se listan los identificadores que sí aporta el CSV.
            if ($missing === $shown) {
                $ids = [];
                foreach ($rows as $row) {
                    foreach ((array)($row['exploit_cves'] ?? []) as $rawCve) {
                        $cve = strtoupper(trim((string)$rawCve));
                        if (preg_match('/^CVE-\d{4}-\d{4,}$/', $cve) === 1) {
                            $ids[$cve] = true;
                        }
                    }
                }
                $ids = array_slice(array_keys($ids), 0, self::MAX_ANNEX_ROWS);
                $lines[] = '';
                $lines[] = '> El catálogo local no tiene datos de estos CVE. Identificadores que aporta el CSV: '
                    . implode(', ', $ids) . '.';

                return [
                    'markdown' => implode("\n", $lines),
                    'notice'   => 'El catálogo local no tiene datos de los CVE con exploit de este CSV: '
                        . 'el anexo solo enumera los identificadores.',
                ];
            }

            $lines[] = '';
            $lines[] = '| Servidor | CVE | Severidad | CVSS | EPSS | KEV | Exploit | Publicado |';
            $lines[] = '|---|---|---|---|---|---|---|---|';
            foreach ($body as $row) {
                $lines[] = $row;
            }
            $lines[] = '';

            $notes = [];
            if ($total > self::MAX_ANNEX_ROWS) {
                $notes[] = 'Se listan los primeros ' . self::MAX_ANNEX_ROWS . ' de ' . $total . ' CVE.';
            }
            if ($missing > 0) {
                $notes[] = $missing . ' de ' . min($total, self::MAX_ANNEX_ROWS)
                    . ' CVE no constan en el catálogo local (marcados con «—»).';
            }
            if ($notes !== []) {
                $lines[] = '> ' . implode(' ', $notes);
                $lines[] = '';
            }

            return ['markdown' => implode("\n", $lines), 'notice' => null];
        }

        /**
         * Anexo C del modo detallado con el inventario TVM sincronizado (V2).
         *
         * @param array<int,array<string,mixed>> $rows
         * @return array{markdown:string,notice:?string,mismatch:array<int,string>}
         */
        public static function annexInventory(array $rows): array
        {
            if (!self::inventoryAvailable()) {
                return [
                    'markdown' => '',
                    'notice'   => 'No hay inventario TVM sincronizado: el anexo de CVEs necesita que el módulo '
                        . 'Vulnerabilidades se haya sincronizado para el tenant (requiere licencia Graph).',
                    'mismatch' => [],
                ];
            }

            $body = [];
            $mismatch = [];
            $withoutInventory = 0;
            $withInventory = 0;

            foreach ($rows as $row) {
                $device = (string)($row['device'] ?? '');
                $machine = self::findMachine($device);
                if ($machine === null) {
                    $withoutInventory++;
                    continue;
                }
                $withInventory++;

                $defenderExposure = (string)($machine['exposure_level'] ?? '');
                $csvExposure = (string)($row['exposure'] ?? '');
                if ($defenderExposure !== '' && $csvExposure !== ''
                    && strcasecmp($defenderExposure, $csvExposure) !== 0) {
                    $mismatch[] = $device . ': el CSV dice ' . $csvExposure . ' y Defender ' . $defenderExposure . '.';
                }

                $cves = self::machineCves((string)($machine['machine_id'] ?? ''));
                $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
                $top = [];
                foreach ($cves as $cve) {
                    $severity = strtolower((string)($cve['severity'] ?? ''));
                    if (isset($counts[$severity])) {
                        $counts[$severity]++;
                    }
                    $label = (string)$cve['cve_id'];
                    $score = $cve['cvss_v3'] !== null ? (float)$cve['cvss_v3'] : null;
                    $top[] = $label
                        . ($score !== null ? ' (' . number_format($score, 1, ',', '') . ')' : '')
                        . ((int)($cve['public_exploit'] ?? 0) === 1 ? ' · exploit' : '');
                }

                $body[] = '| ' . self::cell($device)
                    . ' | ' . self::cell($defenderExposure !== '' ? $defenderExposure : '—')
                    . ' | ' . $counts['critical']
                    . ' | ' . $counts['high']
                    . ' | ' . $counts['medium']
                    . ' | ' . $counts['low']
                    . ' | ' . count($cves)
                    . ' | ' . self::cell(implode('; ', array_slice($top, 0, 3)))
                    . ' |';
            }

            if ($body === []) {
                return [
                    'markdown' => '',
                    'notice'   => 'Ninguno de los servidores del CSV aparece en el inventario sincronizado.',
                    'mismatch' => [],
                ];
            }

            $lines = [];
            $lines[] = '### Anexo C. Detalle por servidor (inventario TVM)';
            $lines[] = '';
            $lines[] = '> Fuente: inventario de Defender sincronizado en la aplicación '
                . '(máquinas + vulnerabilidades). Se muestran los 3 CVE de mayor CVSS por servidor.';
            $lines[] = '';
            $lines[] = '| Servidor | Exposición Defender | Críticos | Altos | Medios | Bajos | CVEs | Top CVE (CVSS) |';
            $lines[] = '|---|---|---|---|---|---|---|---|';
            foreach ($body as $line) {
                $lines[] = $line;
            }
            $lines[] = '';

            if ($withoutInventory > 0) {
                $lines[] = '> ' . $withoutInventory . ' de ' . ($withoutInventory + $withInventory)
                    . ' servidores del CSV no constan en el inventario sincronizado.';
                $lines[] = '';
            }

            return [
                'markdown' => implode("\n", $lines),
                'notice'   => $withoutInventory > 0
                    ? $withoutInventory . ' servidor(es) sin inventario sincronizado; el resto sí se detalla.'
                    : null,
                'mismatch' => $mismatch,
            ];
        }

        /* =================================================================
         * Interno
         * ============================================================== */

        /** @return array<string,mixed>|null */
        private static function findMachine(string $deviceName): ?array
        {
            $deviceName = trim($deviceName);
            if ($deviceName === '') {
                return null;
            }
            try {
                return Database::fetchOne(
                    "SELECT machine_id, computer_dns_name, exposure_level
                     FROM machines
                     WHERE LOWER(computer_dns_name) = LOWER(?)
                     ORDER BY last_seen DESC
                     LIMIT 1",
                    [$deviceName]
                );
            } catch (Throwable $e) {
                return null;
            }
        }

        /** @return array<int,array<string,mixed>> */
        private static function machineCves(string $machineId): array
        {
            if ($machineId === '') {
                return [];
            }
            try {
                return Database::fetchAll(
                    "SELECT cve_id, severity, cvss_v3, public_exploit
                     FROM vulnerabilities
                     WHERE machine_id = ?
                     ORDER BY COALESCE(cvss_v3, 0) DESC, cve_id ASC
                     LIMIT 800",
                    [$machineId]
                );
            } catch (Throwable $e) {
                return [];
            }
        }

        private static function severityLabel(string $severity): string
        {
            return self::SEVERITY_LABELS[$severity] ?? ($severity !== '' ? ucfirst($severity) : '—');
        }

        private static function score(mixed $value): string
        {
            return $value !== null ? number_format((float)$value, 1, ',', '') : '—';
        }

        private static function percent(mixed $value): string
        {
            return $value !== null ? number_format((float)$value * 100, 1, ',', '') . ' %' : '—';
        }

        private static function exploitLabel(int $sources): string
        {
            if ($sources <= 0) {
                return '—';
            }
            return $sources === 1 ? '1 fuente' : $sources . ' fuentes';
        }

        private static function dateLabel(string $value): string
        {
            $value = trim($value);
            if ($value === '') {
                return '—';
            }
            $ts = strtotime(str_contains($value, 'T') ? $value : $value . ' UTC');
            return $ts !== false ? gmdate('d/m/Y', $ts) : '—';
        }

        private static function cell(string $value): string
        {
            $value = trim(str_replace(["\r", "\n", '|'], [' ', ' ', '\\|'], $value));
            if (function_exists('mb_substr') && mb_strlen($value) > 90) {
                $value = mb_substr($value, 0, 89) . '…';
            } elseif (strlen($value) > 90) {
                $value = substr($value, 0, 89) . '…';
            }
            return $value;
        }
    }
}
