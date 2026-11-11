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

        /** CVE y caracteres máximos del bloque de datos que se envía a la IA. */
        public const MAX_PROMPT_CVES = 40;
        public const MAX_PROMPT_CHARS = 12000;

        /** Análisis por CVE que se pueden encolar en una tanda. */
        public const MAX_ANALYSIS_QUEUE = 20;

        /** Antigüedad máxima de un análisis por CVE reutilizado. */
        public const ANALYSIS_MAX_AGE_DAYS = 365;

        /** Tamaño máximo del JSON de especificación editado en pantalla. */
        public const MAX_SPEC_CHARS = 60000;

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
         * Datos completos del catálogo para los CVE indicados (misma fuente que
         * usa el módulo CVE en sus informes IA). No hace red.
         *
         * @param array<int,string> $cveIds
         * @return array<string,array<string,mixed>> clave = CVE
         */
        public static function cveDetails(array $cveIds): array
        {
            $cveIds = array_values(array_unique(array_filter(array_map(
                static fn($id): string => strtoupper(trim((string)$id)),
                $cveIds
            ))));
            if ($cveIds === [] || !self::catalogAvailable()) {
                return [];
            }
            if (!class_exists('CveReportAi')) {
                return [];
            }

            try {
                $items = CveReportAi::buildData($cveIds);
            } catch (Throwable $e) {
                return [];
            }

            $out = [];
            foreach ($items as $item) {
                $id = strtoupper((string)($item['cve_id'] ?? ''));
                if ($id !== '') {
                    $out[$id] = $item;
                }
            }
            return $out;
        }

        /**
         * Bloque de datos de CVE que se inyecta en el prompt del modo detallado.
         *
         * @param array<int,string> $cveIds
         * @return array{text:string,count:int}
         */
        public static function promptBlock(array $cveIds): array
        {
            $details = self::cveDetails($cveIds);
            if ($details === []) {
                return ['text' => '', 'count' => 0];
            }

            $lines = [
                'Datos de los CVE con exploit público (fuente: catálogo local de la aplicación).',
                'Formato: CVE | severidad | CVSS | EPSS | KEV | exploits | prioridad | publicado.',
                '',
            ];

            $count = 0;
            $chars = 0;
            foreach ($details as $cve => $item) {
                if ($count >= self::MAX_PROMPT_CVES || $chars >= self::MAX_PROMPT_CHARS) {
                    break;
                }

                $severity = self::severityLabel(strtolower((string)($item['severity'] ?? '')));
                $cvss = $item['cvss'] !== null ? number_format((float)$item['cvss'], 1, ',', '') : '—';
                $epss = $item['epss'] !== null
                    ? number_format((float)$item['epss'] * 100, 1, ',', '') . ' %'
                        . ($item['epss_percentile'] !== null
                            ? ' (percentil ' . number_format((float)$item['epss_percentile'], 2, ',', '') . ')'
                            : '')
                    : '—';
                $kev = !empty($item['kev'])
                    ? 'Sí' . (($item['kev_name'] ?? '') !== '' ? ' (' . $item['kev_name'] . ')' : '')
                        . (($item['kev_due'] ?? '') !== '' ? ', vence ' . $item['kev_due'] : '')
                        . (($item['kev_ransomware'] ?? '') !== '' ? ', ransomware: ' . $item['kev_ransomware'] : '')
                    : 'No';
                $exploits = (int)($item['exploits']['total'] ?? 0);

                $line = $cve
                    . ' | ' . $severity
                    . ' | CVSS ' . $cvss
                    . ' | EPSS ' . $epss
                    . ' | KEV: ' . $kev
                    . ' | Exploits públicos: ' . $exploits
                    . ' | Prioridad: ' . (string)($item['priority'] ?? '—')
                    . ' | Publicado: ' . (string)($item['published_at'] ?? '—');

                $description = trim((string)($item['description_es'] ?? ''));
                if ($description === '') {
                    $description = trim((string)($item['description'] ?? ''));
                }
                if ($description !== '') {
                    $line .= "\n  Descripción: " . self::clip($description, 500);
                }

                $lines[] = $line;
                $count++;
                $chars += strlen($line);
            }

            return ['text' => implode("\n", $lines), 'count' => $count];
        }

        /**
         * Análisis por CVE ya generados en el módulo CVE (se reutilizan tal cual).
         *
         * @param array<int,string> $cveIds
         * @return array<string,array<string,mixed>>
         */
        public static function storedAnalyses(array $cveIds): array
        {
            $cveIds = array_values(array_unique(array_filter(array_map(
                static fn($id): string => strtoupper(trim((string)$id)),
                $cveIds
            ))));
            if ($cveIds === [] || !self::catalogAvailable()) {
                return [];
            }

            $out = [];
            foreach (array_chunk($cveIds, self::CHUNK) as $chunk) {
                $in = implode(', ', array_fill(0, count($chunk), '?'));
                try {
                    $rows = CveDatabase::fetchAll(
                        "SELECT i.cve_id, i.sections_json, i.ai_text, i.ai_model, i.finished_at, i.created_at,
                                r.id AS report_id, r.ai_model AS report_model, r.created_at AS report_created
                         FROM cve_ai_report_items i
                         JOIN cve_ai_reports r ON r.id = i.report_id
                         WHERE i.cve_id IN ($in)
                           AND i.status = 'done'
                           AND COALESCE(r.archived, 0) = 0
                           AND i.created_at >= datetime('now', ?)
                         ORDER BY i.cve_id ASC, i.created_at DESC, i.id DESC",
                        array_merge($chunk, ['-' . self::ANALYSIS_MAX_AGE_DAYS . ' days'])
                    );
                } catch (Throwable $e) {
                    return [];
                }

                foreach ($rows as $row) {
                    $id = strtoupper((string)$row['cve_id']);
                    if ($id === '' || isset($out[$id])) {
                        continue; // ya está el más reciente
                    }

                    $sections = [];
                    $decoded = safe_json_decode((string)($row['sections_json'] ?? ''), []);
                    if (is_array($decoded)) {
                        foreach ($decoded as $section) {
                            if (!is_array($section)) {
                                continue;
                            }
                            $sections[] = [
                                'title'      => (string)($section['title'] ?? ''),
                                'bullets'    => array_values(array_map('strval', (array)($section['bullets'] ?? []))),
                                'paragraphs' => array_values(array_map('strval', (array)($section['paragraphs'] ?? []))),
                            ];
                        }
                    }

                    if ($sections === []) {
                        $text = trim((string)($row['ai_text'] ?? ''));
                        if ($text !== '') {
                            $sections[] = ['title' => 'Análisis', 'bullets' => [], 'paragraphs' => [$text]];
                        }
                    }

                    if ($sections === []) {
                        continue;
                    }

                    $out[$id] = [
                        'cve_id'     => $id,
                        'sections'   => $sections,
                        'model'      => trim((string)($row['ai_model'] ?? '')) !== ''
                            ? (string)$row['ai_model']
                            : (string)($row['report_model'] ?? ''),
                        'finished'   => (string)($row['finished_at'] ?? $row['created_at'] ?? $row['report_created'] ?? ''),
                        'report_id'  => (int)($row['report_id'] ?? 0),
                    ];
                }
            }

            ksort($out);
            return $out;
        }

        /**
         * CVE sin análisis generado en la aplicación.
         *
         * @param array<int,string> $cveIds
         * @return array<int,string>
         */
        public static function pendingAnalyses(array $cveIds): array
        {
            $stored = self::storedAnalyses($cveIds);
            $pending = [];
            foreach ($cveIds as $id) {
                $id = strtoupper(trim((string)$id));
                if ($id !== '' && !isset($stored[$id])) {
                    $pending[$id] = true;
                }
            }
            return array_keys($pending);
        }

        /**
         * Anexo D: análisis por CVE reutilizados del módulo CVE.
         *
         * @param array<int,string> $cveIds
         * @return array{markdown:string,notice:?string,missing:array<int,string>}
         */
        public static function annexAnalyses(array $cveIds): array
        {
            $analyses = self::storedAnalyses($cveIds);
            if ($analyses === []) {
                return [
                    'markdown' => '',
                    'notice'   => 'No hay análisis por CVE generados en la aplicación. '
                        . 'Usa «Generar análisis de los CVE» para crearlos; se adjuntarán en el próximo informe.',
                    'missing'  => array_values(array_unique(array_map(
                        static fn($id): string => strtoupper(trim((string)$id)),
                        $cveIds
                    ))),
                ];
            }

            $lines = [];
            $lines[] = '### Anexo D. Análisis por CVE';
            $lines[] = '';
            $lines[] = '> Análisis generados con la IA en el módulo CVE y reproducidos sin cambios. '
                . 'La fuente de los datos es el catálogo local de la aplicación.';

            foreach ($analyses as $cve => $analysis) {
                $lines[] = '';
                $meta = [];
                if ((string)$analysis['model'] !== '') {
                    $meta[] = 'modelo: ' . (string)$analysis['model'];
                }
                if ((string)$analysis['finished'] !== '') {
                    $meta[] = self::dateLabel((string)$analysis['finished']);
                }
                $lines[] = '#### ' . $cve . ($meta !== [] ? ' · ' . implode(' · ', $meta) : '');

                foreach ((array)$analysis['sections'] as $section) {
                    $title = trim((string)($section['title'] ?? ''));
                    $bullets = (array)($section['bullets'] ?? []);
                    $paragraphs = (array)($section['paragraphs'] ?? []);
                    if ($title === '' && $bullets === [] && $paragraphs === []) {
                        continue;
                    }
                    if ($title !== '') {
                        $lines[] = '';
                        $lines[] = '**' . $title . '**';
                    }
                    foreach ($bullets as $bullet) {
                        $lines[] = '- ' . $bullet;
                    }
                    foreach ($paragraphs as $paragraph) {
                        $lines[] = '';
                        $lines[] = $paragraph;
                    }
                }
            }

            $missing = [];
            $seen = [];
            foreach ($cveIds as $id) {
                $id = strtoupper(trim((string)$id));
                if ($id === '' || isset($seen[$id])) {
                    continue;
                }
                $seen[$id] = true;
                if (!isset($analyses[$id])) {
                    $missing[] = $id;
                }
            }
            if ($missing !== []) {
                $lines[] = '';
                $lines[] = '> Sin análisis generado en la aplicación: ' . implode(', ', $missing) . '.';
            }
            $lines[] = '';

            return [
                'markdown' => implode("\n", $lines),
                'notice'   => $missing !== []
                    ? count($missing) . ' CVE no tienen análisis generado todavía.'
                    : null,
                'missing'  => $missing,
            ];
        }

        /**
         * JSON de especificación efectivo para una generación.
         *
         * @param string|null $override Texto editado en pantalla (vacío = catálogo).
         * @return array{spec:string,notice:?string,custom:bool}
         */
        public static function resolveSpec(?string $override, string $kqlJson): array
        {
            $catalog = llm_prompts_catalog();
            $default = (string)($catalog['llm.exposed.spec']['default'] ?? '');
            $catalogSpec = llm_prompt('llm.exposed.spec', $default, ['{kql}' => $kqlJson]);

            $override = trim((string)$override);
            if ($override === '') {
                return ['spec' => $catalogSpec, 'notice' => null, 'custom' => false];
            }

            if (strlen($override) > self::MAX_SPEC_CHARS) {
                return [
                    'spec'   => $catalogSpec,
                    'notice' => 'El JSON editado supera ' . number_format(self::MAX_SPEC_CHARS / 1000, 0, ',', '.')
                        . '.000 caracteres; se usa el de la plantilla.',
                    'custom' => false,
                ];
            }

            if (json_decode($override, true) === null && json_last_error() !== JSON_ERROR_NONE) {
                return [
                    'spec'   => $catalogSpec,
                    'notice' => 'El JSON editado no es válido (' . json_last_error_msg() . '); se usa el de la plantilla.',
                    'custom' => false,
                ];
            }

            return [
                'spec'   => strtr($override, ['{kql}' => $kqlJson]),
                'notice' => null,
                'custom' => true,
            ];
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
            $descriptions = [];

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

                    $description = trim((string)($data['description'] ?? ''));
                    if ($description !== '' && !isset($descriptions[$cve])) {
                        $descriptions[$cve] = [
                            'text'     => self::clip($description, 600),
                            'severity' => self::severityLabel((string)$data['severity']),
                            'cvss'     => self::score($data['cvss']),
                        ];
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

            if ($descriptions !== []) {
                $lines[] = '**Descripciones**';
                $lines[] = '';
                foreach ($descriptions as $cve => $info) {
                    $meta = array_filter([$info['severity'], $info['cvss'] !== '—' ? 'CVSS ' . $info['cvss'] : '']);
                    $lines[] = '- **' . $cve . '**' . ($meta !== [] ? ' (' . implode(', ', $meta) . ')' : '')
                        . ': ' . $info['text'];
                }
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
            return self::clip($value, 90);
        }

        private static function clip(string $value, int $length): string
        {
            $value = trim(preg_replace('/\s+/u', ' ', $value) ?? $value);
            if (function_exists('mb_substr') && mb_strlen($value) > $length) {
                return mb_substr($value, 0, max(0, $length - 1)) . '…';
            }
            if (strlen($value) > $length) {
                return substr($value, 0, max(0, $length - 1)) . '…';
            }
            return $value;
        }
    }
}
