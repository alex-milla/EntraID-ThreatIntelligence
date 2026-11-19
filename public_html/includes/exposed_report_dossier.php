<?php
/**
 * exposed_report_dossier.php — Informe de vulnerabilidad de un grupo
 * (v0.4.26.3).
 *
 * Formato minimalista tipo SploitScan: cabecera «Informe de vulnerabilidad»,
 * tira de KPIs y **una tarjeta independiente por CVE** (no una tabla ancha).
 * El grupo es solo el contenedor de entrega y aparece en la línea de metadatos;
 * el protagonista es la vulnerabilidad.
 *
 * El HTML se construye con **estilos en línea** a propósito: así «Copiar
 * informe» conserva colores, barras y bordes al pegarlo en Word/Outlook.
 *
 * Lo determinista lo calcula la aplicación (ExposedPriority + CveReportAi).
 * La IA solo aporta, si se pide, la lectura del riesgo.
 */

declare(strict_types=1);

if (!class_exists('ExposedReportDossier')) {
    final class ExposedReportDossier
    {
        private const MAX_WORK_ROWS = 40;
        private const MAX_FICHAS = 120;

        private const SEV_COLORS = [
            'critical' => ['#dc2626', '#fee2e2', '#b91c1c'],
            'high'     => ['#ea580c', '#ffedd5', '#c2410c'],
            'medium'   => ['#d97706', '#fef3c7', '#92400e'],
            'low'      => ['#16a34a', '#dcfce7', '#15803d'],
            'info'     => ['#6b7280', '#f3f4f6', '#374151'],
        ];

        private const SEV_LABELS = [
            'critical' => 'CRÍTICO',
            'high'     => 'ALTO',
            'medium'   => 'MEDIO',
            'low'      => 'BAJO',
            'info'     => 'INFORMATIVO',
        ];

        private const GRADE_COLORS = [
            'A+' => '#b91c1c',
            'A'  => '#dc2626',
            'B'  => '#d97706',
            'C'  => '#2563eb',
            'D'  => '#059669',
        ];

        /**
         * @param array<string,mixed>            $group
         * @param array<int,array<string,mixed>> $rows
         * @param array<string,mixed>            $options
         * @return array{markdown:string,html:string,tiers:array<string,int>,p1p2:int,kev:int,
         *               with_report:int,without:int,max_priority:string,count:int}
         */
        public static function build(
            array $group,
            array $rows,
            array $options = [],
            ?string $aiPlan = null,
            ?string $singleCve = null
        ): array {
            $items = [];
            $tiers = ['p1' => 0, 'p2' => 0, 'p3' => 0, 'p4' => 0];
            $kev = 0;
            $exploit = 0;
            $exceptions = 0;
            $maxMachines = 0;
            $maxAge = 0;
            $maxGrade = null;
            $gradeOrder = ['A+' => 5, 'A' => 4, 'B' => 3, 'C' => 2, 'D' => 1];

            foreach ($rows as $row) {
                $priority = ExposedPriority::classify($row, $options);
                $desc = ExposedPriority::describe((string)($row['description'] ?? ''));
                $grade = self::priorityGrade($row);
                $row['_tier'] = $priority['tier'];
                $row['_label'] = $priority['label'];
                $row['_reason'] = $priority['reason'];
                $row['_window'] = $priority['window'];
                $row['_ssvc'] = $priority['ssvc'];
                $row['_exception'] = !empty($priority['exception']);
                $row['_desc'] = $desc;
                $row['_grade'] = $grade;
                $row['_action'] = self::actionFor($row);
                $items[] = $row;

                $tiers[$priority['tier']] = ($tiers[$priority['tier']] ?? 0) + 1;
                if ((int)($row['is_kev'] ?? 0) === 1) {
                    $kev++;
                }
                if ((int)($row['has_exploit'] ?? 0) === 1) {
                    $exploit++;
                }
                if (!empty($row['_exception'])) {
                    $exceptions++;
                }
                $maxMachines = max($maxMachines, (int)($row['exposed_machines'] ?? 0));
                $maxAge = max($maxAge, (int)($row['age_days'] ?? 0));
                if ($grade !== '' && ($maxGrade === null || ($gradeOrder[$grade] ?? 0) > ($gradeOrder[$maxGrade] ?? 0))) {
                    $maxGrade = $grade;
                }
            }

            usort($items, static function (array $a, array $b) use ($gradeOrder): int {
                return ($gradeOrder[(string)$b['_grade']] ?? 0) <=> ($gradeOrder[(string)$a['_grade']] ?? 0)
                    ?: ((int)($b['exposed_machines'] ?? 0) <=> (int)($a['exposed_machines'] ?? 0))
                    ?: ((int)($b['age_days'] ?? 0) <=> (int)($a['age_days'] ?? 0))
                    ?: strcmp((string)$a['cve_id'], (string)$b['cve_id']);
            });

            $groupName = trim((string)($group['name'] ?? 'Grupo de análisis'));
            $total = count($items);
            $clusters = self::softwareClusters($items);
            $p1p2 = $tiers['p1'] + $tiers['p2'];
            $single = $singleCve !== null && $singleCve !== '';

            // Cuántos análisis de IA existen para las fichas (solo informativo).
            $withReport = 0;
            $analyses = [];
            if ($items !== [] && class_exists('ExposedReportEnrichment')) {
                try {
                    $analyses = ExposedReportEnrichment::storedAnalyses(array_map(
                        static fn(array $item): string => (string)$item['cve_id'],
                        array_slice($items, 0, self::MAX_FICHAS)
                    ));
                } catch (Throwable $e) {
                    $analyses = [];
                }
            }

            $data = [
                'group'       => $groupName,
                'items'       => $items,
                'clusters'    => $clusters,
                'total'       => $total,
                'kev'         => $kev,
                'exploit'     => $exploit,
                'exceptions'  => $exceptions,
                'maxMachines' => $maxMachines,
                'maxAge'      => $maxAge,
                'maxGrade'    => $maxGrade,
                'tiers'       => $tiers,
                'analyses'    => $analyses,
                'aiPlan'      => $aiPlan,
                'single'      => $single,
                'filter'      => self::filterLabel($group),
                'date'        => date('d/m/Y H:i'),
            ];

            $html = self::renderHtml($data);
            $markdown = self::renderMarkdown($data);

            foreach ($items as $item) {
                if (isset($analyses[(string)$item['cve_id']])) {
                    $withReport++;
                }
            }

            return [
                'markdown'     => $markdown,
                'html'         => $html,
                'tiers'        => $tiers,
                'p1p2'         => $p1p2,
                'kev'          => $kev,
                'with_report'  => $withReport,
                'without'      => max(0, $total - $withReport),
                'max_priority' => (string)($maxGrade ?? ''),
                'count'        => $total,
            ];
        }

        /* =================================================================
         * HTML (estilos en línea para que sobrevivan al copiar/pegar)
         * ============================================================== */

        private static function renderHtml(array $data): string
        {
            $items = $data['items'];
            $total = (int)$data['total'];
            $html = [];

            $html[] = '<div style="font-family:Segoe UI,Arial,sans-serif;color:#111827;line-height:1.55;">';
            $html[] = '<p style="margin:0;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#6b7280;font-weight:700;">Informe de vulnerabilidad</p>';

            if ($total === 1) {
                $html[] = '<h1 style="margin:4px 0 0;font-size:26px;font-weight:700;font-family:Consolas,Menlo,monospace;color:#0f172a;">'
                    . self::esc((string)$items[0]['cve_id']) . '</h1>';
            } else {
                $html[] = '<h1 style="margin:4px 0 0;font-size:26px;font-weight:700;color:#0f172a;">'
                    . $total . ' vulnerabilidades</h1>';
            }

            $chips = [];
            foreach ($items as $item) {
                $chips[] = '<a href="https://nvd.nist.gov/vuln/detail/' . rawurlencode((string)$item['cve_id'])
                    . '" target="_blank" rel="noopener noreferrer" style="display:inline-block;margin:2px 4px 2px 0;padding:2px 7px;border-radius:6px;background:#f3f4f6;color:#111827;font-family:Consolas,Menlo,monospace;font-size:11px;text-decoration:none;">'
                    . self::esc((string)$item['cve_id']) . '</a>';
            }
            $html[] = '<div style="margin-top:10px;">' . implode('', $chips) . '</div>';

            $meta = [];
            $meta[] = 'Grupo: <strong>' . self::esc((string)$data['group']) . '</strong>';
            $meta[] = 'Export: ' . self::esc((string)$data['date']);
            if ((string)$data['maxGrade'] !== '') {
                $meta[] = 'Prioridad máxima: <strong>' . self::esc((string)$data['maxGrade']) . '</strong>';
            }
            if ((string)$data['filter'] !== '') {
                $meta[] = 'Filtro: ' . self::esc((string)$data['filter']);
            }
            $html[] = '<p style="margin:8px 0 0;font-size:11px;color:#6b7280;">' . implode(' · ', $meta) . '</p>';

            // Tira de KPIs (tabla: se copia e imprime bien).
            $html[] = '<table data-rd-stack="metrics" style="width:100%;border-collapse:collapse;margin:18px 0 6px;font-size:12px;">'
                . '<tr>'
                . self::kpiCell('CVE', (string)$total)
                . self::kpiCell('En CISA KEV', (string)$data['kev'], (int)$data['kev'] > 0 ? '#b91c1c' : null)
                . self::kpiCell('CVSS máximo', self::maxCvss($items))
                . self::kpiCell('Prioridad máxima', (string)($data['maxGrade'] ?? '—'))
                . '</tr></table>';

            // Tarjetas por CVE.
            $first = true;
            foreach (array_slice($items, 0, self::MAX_FICHAS) as $item) {
                $html[] = self::cardHtml($item, $first ? '' : 'page-break-before:always;');
                $first = false;
            }
            if ($total > self::MAX_FICHAS) {
                $html[] = '<p style="font-size:11px;color:#6b7280;">Se listan ' . self::MAX_FICHAS
                    . ' de ' . $total . ' CVE. El resto está en la consola.</p>';
            }

            // Bloques compactos.
            if ($total > 1) {
                $html[] = self::workTableHtml($items);
                $html[] = self::clustersHtml($data['clusters']);
            }
            $html[] = self::exceptionsHtml($data);
            $html[] = self::verificationHtml($data);
            $html[] = self::decisionsHtml($data);
            if (is_string($data['aiPlan']) && trim($data['aiPlan']) !== '') {
                $html[] = '<h2 style="font-size:15px;font-weight:700;color:#0f172a;margin:28px 0 6px;border-top:1px solid #e5e7eb;padding-top:16px;">Lectura del riesgo (IA)</h2>'
                    . '<p style="font-size:10px;color:#6b7280;margin:0 0 8px;">Generada por tu modelo local a partir de los datos anteriores. Las cifras y prioridades son deterministas.</p>';
                $html[] = function_exists('render_ai_markdown')
                    ? render_ai_markdown((string)$data['aiPlan'])
                    : nl2br(self::esc((string)$data['aiPlan']));
            }

            $html[] = '</div>';
            return implode("\n", $html);
        }

        private static function cardHtml(array $item, string $breakStyle = ''): string
        {
            $cveId = (string)$item['cve_id'];
            $severity = strtolower((string)($item['severity'] ?? ''));
            $colors = self::SEV_COLORS[$severity] ?? self::SEV_COLORS['info'];
            $sevLabel = self::SEV_LABELS[$severity] ?? 'SIN SEVERIDAD';
            $grade = (string)($item['_grade'] ?? '');
            $cvss = $item['cvss'] !== null ? (float)$item['cvss'] : null;
            $epss = $item['epss'] !== null ? (float)$item['epss'] : null;
            $epssPct = $epss !== null ? max(0, min(100, $epss * 100)) : 0;

            $out = [];
            $out[] = '<section style="border-left:4px solid ' . $colors[0] . ';padding:0 0 0 14px;margin:24px 0;' . $breakStyle . 'page-break-inside:avoid;break-inside:avoid;">';

            // Cabecera de la tarjeta.
            $out[] = '<div data-rd-stack="blocks" style="display:flex;align-items:baseline;justify-content:space-between;gap:10px;flex-wrap:wrap;">';
            $out[] = '<h2 style="margin:0;font-size:19px;font-weight:700;font-family:Consolas,Menlo,monospace;color:#0f172a;">' . self::esc($cveId) . '</h2>';
            $badges = [];
            $badges[] = '<span style="display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;background:' . $colors[1] . ';color:' . $colors[2] . ';">' . $sevLabel . '</span>';
            if ($grade !== '') {
                $badges[] = '<span style="display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;background:' . (self::GRADE_COLORS[$grade] ?? '#6b7280') . ';color:#ffffff;">Prioridad ' . self::esc($grade) . '</span>';
            }
            $badges[] = '<a href="https://nvd.nist.gov/vuln/detail/' . rawurlencode($cveId) . '" target="_blank" rel="noopener noreferrer" style="display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600;border:1px solid #e5e7eb;color:#6b7280;text-decoration:none;">NVD ↗</a>';
            $out[] = '<div>' . implode(' ', $badges) . '</div>';
            $out[] = '</div>';

            $out[] = '<p style="margin:6px 0 0;font-size:11px;color:#6b7280;">' . self::esc((string)$item['_reason'])
                . ' · ventana ' . self::esc((string)$item['_window']) . '</p>';

            // Rejilla de métricas.
            $out[] = '<table data-rd-stack="metrics" style="width:100%;border-collapse:collapse;margin:12px 0 0;font-size:12px;"><tr>';
            $out[] = self::metricCell('CVSS', $cvss !== null ? number_format($cvss, 1, '.', '') : '—',
                $cvss !== null ? self::meter(min(100, $cvss * 10), $colors[0]) : '');
            $out[] = self::metricCell('EPSS', $epss !== null ? number_format($epssPct, 2, ',', '') . ' %' : '—',
                $epss !== null ? self::meter($epssPct, '#d97706') : '');
            $out[] = self::metricCell('CISA KEV', (int)($item['is_kev'] ?? 0) === 1 ? 'Sí' : 'No', '', (int)($item['is_kev'] ?? 0) === 1 ? '#b91c1c' : null);
            $out[] = self::metricCell('Equipos expuestos', (string)(int)($item['exposed_machines'] ?? 0), '');
            $out[] = '</tr></table>';

            $out[] = '<p style="margin:4px 0 0;font-size:11px;color:#6b7280;">Detectado '
                . self::esc(self::dateLabel((string)($item['first_detected_at'] ?? '')))
                . ' · ' . (int)($item['age_days'] ?? 0) . ' días en el tenant'
                . ((string)($item['tvm_status'] ?? '') !== '' ? ' · estado ' . self::esc((string)$item['tvm_status']) : '')
                . '</p>';

            // TL;DR: la acción en una línea.
            $out[] = '<p style="margin:8px 0 0;font-size:12.5px;color:#0f172a;font-weight:600;">'
                . self::esc((string)$item['_action']) . ' · ' . (int)($item['exposed_machines'] ?? 0)
                . ' equipos · ventana ' . self::esc((string)$item['_window']) . '</p>';

            // Descripción en viñetas cortas.
            $desc = $item['_desc'];
            $bullets = self::bullets((string)$desc['summary'], 3, 160);
            if ($bullets !== []) {
                $out[] = '<ul style="margin:8px 0 0 18px;padding:0;font-size:12.5px;color:#374151;">';
                foreach ($bullets as $bullet) {
                    $out[] = '<li style="margin:2px 0;">' . self::esc($bullet) . '</li>';
                }
                $out[] = '</ul>';
            }
            $impact = self::bullets((string)$desc['impact'], 2, 160);
            if ($impact !== []) {
                $out[] = '<p style="margin:8px 0 0;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#6b7280;font-weight:700;">Impacto</p>';
                $out[] = '<ul style="margin:2px 0 0 18px;padding:0;font-size:12.5px;color:#374151;">';
                foreach ($impact as $bullet) {
                    $out[] = '<li style="margin:2px 0;">' . self::esc($bullet) . '</li>';
                }
                $out[] = '</ul>';
            }
            $remediation = self::clip((string)$desc['remediation'], 200);
            if ($remediation !== '') {
                $out[] = '<p style="margin:8px 0 0;font-size:12.5px;color:#374151;"><strong>Remediación:</strong> ' . self::esc($remediation) . '</p>';
            }
            if ((string)$desc['fix'] !== '') {
                $out[] = '<p style="margin:4px 0 0;font-size:11px;color:#92400e;">Versión de corrección inferida: '
                    . self::esc((string)$desc['fix']) . ' (confirmar en el boletín)</p>';
            }

            // Exposición en badges.
            $badgesExp = ['<span style="display:inline-block;padding:1px 7px;border-radius:10px;background:#eef2ff;color:#3730a3;font-size:11px;margin:2px 4px 0 0;">'
                . (int)($item['exposed_machines'] ?? 0) . ' equipos</span>'];
            if ((int)($item['has_exploit'] ?? 0) === 1) {
                $badgesExp[] = '<span style="display:inline-block;padding:1px 7px;border-radius:10px;background:#ffedd5;color:#9a3412;font-size:11px;margin:2px 4px 0 0;">exploit</span>';
            }
            if ((int)($item['has_known_threats'] ?? 0) === 1) {
                $badgesExp[] = '<span style="display:inline-block;padding:1px 7px;border-radius:10px;background:#fee2e2;color:#b91c1c;font-size:11px;margin:2px 4px 0 0;">amenazas</span>';
            }
            if ((int)($item['has_alerts'] ?? 0) === 1) {
                $badgesExp[] = '<span style="display:inline-block;padding:1px 7px;border-radius:10px;background:#fee2e2;color:#b91c1c;font-size:11px;margin:2px 4px 0 0;">alerta</span>';
            }
            if ((string)($item['tvm_status'] ?? '') !== '') {
                $badgesExp[] = '<span style="display:inline-block;padding:1px 7px;border-radius:10px;background:#f3f4f6;color:#374151;font-size:11px;margin:2px 4px 0 0;">' . self::esc((string)$item['tvm_status']) . '</span>';
            }
            $out[] = '<div style="margin-top:8px;">' . implode('', $badgesExp) . '</div>';

            // Software: máximo 3 chips y «+N».
            $labels = array_values(array_filter(array_map('trim', explode(',', (string)($item['software_labels'] ?? '')))));
            if ($labels !== []) {
                $chips = [];
                foreach (array_slice($labels, 0, 3) as $label) {
                    $chips[] = '<span style="display:inline-block;padding:1px 7px;border-radius:6px;background:#f3f4f6;color:#111827;font-family:Consolas,Menlo,monospace;font-size:10.5px;margin:2px 4px 0 0;">' . self::esc($label) . '</span>';
                }
                if (count($labels) > 3) {
                    $chips[] = '<span style="display:inline-block;padding:1px 7px;border-radius:6px;background:#f9fafb;color:#6b7280;font-size:10.5px;margin:2px 4px 0 0;" title="' . self::esc(implode(', ', array_slice($labels, 3))) . '">+' . (count($labels) - 3) . '</span>';
                }
                $out[] = '<div style="margin-top:6px;">' . implode('', $chips) . '</div>';
            }

            $related = self::relatedFor((string)$cveId);
            if ($related !== []) {
                $out[] = '<p style="margin:8px 0 0;font-size:11px;color:#6b7280;">Relacionados: '
                    . self::esc(implode(', ', $related)) . '</p>';
            }

            $full = trim((string)($item['description'] ?? ''));
            if ($full !== '') {
                $out[] = '<details class="exposed-full-desc" style="margin:8px 0 0;"><summary style="cursor:pointer;font-size:11px;color:#6b7280;">Descripción completa de Defender</summary>'
                    . '<p style="margin:6px 0 0;font-size:12px;color:#4b5563;">' . nl2br(self::esc($full)) . '</p></details>';
            }

            $out[] = '</section>';
            return implode('', $out);
        }

        private static function kpiCell(string $label, string $value, ?string $color = null): string
        {
            return '<td style="border:1px solid #e5e7eb;padding:8px 10px;vertical-align:top;">'
                . '<span style="display:block;font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:#6b7280;font-weight:700;">' . self::esc($label) . '</span>'
                . '<span style="display:block;font-size:18px;font-weight:700;' . ($color !== null ? 'color:' . $color . ';' : '') . '">' . self::esc($value) . '</span>'
                . '</td>';
        }

        private static function metricCell(string $label, string $value, string $meter = '', ?string $color = null): string
        {
            return '<td style="border-top:1px solid #e5e7eb;padding:8px 10px 8px 0;vertical-align:top;">'
                . '<span style="display:block;font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:#6b7280;font-weight:700;">' . self::esc($label) . '</span>'
                . '<span style="display:block;font-size:15px;font-weight:700;' . ($color !== null ? 'color:' . $color . ';' : '') . '">' . self::esc($value) . '</span>'
                . $meter
                . '</td>';
        }

        private static function meter(float $percent, string $color): string
        {
            $width = max(0, min(100, $percent));
            return '<span style="display:block;height:4px;background:#e5e7eb;border-radius:2px;margin-top:4px;">'
                . '<span style="display:block;height:4px;width:' . number_format($width, 0, '.', '') . '%;background:' . $color . ';border-radius:2px;"></span></span>';
        }

        private static function workTableHtml(array $items): string
        {
            $out = [];
            $out[] = '<h2 style="font-size:15px;font-weight:700;color:#0f172a;margin:28px 0 6px;border-top:1px solid #e5e7eb;padding-top:16px;">Tabla de trabajo</h2>';
            $out[] = '<table style="width:100%;border-collapse:collapse;font-size:11.5px;">'
                . '<thead><tr>'
                . '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5px 7px;text-align:left;">CVE</th>'
                . '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5px 7px;text-align:left;">Prioridad</th>'
                . '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5px 7px;text-align:right;">Equipos</th>'
                . '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5px 7px;text-align:left;">Acción</th>'
                . '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5px 7px;text-align:left;">Responsable</th>'
                . '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5px 7px;text-align:left;">Ventana</th>'
                . '</tr></thead><tbody>';
            foreach (array_slice($items, 0, self::MAX_WORK_ROWS) as $item) {
                $out[] = '<tr>'
                    . '<td style="border:1px solid #d1d5db;padding:5px 7px;font-family:Consolas,Menlo,monospace;">' . self::esc((string)$item['cve_id']) . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px 7px;">' . self::esc((string)$item['_grade'] . ' · ' . (string)$item['_reason']) . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px 7px;text-align:right;">' . (int)($item['exposed_machines'] ?? 0) . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px 7px;">' . self::esc((string)$item['_action']) . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px 7px;color:#6b7280;">por asignar</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px 7px;">' . self::esc((string)$item['_window']) . '</td>'
                    . '</tr>';
            }
            $out[] = '</tbody></table>';
            if (count($items) > self::MAX_WORK_ROWS) {
                $out[] = '<p style="font-size:10px;color:#6b7280;margin:4px 0 0;">Se listan los ' . self::MAX_WORK_ROWS
                    . ' CVE de mayor prioridad de ' . count($items) . '.</p>';
            }
            return implode('', $out);
        }

        private static function clustersHtml(array $clusters): string
        {
            $multi = array_filter($clusters, static fn(array $c): bool => count($c['cves']) > 1);
            $out = [];
            if ($multi === []) {
                $out[] = '<h2 style="font-size:15px;font-weight:700;color:#0f172a;margin:28px 0 6px;border-top:1px solid #e5e7eb;padding-top:16px;">Racimos por software</h2>';
                $out[] = '<p style="margin:0;font-size:12px;color:#4b5563;">Ningún software agrupa a más de un CVE: '
                    . 'no hay racimo y cada vulnerabilidad requiere su propia acción.</p>';
                return implode('', $out);
            }
            $out[] = '<h2 style="font-size:15px;font-weight:700;color:#0f172a;margin:28px 0 6px;border-top:1px solid #e5e7eb;padding-top:16px;">Racimos por software</h2>';
            $out[] = '<table style="width:100%;border-collapse:collapse;font-size:11.5px;"><thead><tr>'
                . '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5px 7px;text-align:left;">Software</th>'
                . '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5px 7px;text-align:right;">CVE</th>'
                . '<th style="border:1px solid #d1d5db;background:#f3f4f6;padding:5px 7px;text-align:left;">Acción única</th>'
                . '</tr></thead><tbody>';
            foreach ($multi as $label => $cluster) {
                $out[] = '<tr>'
                    . '<td style="border:1px solid #d1d5db;padding:5px 7px;">' . self::esc((string)$label) . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px 7px;text-align:right;">' . count($cluster['cves']) . '</td>'
                    . '<td style="border:1px solid #d1d5db;padding:5px 7px;">' . self::esc((string)$cluster['action']) . '</td>'
                    . '</tr>';
            }
            $out[] = '</tbody></table>';
            return implode('', $out);
        }

        private static function exceptionsHtml(array $data): string
        {
            $items = array_values(array_filter($data['items'], static fn(array $i): bool => !empty($i['_exception'])));
            $out = [];
            $out[] = '<h2 style="font-size:15px;font-weight:700;color:#0f172a;margin:28px 0 6px;border-top:1px solid #e5e7eb;padding-top:16px;">Excepciones</h2>';
            if ($items === []) {
                $out[] = '<p style="margin:0;font-size:12px;color:#4b5563;">El export no contiene CVE en estado '
                    . '<code>UnderException</code> ni <code>PartialException</code>.</p>';
                return implode('', $out);
            }
            $out[] = '<p style="margin:0;font-size:12px;color:#4b5563;">' . count($items)
                . ' CVE en excepción según Defender. El export no trae aprobador ni caducidad: complétalos en el registro de excepciones.</p>';
            $out[] = '<ul style="margin:6px 0 0 18px;padding:0;font-size:12px;color:#374151;">';
            foreach ($items as $item) {
                $out[] = '<li>' . self::esc((string)$item['cve_id']) . ' · ' . self::esc((string)$item['tvm_status'])
                    . ' · ' . (int)($item['exposed_machines'] ?? 0) . ' equipos</li>';
            }
            $out[] = '</ul>';
            return implode('', $out);
        }

        private static function verificationHtml(array $data): string
        {
            $kev = (int)$data['kev'];
            $p1 = (int)($data['tiers']['p1'] ?? 0);
            $p2 = (int)($data['tiers']['p2'] ?? 0);
            return '<h2 style="font-size:15px;font-weight:700;color:#0f172a;margin:28px 0 6px;border-top:1px solid #e5e7eb;padding-top:16px;">Verificación</h2>'
                . '<ul style="margin:0 0 0 18px;padding:0;font-size:12px;color:#374151;">'
                . '<li><strong>P1:</strong> ' . $p1 . ' → 0 en 72 h · <strong>P2:</strong> ' . $p2 . ' → 0 en 15 días.</li>'
                . '<li><strong>CISA KEV:</strong> ' . $kev . ' → 0; son los únicos con explotación confirmada.</li>'
                . '<li><strong>Equipos expuestos:</strong> máximo actual ' . (int)$data['maxMachines'] . '; debe bajar en el próximo export.</li>'
                . '<li><strong>Demostración:</strong> captura del activo o del gestor de parches. Que un CVE desaparezca del export no prueba el parche.</li>'
                . '<li><strong>Siguiente revisión:</strong> volver a importar y comparar KEV, equipos y CVE abiertos.</li>'
                . '</ul>';
        }

        private static function decisionsHtml(array $data): string
        {
            return '<h2 style="font-size:15px;font-weight:700;color:#0f172a;margin:28px 0 6px;border-top:1px solid #e5e7eb;padding-top:16px;">Decisiones</h2>'
                . '<ul style="margin:0 0 0 18px;padding:0;font-size:12px;color:#374151;">'
                . '<li><strong>D1 · Excepciones:</strong> aprobar o renovar las ' . (int)$data['exceptions'] . ' con responsable y caducidad.</li>'
                . '<li><strong>D2 · Responsables:</strong> asignar owner y ventana a los CVE A+/A (prioridad máxima).</li>'
                . '<li><strong>D3 · Ciclo:</strong> confirmar la ventana de parcheo de emergencia y la verificación en el próximo export.</li>'
                . '</ul>';
        }

        /* =================================================================
         * Markdown (para .md y «Copiar Markdown»)
         * ============================================================== */

        private static function renderMarkdown(array $data): string
        {
            $items = $data['items'];
            $total = (int)$data['total'];
            $md = [];
            $md[] = '# Informe de vulnerabilidad';
            $md[] = '';
            $md[] = $total === 1 ? '## ' . $items[0]['cve_id'] : '**' . $total . ' vulnerabilidades**';
            $md[] = '';
            $md[] = '- Grupo: ' . self::cell((string)$data['group']);
            $md[] = '- Export: ' . self::cell((string)$data['date']);
            if ((string)$data['maxGrade'] !== '') {
                $md[] = '- Prioridad máxima: ' . self::cell((string)$data['maxGrade']);
            }
            if ((string)$data['filter'] !== '') {
                $md[] = '- Filtro de origen: ' . self::cell((string)$data['filter']);
            }
            $md[] = '';
            $md[] = '| CVE | En CISA KEV | CVSS máx. | Prioridad máx. |';
            $md[] = '| --- | --- | --- | --- |';
            $md[] = '| ' . $total . ' | ' . (int)$data['kev'] . ' | ' . self::maxCvss($items) . ' | '
                . self::cell((string)($data['maxGrade'] ?? '—')) . ' |';
            $md[] = '';

            foreach (array_slice($items, 0, self::MAX_FICHAS) as $item) {
                $md[] = '---';
                $md[] = '';
                $md[] = '## ' . $item['cve_id'];
                $md[] = '';
                $md[] = '| Métrica | Valor |';
                $md[] = '| --- | --- |';
                $md[] = '| Severidad | ' . self::cell((string)($item['severity'] ?? '—')) . ' |';
                $md[] = '| CVSS | ' . ($item['cvss'] !== null ? number_format((float)$item['cvss'], 1, '.', '') : '—') . ' |';
                $md[] = '| EPSS | ' . ($item['epss'] !== null ? number_format((float)$item['epss'], 4, '.', '') : '—') . ' |';
                $md[] = '| CISA KEV | ' . ((int)($item['is_kev'] ?? 0) === 1 ? 'Sí' : 'No') . ' |';
                $md[] = '| Prioridad | ' . self::cell((string)($item['_grade'] ?? '—') . ' · ' . (string)$item['_reason']) . ' |';
                $md[] = '| Equipos expuestos | ' . (int)($item['exposed_machines'] ?? 0) . ' |';
                $md[] = '| Antigüedad | ' . (int)($item['age_days'] ?? 0) . ' días |';
                $md[] = '| Estado TVM | ' . self::cell((string)($item['tvm_status'] ?? '—')) . ' |';
                $md[] = '| Software | ' . self::cell((string)($item['software_labels'] ?? '—')) . ' |';
                $md[] = '';
                if ((string)$item['_desc']['summary'] !== '') {
                    $md[] = '**Qué es**';
                    $md[] = '';
                    foreach (self::bullets((string)$item['_desc']['summary'], 3, 160) as $bullet) {
                        $md[] = '- ' . $bullet;
                    }
                    $md[] = '';
                }
                if ((string)$item['_desc']['impact'] !== '') {
                    $md[] = '**Impacto**';
                    $md[] = '';
                    foreach (self::bullets((string)$item['_desc']['impact'], 2, 160) as $bullet) {
                        $md[] = '- ' . $bullet;
                    }
                    $md[] = '';
                }
                if ((string)$item['_desc']['remediation'] !== '') {
                    $md[] = '**Remediación.** ' . self::clip((string)$item['_desc']['remediation'], 200);
                    $md[] = '';
                }
                if ((string)$item['_desc']['fix'] !== '') {
                    $md[] = '> Versión de corrección inferida: ' . (string)$item['_desc']['fix']
                        . '. Confirmar en el boletín del fabricante.';
                    $md[] = '';
                }
                $md[] = '**Acción:** ' . self::cell((string)$item['_action']);
                $md[] = '';
                $related = self::relatedFor((string)$item['cve_id']);
                if ($related !== []) {
                    $md[] = '**CVEs relacionados:** ' . implode(', ', $related);
                    $md[] = '';
                }
            }

            if ($total > 1) {
                $md[] = '---';
                $md[] = '';
                $md[] = '## Tabla de trabajo';
                $md[] = '';
                $md[] = '| CVE | Prioridad | Equipos | Acción | Responsable | Ventana |';
                $md[] = '| --- | --- | --- | --- | --- | --- |';
                foreach (array_slice($items, 0, self::MAX_WORK_ROWS) as $item) {
                    $md[] = '| ' . self::cell((string)$item['cve_id'])
                        . ' | ' . self::cell((string)$item['_grade'] . ' · ' . (string)$item['_reason'])
                        . ' | ' . (int)($item['exposed_machines'] ?? 0)
                        . ' | ' . self::cell((string)$item['_action'])
                        . ' | por asignar | ' . self::cell((string)$item['_window']) . ' |';
                }
                $md[] = '';
            }

            $md[] = '## Verificación';
            $md[] = '';
            $md[] = '- P1: ' . (int)($data['tiers']['p1'] ?? 0) . ' → 0 en 72 h · P2: ' . (int)($data['tiers']['p2'] ?? 0) . ' → 0 en 15 días.';
            $md[] = '- CISA KEV: ' . (int)$data['kev'] . ' → 0.';
            $md[] = '- Equipos expuestos: máximo ' . (int)$data['maxMachines'] . '; debe bajar en el próximo export.';
            $md[] = '- Que un CVE desaparezca del export no prueba el parche: adjuntar evidencia del activo.';
            $md[] = '';
            $md[] = '## Decisiones';
            $md[] = '';
            $md[] = '- D1 · Excepciones: aprobar o renovar las ' . (int)$data['exceptions'] . ' con responsable y caducidad.';
            $md[] = '- D2 · Responsables: asignar owner y ventana a los CVE A+/A.';
            $md[] = '- D3 · Ciclo: confirmar ventana de emergencia y verificación en el próximo export.';
            $md[] = '';

            if (is_string($data['aiPlan']) && trim($data['aiPlan']) !== '') {
                $md[] = '## Lectura del riesgo (IA)';
                $md[] = '';
                $md[] = '> Generada por tu modelo local a partir de los datos anteriores.';
                $md[] = '';
                $md[] = trim((string)$data['aiPlan']);
                $md[] = '';
            }

            return implode("\n", $md);
        }

        /* =================================================================
         * Utilidades
         * ============================================================== */

        private static function priorityGrade(array $row): string
        {
            if (class_exists('CveReportAi')) {
                $grade = CveReportAi::calculatePriority(
                    $row['cvss'] !== null ? (float)$row['cvss'] : null,
                    $row['epss'] !== null ? (float)$row['epss'] : null,
                    (int)($row['is_kev'] ?? 0) === 1,
                    (int)($row['has_exploit'] ?? 0) === 1
                );
                return $grade !== null ? (string)$grade : '';
            }
            return '';
        }

        private static function relatedFor(string $cveId): array
        {
            if (!class_exists('ExposedConsoleStore')) {
                return [];
            }
            $index = ExposedConsoleStore::mentionIndex();
            $ids = [];
            foreach ((array)($index['out'][$cveId] ?? []) as $id) {
                $ids[$id] = true;
            }
            foreach ((array)($index['in'][$cveId] ?? []) as $id) {
                if ($id !== $cveId) {
                    $ids[$id] = true;
                }
            }
            return array_slice(array_keys($ids), 0, 6);
        }

        private static function maxCvss(array $items): string
        {
            $max = null;
            foreach ($items as $item) {
                if ($item['cvss'] !== null) {
                    $max = $max === null ? (float)$item['cvss'] : max($max, (float)$item['cvss']);
                }
            }
            return $max !== null ? number_format($max, 1, '.', '') : '—';
        }

        private static function filterLabel(array $group): string
        {
            $filters = safe_json_decode((string)($group['filters_json'] ?? ''), []);
            if (!is_array($filters) || $filters === []) {
                return '';
            }
            $parts = [];
            foreach ($filters as $key => $value) {
                if ($key === 'sort') {
                    continue;
                }
                if (is_array($value)) {
                    $parts[] = $key . '=' . implode('/', array_map('strval', $value));
                } elseif ((string)$value !== '') {
                    $parts[] = $key . '=' . (string)$value;
                }
            }
            return implode(' · ', array_slice($parts, 0, 4));
        }

        /**
         * Racimos por software principal.
         *
         * @return array<string,array{cves:array<int,string>,machines:int,tier:string,action:string,rank:int}>
         */
        private static function softwareClusters(array $items): array
        {
            $clusters = [];
            foreach ($items as $item) {
                $main = trim(explode(',', (string)($item['software_labels'] ?? ''))[0] ?? '');
                if ($main === '') {
                    continue;
                }
                if (!isset($clusters[$main])) {
                    $clusters[$main] = ['cves' => [], 'machines' => 0, 'tier' => 'p4', 'action' => '', 'rank' => 9];
                }
                $clusters[$main]['cves'][] = (string)$item['cve_id'];
                $clusters[$main]['machines'] = max($clusters[$main]['machines'], (int)($item['exposed_machines'] ?? 0));
                $rank = ExposedPriority::rank((string)$item['_tier']);
                if ($rank < $clusters[$main]['rank']) {
                    $clusters[$main]['rank'] = $rank;
                    $clusters[$main]['tier'] = (string)$item['_label'];
                    $clusters[$main]['action'] = (string)$item['_action'];
                }
            }
            uasort($clusters, static fn(array $a, array $b): int => $a['rank'] <=> $b['rank']
                ?: $b['machines'] <=> $a['machines']);
            return $clusters;
        }

        private static function actionFor(array $item): string
        {
            $fix = (string)($item['_desc']['fix'] ?? '');
            if ($fix !== '') {
                return 'Actualizar a ' . $fix . ' (versión inferida)';
            }
            $remediation = (string)($item['_desc']['remediation'] ?? '');
            if ($remediation !== '') {
                return ExposedPriority::sentences($remediation, 1);
            }
            return 'Aplicar la actualización del fabricante y verificar en el activo';
        }

        private static function dateLabel(string $value): string
        {
            $value = trim($value);
            if ($value === '') {
                return 'sin fecha';
            }
            $ts = strtotime($value);
            return $ts === false ? $value : date('d/m/Y', $ts);
        }

        private static function cell(string $value): string
        {
            $value = trim(preg_replace('/\s+/u', ' ', $value) ?? $value);
            return str_replace(['|', "\n", "\r"], ['/', ' ', ' '], $value);
        }

        /**
         * Convierte un párrafo en viñetas cortas (frases), sin cortar palabras.
         *
         * @return string[]
         */
        private static function bullets(string $text, int $max = 3, int $clip = 160): array
        {
            $text = trim($text);
            if ($text === '') {
                return [];
            }
            $parts = preg_split('/(?<=[.!?])\s+/', $text) ?: [];
            $out = [];
            foreach (array_slice($parts, 0, max(1, $max)) as $sentence) {
                $sentence = self::clip($sentence, $clip);
                if ($sentence !== '') {
                    $out[] = $sentence;
                }
            }
            if (count($parts) > $max && $out !== []) {
                $last = count($out) - 1;
                if (!str_ends_with($out[$last], '…')) {
                    $out[$last] .= ' …';
                }
            }
            return $out;
        }

        /** Recorta por caracteres en un límite de palabra. */
        private static function clip(string $text, int $max): string
        {
            $text = trim(preg_replace('/\s+/u', ' ', $text) ?? $text);
            if ($max <= 0 || self::len($text) <= $max) {
                return $text;
            }
            $cut = function_exists('mb_substr') ? mb_substr($text, 0, $max) : substr($text, 0, $max);
            $space = strrpos($cut, ' ');
            if ($space !== false && $space > (int)($max * 0.6)) {
                $cut = substr($cut, 0, $space);
            }
            return rtrim($cut, " ,;.") . '…';
        }

        private static function len(string $text): int
        {
            return function_exists('mb_strlen') ? mb_strlen($text) : strlen($text);
        }

        private static function esc(string $value): string
        {
            return function_exists('e') ? e($value) : htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }
    }
}
