<?php
/**
 * exposed_report_dossier.php — Informe de remediación de un grupo (v0.4.26.2).
 *
 * Compone el documento siguiendo la estructura de la práctica recomendada:
 *
 *   1 Control · 2 Resumen ejecutivo (5 frases) · 3 Tablero · 4 Prioridad
 *   5 Plan por fases + escenarios NIST · 6 Análisis de la IA (si existe)
 *   7 Racimos por software · 8 Tabla de trabajo · 9 Exposición residual
 *   10 Verificación · 11 Decisiones
 *   Anexo A inventario · B fichas P1/P2 · C relaciones · D definiciones
 *
 * Todo lo determinista lo calcula la aplicación (ExposedPriority). La IA solo
 * aporta la lectura del riesgo. Nunca se inventan owners, equipos ni fechas.
 */

declare(strict_types=1);

if (!class_exists('ExposedReportDossier')) {
    final class ExposedReportDossier
    {
        /** Filas de la tabla de trabajo y del inventario anexo. */
        private const MAX_WORK_ROWS = 40;
        private const MAX_INVENTORY_ROWS = 300;
        private const MAX_FICHAS = 60;

        /**
         * @param array<string,mixed>            $group
         * @param array<int,array<string,mixed>> $rows
         * @param array<string,mixed>            $options Umbrales de prioridad
         * @return array{markdown:string,html:string,tiers:array<string,int>,p1p2:int,kev:int,with_report:int,without:int}
         */
        public static function build(array $group, array $rows, array $options = [], ?string $aiPlan = null): array
        {
            $items = [];
            $tiers = ['p1' => 0, 'p2' => 0, 'p3' => 0, 'p4' => 0];
            $kev = 0;
            $exceptions = 0;
            $exploit = 0;
            $maxMachines = 0;
            $maxAge = 0;

            foreach ($rows as $row) {
                $priority = ExposedPriority::classify($row, $options);
                $desc = ExposedPriority::describe((string)($row['description'] ?? ''));
                $row['_tier'] = $priority['tier'];
                $row['_label'] = $priority['label'];
                $row['_reason'] = $priority['reason'];
                $row['_window'] = $priority['window'];
                $row['_ssvc'] = $priority['ssvc'];
                $row['_desc'] = $desc;
                $row['_action'] = self::actionFor($row);
                $items[] = $row;

                $tiers[$priority['tier']] = ($tiers[$priority['tier']] ?? 0) + 1;
                if ((int)($row['is_kev'] ?? 0) === 1) {
                    $kev++;
                }
                if ((int)($row['has_exploit'] ?? 0) === 1) {
                    $exploit++;
                }
                if (!empty($priority['exception'])) {
                    $exceptions++;
                }
                $maxMachines = max($maxMachines, (int)($row['exposed_machines'] ?? 0));
                $maxAge = max($maxAge, (int)($row['age_days'] ?? 0));
            }

            usort($items, static function (array $a, array $b): int {
                return ExposedPriority::rank((string)$a['_tier']) <=> ExposedPriority::rank((string)$b['_tier'])
                    ?: ((int)($b['exposed_machines'] ?? 0) <=> (int)($a['exposed_machines'] ?? 0))
                    ?: ((int)($b['age_days'] ?? 0) <=> (int)($a['age_days'] ?? 0))
                    ?: strcmp((string)$a['cve_id'], (string)$b['cve_id']);
            });

            $groupName = trim((string)($group['name'] ?? 'Grupo de análisis'));
            $total = count($items);
            $software = self::softwareClusters($items);
            $p1p2 = $tiers['p1'] + $tiers['p2'];
            $worst = $items[0] ?? null;

            $md = [];
            $md[] = '# Informe de remediación · ' . self::cell($groupName);
            $md[] = '';

            // 1. Control del documento.
            $md[] = '## 1. Control del documento';
            $md[] = '';
            $md[] = '| Campo | Valor |';
            $md[] = '| --- | --- |';
            $md[] = '| Grupo | ' . self::cell($groupName) . ' |';
            $md[] = '| Fecha del informe | ' . date('d/m/Y H:i') . ' |';
            $md[] = '| Fuente | Export de Microsoft Defender TVM (lista maestra del tenant) |';
            $md[] = '| Alcance | ' . $total . ' CVE · ' . count($software) . ' software principal |';
            $md[] = '| Límite del dato | El export web de Defender corta en 6.000 filas y agrega por CVE |';
            $md[] = '| Sin datos | Identidad de equipos, propietario del activo y criticidad de negocio |';
            $md[] = '';

            // 2. Resumen ejecutivo (5 frases).
            $md[] = '## 2. Resumen ejecutivo';
            $md[] = '';
            $md[] = self::executiveSummary($groupName, $items, $tiers, $kev, $exceptions, $maxMachines, $worst, $total);
            $md[] = '';

            // 3. Tablero.
            $md[] = '## 3. Tablero';
            $md[] = '';
            $md[] = '| Indicador | Valor | Objetivo |';
            $md[] = '| --- | --- | --- |';
            $md[] = '| CVE con prioridad P1 (Immediate) | ' . $tiers['p1'] . ' | 0 en 72 h |';
            $md[] = '| CVE con prioridad P2 (Out-of-cycle) | ' . $tiers['p2'] . ' | 0 en 15 días |';
            $md[] = '| CVE en CISA KEV | ' . $kev . ' | 0 |';
            $md[] = '| CVE con exploit disponible | ' . $exploit . ' | seguimiento |';
            $md[] = '| Excepciones TVM registradas | ' . $exceptions . ' | con aprobador y caducidad |';
            $md[] = '| Máximo de equipos expuestos por CVE | ' . $maxMachines . ' | bajar del máximo actual |';
            $md[] = '| Antigüedad máxima en el tenant | ' . $maxAge . ' días | según SLA |';
            $md[] = '';

            // 4. Prioridad.
            $md[] = '## 4. Modelo de prioridad';
            $md[] = '';
            $md[] = 'La prioridad no es el CVSS: manda la explotación confirmada (KEV), las alertas '
                . 'activas y el EPSS, y después la exposición real del tenant. Cada CVE lleva su '
                . 'motivo y su ventana; el tier equivale al resultado de CISA SSVC.';
            $md[] = '';
            $md[] = '| Tier | CVE | Ventana | SSVC |';
            $md[] = '| --- | --- | --- | --- |';
            foreach (ExposedPriority::TIERS as $key => $meta) {
                $md[] = '| ' . $meta['label'] . ' | ' . (int)($tiers[$key] ?? 0)
                    . ' | ' . $meta['window'] . ' | ' . $meta['ssvc'] . ' |';
            }
            $md[] = '';

            // 5. Plan por fases.
            $md[] = '## 5. Plan de actuación por fases';
            $byTier = [];
            foreach ($items as $item) {
                $byTier[(string)$item['_tier']][] = $item;
            }
            foreach (ExposedPriority::TIERS as $key => $meta) {
                $list = $byTier[$key] ?? [];
                $md[] = '### ' . $meta['label'] . ' (' . $meta['window'] . ')';
                $md[] = '';
                if ($list === []) {
                    $md[] = 'Sin CVE en este tier.';
                    $md[] = '';
                    continue;
                }
                $md[] = '| CVE | Motivo | Equipos | Acción |';
                $md[] = '| --- | --- | --- | --- |';
                foreach (array_slice($list, 0, 12) as $item) {
                    $md[] = '| ' . self::cell((string)$item['cve_id'])
                        . ' | ' . self::cell((string)$item['_reason'])
                        . ' | ' . (int)($item['exposed_machines'] ?? 0)
                        . ' | ' . self::cell((string)$item['_action']) . ' |';
                }
                if (count($list) > 12) {
                    $md[] = '';
                    $md[] = '… y ' . (count($list) - 12) . ' CVE más en este tier (ver Anexo A).';
                }
                $md[] = '';
            }

            // Escenarios NIST SP 800-40 r4.
            $noFix = 0;
            foreach ($items as $item) {
                if ((string)$item['_desc']['fix'] === '' && !in_array($item['_tier'], ['p1', 'p2'], true)) {
                    $noFix++;
                }
            }
            $md[] = '### Escenarios de mantenimiento (NIST SP 800-40 r4)';
            $md[] = '';
            $md[] = '| Escenario | CVE | Qué hacer |';
            $md[] = '| --- | --- | --- |';
            $md[] = '| Parcheo de emergencia | ' . $tiers['p1'] . ' | Aplicar en la ventana de 24-72 h |';
            $md[] = '| Parcheo fuera de ciclo | ' . $tiers['p2'] . ' | Ventana de 7-15 días |';
            $md[] = '| Parcheo rutinario | ' . $tiers['p3'] . ' | Ciclo mensual de actualizaciones |';
            $md[] = '| Mitigación / no parcheable | ' . max($noFix, $tiers['p4']) . ' | Sin versión de corrección en el dato: control compensatorio |';
            $md[] = '';

            // 6. Análisis de la IA.
            if ($aiPlan !== null && trim($aiPlan) !== '') {
                $md[] = '## 6. Análisis de la IA';
                $md[] = '';
                $md[] = '> Lectura del riesgo y justificación de prioridades generada por el modelo '
                    . 'local. Las tablas, tiers y ventanas son deterministas y no dependen del modelo.';
                $md[] = '';
                $md[] = trim($aiPlan);
                $md[] = '';
            }

            // 7. Racimos por software.
            $md[] = '## 7. Agrupación por software (racimos)';
            $md[] = '';
            $md[] = 'Una sola acción por producto corrige varios CVE. Es la vista que usa el equipo '
                . 'de sistemas para planificar la ventana.';
            $md[] = '';
            $md[] = '| Software | CVE | Equipos máx. | Tier máx. | Acción |';
            $md[] = '| --- | --- | --- | --- | --- |';
            foreach ($software as $label => $cluster) {
                $md[] = '| ' . self::cell((string)$label)
                    . ' | ' . count($cluster['cves'])
                    . ' | ' . (int)$cluster['machines']
                    . ' | ' . $cluster['tier']
                    . ' | ' . self::cell($cluster['action']) . ' |';
            }
            $md[] = '';

            // 8. Tabla de trabajo.
            $md[] = '## 8. Tabla de trabajo';
            $md[] = '';
            $md[] = '| CVE | Prioridad y motivo | Equipos | Acción | Responsable | Ventana |';
            $md[] = '| --- | --- | --- | --- | --- | --- |';
            foreach (array_slice($items, 0, self::MAX_WORK_ROWS) as $item) {
                $md[] = '| ' . self::cell((string)$item['cve_id'])
                    . ' | ' . self::cell($item['_label'] . ': ' . $item['_reason'])
                    . ' | ' . (int)($item['exposed_machines'] ?? 0)
                    . ' | ' . self::cell((string)$item['_action'])
                    . ' | por asignar | ' . self::cell((string)$item['_window']) . ' |';
            }
            if ($total > self::MAX_WORK_ROWS) {
                $md[] = '';
                $md[] = 'Se listan los ' . self::MAX_WORK_ROWS . ' CVE de mayor prioridad de ' . $total
                    . '. El resto está en el Anexo A.';
            }
            $md[] = '';

            // 9. Exposición residual.
            $md[] = '## 9. Exposición residual y excepciones';
            $md[] = '';
            if ($exceptions === 0) {
                $md[] = 'El export no contiene CVE en estado `UnderException` ni `PartialException`. '
                    . 'Si existen excepciones internas, no están reflejadas en este dato.';
            } else {
                $md[] = 'Hay **' . $exceptions . ' CVE en excepción** según Defender. El export no '
                    . 'incluye aprobador ni fecha de caducidad: hay que completarlos en el registro de '
                    . 'excepciones antes de aceptarlos.';
                $md[] = '';
                foreach (array_slice(array_values(array_filter($items, static function (array $item): bool {
                    return in_array((string)($item['tvm_status'] ?? ''), ['UnderException', 'PartialException'], true);
                })), 0, 10) as $item) {
                    $md[] = '- ' . $item['cve_id'] . ' · ' . $item['tvm_status']
                        . ' · ' . (int)($item['exposed_machines'] ?? 0) . ' equipos';
                }
            }
            $md[] = '';

            // 10. Verificación.
            $md[] = '## 10. Verificación';
            $md[] = '';
            $md[] = '- **P1:** ' . $tiers['p1'] . ' → 0 en 72 h; **P2:** ' . $tiers['p2'] . ' → 0 en 15 días.';
            $md[] = '- **KEV:** ' . $kev . ' → 0; son los únicos con explotación confirmada.';
            $md[] = '- **Equipos expuestos:** el máximo actual es ' . $maxMachines
                . '; debe bajar en el siguiente export.';
            $md[] = '- **Demostración:** adjuntar captura del estado del activo o del gestor de parches. '
                . 'Que un CVE desaparezca del export **no** prueba que se haya parcheado.';
            $md[] = '- **Siguiente revisión:** volver a importar el export y comparar P1, KEV y equipos.';
            $md[] = '';

            // 11. Decisiones.
            $md[] = '## 11. Decisiones que se piden';
            $md[] = '';
            $md[] = '- **D1 · Excepciones:** aprobar o renovar las ' . $exceptions
                . ' excepciones con responsable y fecha de caducidad.';
            $md[] = '- **D2 · Responsables:** asignar owner y ventana a los ' . $p1p2
                . ' CVE P1/P2 (el export no identifica equipos ni propietarios).';
            $md[] = '- **D3 · Ciclo:** confirmar la ventana de parcheo de emergencia y la verificación '
                . 'en el próximo export.';
            $md[] = '';

            // Anexo A. Inventario.
            $md[] = '## Anexo A. Inventario completo';
            $md[] = '';
            $md[] = '| CVE | Severidad | CVSS | EPSS | Equipos | Tier | Software |';
            $md[] = '| --- | --- | --- | --- | --- | --- | --- |';
            foreach (array_slice($items, 0, self::MAX_INVENTORY_ROWS) as $item) {
                $md[] = '| ' . self::cell((string)$item['cve_id'])
                    . ' | ' . self::cell((string)($item['severity'] ?? '—'))
                    . ' | ' . ($item['cvss'] !== null ? number_format((float)$item['cvss'], 1) : '—')
                    . ' | ' . ($item['epss'] !== null ? number_format((float)$item['epss'], 4) : '—')
                    . ' | ' . (int)($item['exposed_machines'] ?? 0)
                    . ' | ' . self::cell((string)$item['_label'])
                    . ' | ' . self::cell((string)($item['software_labels'] ?? '—')) . ' |';
            }
            if ($total > self::MAX_INVENTORY_ROWS) {
                $md[] = '';
                $md[] = 'Se listan ' . self::MAX_INVENTORY_ROWS . ' de ' . $total . ' CVE.';
            }
            $md[] = '';

            // Anexo B. Fichas P1/P2.
            $md[] = '## Anexo B. Fichas de los CVE P1 y P2';
            $md[] = '';
            $fiches = array_values(array_filter($items, static function (array $item): bool {
                return in_array((string)$item['_tier'], ['p1', 'p2'], true);
            }));
            $withReport = 0;
            $analyses = [];
            if ($fiches !== [] && class_exists('ExposedReportEnrichment')) {
                try {
                    $analyses = ExposedReportEnrichment::storedAnalyses(array_map(
                        static fn(array $item): string => (string)$item['cve_id'],
                        $fiches
                    ));
                } catch (Throwable $e) {
                    $analyses = [];
                }
            }
            if ($fiches === []) {
                $md[] = 'No hay CVE en P1 ni P2: no se generan fichas.';
                $md[] = '';
            }
            foreach (array_slice($fiches, 0, self::MAX_FICHAS) as $item) {
                $cveId = (string)$item['cve_id'];
                $md[] = '### ' . $cveId . ' · ' . $item['_label'];
                $md[] = '';
                $md[] = '**Por qué está aquí:** ' . $item['_reason'] . ' · ventana '
                    . $item['_window'] . ' · ' . (int)($item['exposed_machines'] ?? 0) . ' equipos.';
                $md[] = '';
                if ((string)$item['_desc']['summary'] !== '') {
                    $md[] = '**Qué es:** ' . $item['_desc']['summary'];
                    $md[] = '';
                }
                if ((string)$item['_desc']['impact'] !== '') {
                    $md[] = '**Impacto:** ' . $item['_desc']['impact'];
                    $md[] = '';
                }
                $md[] = '**Acción:** ' . $item['_action'];
                $md[] = '';
                if ((string)$item['_desc']['fix'] !== '') {
                    $md[] = '> Versión de corrección inferida de la descripción: '
                        . $item['_desc']['fix'] . '. Confirmar en el boletín del fabricante.';
                    $md[] = '';
                }
                $labels = array_values(array_filter(array_map(
                    'trim',
                    explode(',', (string)($item['software_labels'] ?? ''))
                )));
                if ($labels !== []) {
                    $md[] = '**Software afectado:** ' . implode(', ', array_slice($labels, 0, 6))
                        . (count($labels) > 6 ? '…' : '');
                    $md[] = '';
                }
                if (isset($analyses[$cveId])) {
                    $withReport++;
                    $md[] = '**Informe técnico de tu IA**';
                    foreach ((array)$analyses[$cveId]['sections'] as $section) {
                        $title = trim((string)($section['title'] ?? ''));
                        if ($title !== '') {
                            $md[] = '';
                            $md[] = '**' . $title . '**';
                        }
                        foreach ((array)($section['bullets'] ?? []) as $bullet) {
                            $md[] = '- ' . (string)$bullet;
                        }
                        foreach ((array)($section['paragraphs'] ?? []) as $paragraph) {
                            $md[] = '';
                            $md[] = (string)$paragraph;
                        }
                    }
                    $md[] = '';
                }
                $full = trim((string)($item['description'] ?? ''));
                if ($full !== '') {
                    $md[] = '<details><summary>Descripción completa de Defender</summary>';
                    $md[] = '';
                    $md[] = self::paragraphs($full);
                    $md[] = '';
                    $md[] = '</details>';
                    $md[] = '';
                }
            }
            if (count($fiches) > self::MAX_FICHAS) {
                $md[] = 'Se listan ' . self::MAX_FICHAS . ' de ' . count($fiches) . ' fichas P1/P2.';
                $md[] = '';
            }

            // Anexo C. Relaciones.
            $md[] = '## Anexo C. Relaciones entre los CVE del grupo';
            $md[] = '';
            $md[] = '### Por software principal';
            $md[] = '';
            if ($software === []) {
                $md[] = 'Sin software asociado en el export.';
                $md[] = '';
            } else {
                $clusters = array_filter($software, static fn(array $c): bool => count($c['cves']) > 1);
                if ($clusters === []) {
                    $md[] = 'Ningún software agrupa a más de un CVE del grupo.';
                } else {
                    $md[] = '| Software | CVE del grupo |';
                    $md[] = '| --- | --- |';
                    foreach ($clusters as $label => $cluster) {
                        $md[] = '| ' . self::cell((string)$label) . ' | '
                            . self::cell(implode(', ', $cluster['cves'])) . ' |';
                    }
                }
                $md[] = '';
            }

            $md[] = '### Menciones en la descripción de Defender';
            $md[] = '';
            $groupIds = [];
            foreach ($items as $item) {
                $groupIds[(string)$item['cve_id']] = true;
            }
            $mentions = class_exists('ExposedConsoleStore') ? ExposedConsoleStore::mentionIndex() : ['out' => []];
            $pairs = [];
            foreach ($items as $item) {
                $id = (string)$item['cve_id'];
                $hits = [];
                foreach ((array)($mentions['out'][$id] ?? []) as $other) {
                    if (isset($groupIds[$other])) {
                        $hits[$other] = true;
                    }
                }
                if ($hits !== []) {
                    $pairs[] = '- ' . $id . ' → ' . implode(', ', array_keys($hits));
                }
            }
            if ($pairs === []) {
                $md[] = 'Ningún CVE del grupo cita a otro del grupo en su descripción.';
            } else {
                foreach ($pairs as $line) {
                    $md[] = $line;
                }
            }
            $md[] = '';

            // Anexo D. Definiciones.
            $md[] = '## Anexo D. Definiciones y fuentes';
            $md[] = '';
            $md[] = '- **CVSS:** severidad técnica intrínseca. No es prioridad de remediación (FIRST CVSS v4.0).';
            $md[] = '- **EPSS:** probabilidad de explotación en los próximos 30 días (FIRST).';
            $md[] = '- **CISA KEV:** catálogo de vulnerabilidades con explotación confirmada.';
            $md[] = '- **SSVC:** categorización de CISA con resultados Immediate / Out-of-cycle / Scheduled / Defer.';
            $md[] = '- **NIST SP 800-40 r4:** planes de parcheo rutinario, de emergencia, mitigación de emergencia y activos no parcheables.';
            $md[] = '- **Equipos expuestos:** contador agregado de Defender por CVE; no identifica servidores concretos.';
            $md[] = '';

            $markdown = implode("\n", $md);
            $html = function_exists('render_ai_markdown')
                ? render_ai_markdown($markdown)
                : nl2br(e($markdown));

            return [
                'markdown'    => $markdown,
                'html'        => $html,
                'tiers'       => $tiers,
                'p1p2'        => $p1p2,
                'kev'         => $kev,
                'with_report' => $withReport,
                'without'     => max(0, count($fiches) - $withReport),
            ];
        }

        /**
         * Racimos por software principal.
         *
         * @param array<int,array<string,mixed>> $items
         * @return array<string,array{cves:array<int,string>,machines:int,tier:string,action:string}>
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

        /** Acción recomendada por CVE (determinista). */
        private static function actionFor(array $item): string
        {
            $fix = (string)($item['_desc']['fix'] ?? '');
            if ($fix !== '') {
                return 'Actualizar a ' . $fix . ' (versión inferida de la descripción)';
            }
            $remediation = (string)($item['_desc']['remediation'] ?? '');
            if ($remediation !== '') {
                return ExposedPriority::sentences($remediation, 1);
            }
            return 'Aplicar la actualización del fabricante y verificar en el activo';
        }

        /** Resumen ejecutivo de cinco frases, en el orden recomendado. */
        private static function executiveSummary(
            string $groupName,
            array $items,
            array $tiers,
            int $kev,
            int $exceptions,
            int $maxMachines,
            ?array $worst,
            int $total
        ): string {
            if ($total === 0) {
                return 'El grupo «' . $groupName . '» no contiene CVE.';
            }

            $first = 'El grupo «' . $groupName . '» reúne ' . $total . ' CVE, de los que '
                . $tiers['p1'] . ' son P1 y deben resolverse en 24-72 h y ' . $tiers['p2']
                . ' son P2 con ventana de 7-15 días.';

            $second = $kev > 0
                ? 'Hay ' . $kev . ' CVE en CISA KEV (explotación confirmada), que es el dato que '
                    . 'más pesa en la prioridad por delante del CVSS.'
                : 'Ningún CVE del grupo figura en CISA KEV, así que la prioridad se apoya en exploit '
                    . 'disponible, alertas y EPSS.';

            $third = 'El dato procede del export de Defender TVM: es agregado por CVE, no identifica '
                . 'servidores concretos ni propietarios, y el máximo de equipos expuestos es '
                . $maxMachines . '.';

            $fourth = $worst !== null
                ? 'El mayor riesgo es ' . $worst['cve_id'] . ' (' . $worst['_label']
                    . ', ' . (int)($worst['exposed_machines'] ?? 0) . ' equipos): ' . $worst['_reason'] . '.'
                : 'No se ha podido determinar un CVE de mayor riesgo.';

            $fifth = 'Se pide aprobar o renovar las ' . $exceptions . ' excepciones vigentes, asignar '
                . 'responsable y ventana a los CVE P1/P2, y confirmar la verificación en el próximo export.';

            return implode(' ', [$first, $second, $third, $fourth, $fifth]);
        }

        /** Texto a párrafos sin romper tablas ni listas. */
        private static function paragraphs(string $text): string
        {
            $text = preg_replace('/\s+(Impact:|Remediation:|AdditionalInformation:)/u', "\n\n**$1** ", $text) ?? $text;
            $out = [];
            foreach (preg_split('/\n\s*\n/', trim($text)) ?: [] as $paragraph) {
                $paragraph = trim(preg_replace('/\s+/u', ' ', $paragraph) ?? $paragraph);
                if ($paragraph !== '') {
                    $out[] = $paragraph;
                }
            }
            return implode("\n\n", $out);
        }

        /** Escapa una celda de tabla Markdown. */
        private static function cell(string $value): string
        {
            $value = trim(preg_replace('/\s+/u', ' ', $value) ?? $value);
            return str_replace(['|', "\n", "\r"], ['/', ' ', ' '], $value);
        }
    }
}
