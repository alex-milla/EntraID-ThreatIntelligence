<?php
/**
 * Módulo: Equipos expuestos (exposed_report)
 *
 * v0.4.25 — Consola del tenant basada en el export completo de Defender TVM
 * («Vulnerabilities Export» con el filtro Affects my organization). El CSV se
 * guarda como snapshot y se filtra en pantalla con los mismos bloques que el
 * portal (Severity, Age, Threats, Exposed devices, Status, Tags inferidos).
 * Los CVE filtrados se agrupan para analizarlos con IA y generar un plan de
 * actuación documentado.
 *
 * El flujo clásico (KQL de Advanced Hunting → informe de servidores) se
 * conserva íntegro en la pestaña «Informe KQL»: no se ha tocado su contrato.
 *
 * Rutas:
 *   GET  /modules/exposed_report                    consola (+ informe KQL)
 *   GET  /modules/exposed_report/group/{id}         grupo de análisis
 *   POST /modules/exposed_report/upload             snapshot del export TVM
 *   POST /modules/exposed_report/snapshot/delete    borra un snapshot
 *   POST /modules/exposed_report/groups/create      crea un grupo
 *   POST /modules/exposed_report/group/{id}/plan    plan de actuación IA
 *   POST /modules/exposed_report/group/{id}/analyze informes por CVE en cola
 *   POST /modules/exposed_report/group/{id}/remove-cve
 *   POST /modules/exposed_report/group/{id}/delete
 *   POST /modules/exposed_report/generate           informe KQL (clásico)
 *   POST /modules/exposed_report/analyze-cves       análisis CVE (clásico)
 */

declare(strict_types=1);

require_once INCLUDES_PATH . '/exposed_report_parser.php';
require_once INCLUDES_PATH . '/exposed_report_enrichment.php';
require_once INCLUDES_PATH . '/exposed_console_store.php';

class Module_ExposedReport extends BaseModule
{
    /** Pestaña activa al renderizar (console | kql). */
    private string $activeTab = 'console';

    public function key(): string
    {
        return 'exposed_report';
    }

    public function name(): string
    {
        return 'Equipos expuestos';
    }

    public function description(): string
    {
        return 'Consola de vulnerabilidades del tenant (Defender TVM) y plan de actuación';
    }

    public function version(): string
    {
        return '2.0.0';
    }

    /** No usa Microsoft Graph. */
    public function requiredPermissions(): array
    {
        return [];
    }

    /** No sincroniza por tenant: el CSV se sube a mano. */
    public function isSyncable(): bool
    {
        return false;
    }

    public function sync(int $tenantId): array
    {
        return ['success' => false, 'error' => 'Equipos expuestos no se sincroniza por tenant.'];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Equipos expuestos',
            'url'   => base_url('modules/exposed_report'),
            'icon'  => 'shield',
            'group' => 'Seguridad',
            'after' => 'remediation',
        ];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                     'handler' => [$this, 'index']],
            ['method' => 'GET',  'pattern' => 'group/{id}',            'handler' => [$this, 'showGroup']],
            ['method' => 'POST', 'pattern' => 'upload',                'handler' => [$this, 'upload']],
            ['method' => 'POST', 'pattern' => 'snapshot/delete',       'handler' => [$this, 'deleteSnapshot']],
            ['method' => 'POST', 'pattern' => 'groups/create',         'handler' => [$this, 'createGroup']],
            ['method' => 'POST', 'pattern' => 'group/{id}/plan',       'handler' => [$this, 'generatePlan']],
            ['method' => 'POST', 'pattern' => 'group/{id}/analyze',    'handler' => [$this, 'analyzeGroup']],
            ['method' => 'POST', 'pattern' => 'group/{id}/remove-cve', 'handler' => [$this, 'removeGroupCve']],
            ['method' => 'POST', 'pattern' => 'group/{id}/delete',     'handler' => [$this, 'deleteGroup']],
            // Flujo clásico (sin cambios de contrato).
            ['method' => 'POST', 'pattern' => 'generate',              'handler' => [$this, 'generate']],
            ['method' => 'POST', 'pattern' => 'analyze-cves',          'handler' => [$this, 'analyzeCves']],
        ];
    }

    /* =====================================================================
     * Consola del tenant (v0.4.25)
     * ================================================================== */

    public function index(array $params = []): void
    {
        Auth::require();
        $this->renderPage();
    }

    /** POST upload — guarda el export completo como snapshot. */
    public function upload(array $params = []): void
    {
        Auth::require();

        $back = base_url('modules/exposed_report');

        // Si PHP ya ha tirado el cuerpo (post_max_size), no hay CSRF ni fichero:
        // mejor explicarlo que devolver «token inválido».
        $maxUpload = ExposedConsoleStore::maxUploadBytes();
        $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($contentLength > 0 && $contentLength > $maxUpload) {
            flash('error', 'El CSV ocupa ' . ExposedConsoleStore::formatBytes($contentLength)
                . ' y este servidor acepta hasta ' . ExposedConsoleStore::formatBytes($maxUpload)
                . '. Sube un export más pequeño o sube post_max_size/upload_max_filesize en php.ini.');
            redirect($back);
        }

        Csrf::validateOrFail();

        $target = ((string)($_POST['target'] ?? 'new')) === 'merge' ? 'merge' : 'new';
        $targetId = (int)($_POST['snapshot_id'] ?? 0);
        if ($target === 'merge' && $targetId <= 0) {
            flash('error', 'Elige un snapshot válido para fusionar los CSV.');
            redirect($back);
        }
        if ($target === 'new') {
            $targetId = 0;
        }

        $files = $this->uploadedFiles('csv');
        if ($files === []) {
            $error = UPLOAD_ERR_NO_FILE;
            foreach (($_FILES['csv']['error'] ?? []) as $code) {
                if ((int)$code !== UPLOAD_ERR_OK && (int)$code !== UPLOAD_ERR_NO_FILE) {
                    $error = (int)$code;
                    break;
                }
            }
            flash('error', $this->uploadError($error));
            redirect($back);
        }

        // Validación previa de TODO el lote: o entran todos los ficheros o
        // ninguno, para no dejar el snapshot a medias sin explicación.
        $errors = [];
        foreach ($files as $file) {
            $label = (string)($file['name'] ?? 'CSV');
            $size = (int)($file['size'] ?? 0);
            if ((int)($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                $errors[] = $label . ': ' . $this->uploadError((int)$file['error']);
                continue;
            }
            if ($size <= 0) {
                $errors[] = $label . ': el fichero está vacío.';
                continue;
            }
            if ($size > CveTvmImport::CONSOLE_MAX_BYTES) {
                $errors[] = $label . ': ocupa ' . ExposedConsoleStore::formatBytes($size)
                    . ' y el máximo por fichero es ' . ExposedConsoleStore::formatBytes(CveTvmImport::CONSOLE_MAX_BYTES) . '.';
                continue;
            }
            $extension = strtolower(pathinfo($label, PATHINFO_EXTENSION));
            if ($extension !== '' && !in_array($extension, ['csv', 'txt'], true)) {
                $errors[] = $label . ': no es un CSV (solo .csv o .txt).';
            }
        }
        if ($errors !== []) {
            flash('error', 'No se ha importado nada. ' . implode(' · ', array_slice($errors, 0, 4)));
            redirect($back . ($targetId > 0 ? '?snapshot=' . $targetId : ''));
        }

        $snapshotId = 0;
        $inserted = 0;
        $updated = 0;
        $unchanged = 0;
        $skipped = 0;
        $processed = 0;
        $truncated = [];
        $bytes = 0;
        $failures = [];

        foreach ($files as $file) {
            $label = trim((string)($file['name'] ?? 'export-tvm.csv'));
            $tmpName = (string)($file['tmp_name'] ?? '');
            if ($tmpName === '' || !is_uploaded_file($tmpName)) {
                $failures[] = $label . ': no se pudo leer el fichero subido.';
                continue;
            }
            $content = file_get_contents($tmpName);
            if ($content === false || trim($content) === '') {
                $failures[] = $label . ': contenido vacío.';
                continue;
            }

            $res = ExposedConsoleStore::importCsv(
                $content,
                $label,
                Auth::id(),
                $snapshotId > 0 ? $snapshotId : $targetId
            );
            if (!$res['ok']) {
                $failures[] = $label . ': ' . $res['error'];
                continue;
            }

            $snapshotId = (int)$res['snapshot_id'];
            $targetId = $snapshotId;
            $inserted += (int)$res['inserted'];
            $updated += (int)$res['updated'];
            $unchanged += (int)$res['unchanged'];
            $skipped += (int)$res['skipped'];
            $processed += (int)$res['rows'];
            $bytes += (int)($file['size'] ?? 0);
            if (!empty($res['truncated'])) {
                $truncated[] = $label . ' (' . (string)$res['range'] . ')';
            }
        }

        if ($snapshotId === 0) {
            flash('error', 'No se pudo importar ningún CSV. ' . implode(' · ', array_slice($failures, 0, 3)));
            redirect($back);
        }

        $snapshot = ExposedConsoleStore::getSnapshot($snapshotId);
        $total = (int)($snapshot['rows_imported'] ?? 0);

        log_activity('exposed_report.snapshot_imported', [
            'snapshot'  => $snapshotId,
            'files'     => count($files),
            'rows'      => $processed,
            'inserted'  => $inserted,
            'updated'   => $updated,
            'unchanged' => $unchanged,
            'skipped'   => $skipped,
            'bytes'     => $bytes,
            'merged'    => $targetId > 0,
        ]);

        $summary = 'Snapshot #' . $snapshotId . ' con ' . $total . ' CVE únicos'
            . (count($files) > 1 ? ' (' . count($files) . ' ficheros)' : '')
            . ': ' . $inserted . ' nuevos, ' . $updated . ' actualizados, '
            . $unchanged . ' sin cambios (omitidos).';
        if ($inserted === 0 && $updated === 0) {
            $summary .= ' No había información nueva que guardar.';
        }
        if ($failures !== []) {
            $summary .= ' ' . count($failures) . ' fichero(s) con error: '
                . implode(' · ', array_slice($failures, 0, 3));
        }
        flash('success', $summary);

        if ($truncated !== []) {
            flash('warning', 'Defender corta cada export web en 6.000 filas. '
                . implode(' · ', $truncated)
                . '. Si el tenant tiene más, exporta otro tramo (por edad o severidad) y '
                . 'súbelo a este mismo snapshot para completarlo sin duplicar.');
        }

        redirect($back . '?snapshot=' . $snapshotId);
    }

    /**
     * Normaliza $_FILES de un campo multiple a una lista de ficheros.
     *
     * @return array<int,array<string,mixed>>
     */
    private function uploadedFiles(string $field): array
    {
        $raw = $_FILES[$field] ?? null;
        if (!is_array($raw) || !isset($raw['name'])) {
            return [];
        }
        if (!is_array($raw['name'])) {
            return [$raw];
        }

        $files = [];
        foreach ($raw['name'] as $index => $name) {
            if (!is_scalar($name) || (string)$name === '') {
                continue;
            }
            $files[] = [
                'name'     => (string)$name,
                'type'     => (string)($raw['type'][$index] ?? ''),
                'tmp_name' => (string)($raw['tmp_name'][$index] ?? ''),
                'error'    => (int)($raw['error'][$index] ?? UPLOAD_ERR_NO_FILE),
                'size'     => (int)($raw['size'][$index] ?? 0),
            ];
        }
        return $files;
    }

    /** POST snapshot/delete */
    public function deleteSnapshot(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $res = ExposedConsoleStore::deleteSnapshot((int)($_POST['snapshot_id'] ?? 0));
        flash($res['ok'] ? 'success' : 'error', $res['ok'] ? 'Snapshot eliminado.' : $res['error']);
        redirect(base_url('modules/exposed_report'));
    }

    /** POST groups/create — crea un grupo a partir de la selección o del filtro. */
    public function createGroup(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $snapshotId = (int)($_POST['snapshot_id'] ?? 0);
        $filters = ExposedConsoleStore::filtersFromInput($_POST);
        $ids = $_POST['cve_ids'] ?? [];
        $ids = is_array($ids) ? $ids : [];

        $selectAll = (string)($_POST['select_all'] ?? '') === '1';
        if ($selectAll && $snapshotId > 0) {
            $ids = array_merge($ids, ExposedConsoleStore::allIds($snapshotId, $filters));
        }

        $name = (string)($_POST['group_name'] ?? '');
        $res = ExposedConsoleStore::createGroup($name, $snapshotId, $filters, $ids, Auth::id());

        $query = http_build_query(array_merge(['snapshot' => $snapshotId], ExposedConsoleStore::filtersToQuery($filters)));
        $back = base_url('modules/exposed_report') . ($query !== '' ? '?' . $query : '');

        if (!$res['ok']) {
            flash('error', $res['error']);
            redirect($back);
        }

        log_activity('exposed_report.group_created', [
            'group'    => (int)$res['group_id'],
            'snapshot' => $snapshotId,
            'cves'     => count($ids),
            'all'      => $selectAll,
        ]);

        flash('success', 'Grupo creado con ' . count($ids) . ' CVE. Ya puedes generar su plan de actuación.');
        redirect(base_url('modules/exposed_report/group/' . (int)$res['group_id']));
    }

    /** GET group/{id} */
    public function showGroup(array $params = []): void
    {
        Auth::require();
        $groupId = (int)($params['id'] ?? 0);
        $this->renderGroup($groupId);
    }

    /** POST group/{id}/remove-cve */
    public function removeGroupCve(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $groupId = (int)($params['id'] ?? 0);
        $res = ExposedConsoleStore::removeCve($groupId, (string)($_POST['cve_id'] ?? ''));
        flash($res['ok'] ? 'success' : 'error', $res['ok'] ? 'CVE quitado del grupo.' : $res['error']);
        redirect(base_url('modules/exposed_report/group/' . $groupId));
    }

    /** POST group/{id}/delete */
    public function deleteGroup(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $groupId = (int)($params['id'] ?? 0);
        $res = ExposedConsoleStore::deleteGroup($groupId);
        flash($res['ok'] ? 'success' : 'error', $res['ok'] ? 'Grupo eliminado.' : $res['error']);
        redirect(base_url('modules/exposed_report'));
    }

    /** POST group/{id}/analyze — encola los informes por CVE del grupo. */
    public function analyzeGroup(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $groupId = (int)($params['id'] ?? 0);
        $group = ExposedConsoleStore::getGroup($groupId);
        if ($group === null) {
            http_response_code(404);
            $this->renderGroup(0, ['error' => 'El grupo no existe.']);
            return;
        }

        $rows = ExposedConsoleStore::groupRows($groupId);
        $ids = array_map(static fn(array $row): string => (string)$row['cve_id'], $rows);
        $available = ExposedConsoleStore::catalogCves($ids);
        $skipped = array_values(array_diff($ids, $available));
        $queue = array_slice($available, 0, ExposedReportEnrichment::MAX_ANALYSIS_QUEUE);

        if ($queue === []) {
            $this->renderGroup($groupId, [
                'error' => 'Ninguno de los CVE del grupo está en el catálogo local, así que no hay datos que analizar. '
                    . 'Actualiza el catálogo desde el módulo CVE y vuelve a intentarlo.',
            ]);
            return;
        }

        $llm = ModuleManager::get('llm');
        if (!$llm instanceof Module_Llm || !$llm->isConfigured()) {
            $this->renderGroup($groupId, [
                'error' => 'La IA no está configurada. Revisa el perfil en Admin → APIs antes de encolar análisis.',
            ]);
            return;
        }

        try {
            $token = bin2hex(random_bytes(24));
            $reportId = CveDatabase::insert(
                "INSERT INTO cve_ai_reports
                 (cve_ids, title, status, token, ai_profile_id, generated_by, no_ai, mode, total_items)
                 VALUES (?, ?, 'pending', ?, ?, ?, 0, 'extended', ?)",
                [
                    json_encode($queue, JSON_UNESCAPED_SLASHES),
                    'Equipos expuestos · grupo #' . $groupId . ' · ' . date('d/m/Y H:i'),
                    $token,
                    llm_task_profile('cve_report'),
                    Auth::id(),
                    count($queue),
                ]
            );

            CveReportAi::ensureReportItems($reportId);

            $useFpm = function_exists('fastcgi_finish_request');
            log_activity('exposed_report.group_analyses_queued', [
                'group'   => $groupId,
                'report'  => $reportId,
                'cves'    => count($queue),
                'skipped' => count($skipped),
            ]);

            $notice = count($queue) . ' análisis por CVE en cola (informe IA #' . $reportId . '). '
                . ($useFpm
                    ? 'Se generan en segundo plano; en unos minutos estarán disponibles en el módulo CVE.'
                    : 'Se están generando ahora mismo en esta petición.')
                . ($skipped !== []
                    ? ' ' . count($skipped) . ' CVE del grupo no están en el catálogo local y se han omitido.'
                    : '');

            $this->renderGroup($groupId, ['queueNotice' => $notice]);

            if ($useFpm) {
                @ignore_user_abort(true);
                @set_time_limit(0);
                finish_response();
            }
            try {
                CveReportAi::runPending($token);
            } catch (Throwable $e) {
                app_log('error', 'exposed_report', 'Análisis por CVE del grupo fallido', [
                    'group'  => $groupId,
                    'report' => $reportId,
                    'error'  => $e->getMessage(),
                ]);
            }
            if ($useFpm) {
                exit;
            }
        } catch (Throwable $e) {
            $this->renderGroup($groupId, [
                'error' => 'No se pudieron encolar los análisis: ' . $e->getMessage(),
            ]);
        }
    }

    /* =====================================================================
     * Plan de actuación del grupo
     * ================================================================== */

    /** POST group/{id}/plan */
    public function generatePlan(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $groupId = (int)($params['id'] ?? 0);
        $group = ExposedConsoleStore::getGroup($groupId);
        if ($group === null) {
            http_response_code(404);
            $this->renderGroup(0, ['error' => 'El grupo no existe.']);
            return;
        }

        $profileId = max(0, (int)($_POST['profile_id'] ?? 0));
        $rows = ExposedConsoleStore::groupRows($groupId);
        if ($rows === []) {
            $this->renderGroup($groupId, ['error' => 'El grupo no tiene CVE. Añade alguno antes de generar el plan.']);
            return;
        }

        $llm = ModuleManager::get('llm');
        if (!$llm instanceof Module_Llm || !$llm->isConfigured($profileId > 0 ? $profileId : null)) {
            $this->renderGroup($groupId, [
                'error' => 'La IA no está configurada. Revisa el perfil en Admin → APIs antes de generar el plan.',
            ]);
            return;
        }

        $context = $this->buildPlanContext($group, $rows);

        $catalog = llm_prompts_catalog();
        $systemDefault = (string)($catalog['llm.exposed.action_plan']['default'] ?? '');
        $system = llm_prompt('llm.exposed.action_plan', $systemDefault);

        $startedAt = microtime(true);
        $res = llm_run('exposed_action_plan', $system, $context['text'], [
            'profile_id'  => $profileId,
            'max_tokens'  => 4500,
            'temperature' => 0.15,
            'think'       => false,
        ]);
        $elapsedMs = (int)round((microtime(true) - $startedAt) * 1000);

        if (empty($res['success'])) {
            app_log('error', 'exposed_report', 'Plan de actuación fallido', [
                'group' => $groupId,
                'error' => (string)($res['error'] ?? 'error desconocido'),
            ]);
            $this->renderGroup($groupId, [
                'error' => 'La IA no pudo generar el plan: ' . (string)($res['error'] ?? 'error desconocido'),
                'planContext' => $context,
            ]);
            return;
        }

        $markdown = trim((string)($res['content'] ?? ''));
        if ($markdown === '') {
            $this->renderGroup($groupId, [
                'error' => 'El modelo no devolvió contenido. Repite la generación o cambia de perfil de IA.',
                'planContext' => $context,
            ]);
            return;
        }

        // El anexo técnico lo añade la aplicación: cifras rastreables al CSV.
        $annex = $this->buildPlanAnnex($group, $rows);
        $markdown = rtrim($markdown) . "\n\n---\n\n" . $annex;

        ExposedConsoleStore::savePlan(
            $groupId,
            $markdown,
            count($rows),
            (string)($res['model'] ?? ''),
            $profileId
        );

        log_activity('exposed_report.action_plan_generated', [
            'group'    => $groupId,
            'cves'     => count($rows),
            'analyzed' => (int)$context['detailed'],
            'ms'       => $elapsedMs,
            'profile'  => $profileId,
        ]);

        $this->renderGroup($groupId, [
            'planFresh'   => true,
            'elapsedMs'   => $elapsedMs,
            'planContext' => $context,
        ]);
    }

    /**
     * Contexto determinista del plan: cifras, software y CVE prioritarios.
     *
     * @param array<int,array<string,mixed>> $rows
     * @return array{text:string,total:int,detailed:int,truncated:int}
     */
    private function buildPlanContext(array $group, array $rows, int $maxDetail = 60): array
    {
        $total = count($rows);
        $bySeverity = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0, '' => 0];
        $age = ['0-30' => 0, '30-60' => 0, '60-90' => 0, '90+' => 0];
        $exploit = 0;
        $threats = 0;
        $kev = 0;
        $zeroDay = 0;
        $noUpdate = 0;
        $machinesMax = 0;
        $machinesSum = 0;
        $ageMax = 0;
        $ageMin = null;
        $software = [];
        $missing = 0;

        foreach ($rows as $row) {
            $sev = (string)($row['severity'] ?? '');
            $bySeverity[array_key_exists($sev, $bySeverity) ? $sev : '']++;

            if ($row['severity'] === null && $row['age_days'] === null) {
                $missing++;
                continue;
            }

            $days = (int)($row['age_days'] ?? 0);
            if ($days <= 30) {
                $age['0-30']++;
            } elseif ($days <= 60) {
                $age['30-60']++;
            } elseif ($days <= 90) {
                $age['60-90']++;
            } else {
                $age['90+']++;
            }
            $ageMax = max($ageMax, $days);
            $ageMin = $ageMin === null ? $days : min($ageMin, $days);

            if ((int)($row['has_exploit'] ?? 0) === 1) {
                $exploit++;
            }
            if ((int)($row['has_known_threats'] ?? 0) === 1) {
                $threats++;
            }
            if ((int)($row['is_kev'] ?? 0) === 1) {
                $kev++;
            }
            if ((int)($row['zero_day'] ?? 0) === 1) {
                $zeroDay++;
            }
            if ((int)($row['no_security_update'] ?? 0) === 1) {
                $noUpdate++;
            }

            $machines = (int)($row['exposed_machines'] ?? 0);
            $machinesMax = max($machinesMax, $machines);
            $machinesSum += $machines;

            foreach (explode(',', (string)($row['software_labels'] ?? '')) as $label) {
                $label = trim($label);
                if ($label === '') {
                    continue;
                }
                if (!isset($software[$label])) {
                    $software[$label] = ['cves' => 0, 'machines' => 0];
                }
                $software[$label]['cves']++;
                $software[$label]['machines'] = max($software[$label]['machines'], $machines);
            }
        }

        arsort($software);
        uasort($software, static fn(array $a, array $b): int => $b['cves'] <=> $a['cves']);
        $topSoftware = array_slice($software, 0, 12, true);

        $filters = safe_json_decode((string)($group['filters_json'] ?? ''), []);
        $filterText = $this->describeFilters(is_array($filters) ? $filters : []);

        $lines = [];
        $lines[] = '# Contexto del grupo de análisis';
        $lines[] = '';
        $lines[] = '- Grupo: ' . (string)($group['name'] ?? '');
        $lines[] = '- Snapshot: ' . (string)($group['filename'] ?? 'sin fichero')
            . (!empty($group['export_date']) ? ' · export del ' . (string)$group['export_date'] : '');
        $lines[] = '- Filtro de origen: ' . $filterText;
        $lines[] = '- CVE en el grupo: ' . $total;
        $lines[] = '- Sin datos TVM en el snapshot actual: ' . $missing;
        $lines[] = '- Severidad: ' . implode(' · ', [
            'Critical ' . $bySeverity['critical'],
            'High ' . $bySeverity['high'],
            'Medium ' . $bySeverity['medium'],
            'Low ' . $bySeverity['low'],
            'Informativa ' . $bySeverity['info'],
        ]);
        $lines[] = '- Antigüedad: 0-30 días ' . $age['0-30'] . ' · 30-60 ' . $age['30-60']
            . ' · 60-90 ' . $age['60-90'] . ' · 90+ ' . $age['90+']
            . ' · máxima ' . $ageMax . ' días' . ($ageMin !== null ? ' · mínima ' . $ageMin . ' días' : '');
        $lines[] = '- Equipos expuestos (contador TVM del tenant): máximo ' . $machinesMax
            . ' · suma ' . $machinesSum
            . ($total > 0 ? ' · media ' . (int)round($machinesSum / max(1, $total)) : '');
        $lines[] = '- Amenazas: con exploit ' . $exploit . ' · con amenazas conocidas ' . $threats
            . ' · en CISA KEV ' . $kev . ' · zero-day inferido ' . $zeroDay
            . ' · sin actualización inferida ' . $noUpdate;
        $lines[] = '';
        $lines[] = '## Software principal (por número de CVE del grupo)';
        $lines[] = '';
        if ($topSoftware === []) {
            $lines[] = 'Sin software asociado en el CSV.';
        } else {
            $lines[] = '| Software | CVE | Equipos expuestos (máx.) |';
            $lines[] = '| --- | --- | --- |';
            foreach ($topSoftware as $label => $info) {
                $lines[] = '| ' . $label . ' | ' . (int)$info['cves'] . ' | ' . (int)$info['machines'] . ' |';
            }
        }
        $lines[] = '';

        $detailed = min($total, max(1, $maxDetail));
        $lines[] = '## CVE analizados en detalle (' . $detailed . ' de ' . $total . ')';
        $lines[] = '';
        $lines[] = '| CVE | Severidad | CVSS | EPSS | Edad (días) | Equipos | Exploit | Amenaza | KEV | Software | Resumen |';
        $lines[] = '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |';

        $used = 0;
        $chars = 0;
        foreach ($rows as $row) {
            if ($used >= $detailed) {
                break;
            }
            if ($row['severity'] === null && $row['age_days'] === null) {
                continue;
            }
            $summary = $this->clipText((string)($row['description'] ?? ''), 320);
            $softwareLabel = (string)($row['software_labels'] ?? '');
            $softwareLabel = trim(explode(',', $softwareLabel)[0] ?? '');
            $line = '| ' . (string)$row['cve_id']
                . ' | ' . ($row['severity'] !== null ? (string)$row['severity'] : 'sin datos')
                . ' | ' . ($row['cvss'] !== null ? number_format((float)$row['cvss'], 1) : '—')
                . ' | ' . ($row['epss'] !== null ? number_format((float)$row['epss'], 4) : '—')
                . ' | ' . ($row['age_days'] !== null ? (int)$row['age_days'] : '—')
                . ' | ' . (int)($row['exposed_machines'] ?? 0)
                . ' | ' . ((int)($row['has_exploit'] ?? 0) === 1 ? 'sí' : 'no')
                . ' | ' . ((int)($row['has_known_threats'] ?? 0) === 1 ? 'sí' : 'no')
                . ' | ' . ((int)($row['is_kev'] ?? 0) === 1 ? 'sí' : 'no')
                . ' | ' . ($softwareLabel !== '' ? $softwareLabel : '—')
                . ' | ' . ($summary !== '' ? $summary : '—')
                . ' |';
            // Tope de contexto: si el modelo tiene poca ventana, llm_run recorta
            // el final; mejor cortar por nuestra cuenta y avisar.
            if ($chars + strlen($line) > 48000) {
                break;
            }
            $chars += strlen($line);
            $lines[] = $line;
            $used++;
        }

        return [
            'text'      => implode("\n", $lines),
            'total'     => $total,
            'detailed'  => $used,
            'truncated' => $total - $used,
        ];
    }

    /**
     * Anexo determinista del plan: todos los CVE del grupo con sus datos.
     *
     * @param array<int,array<string,mixed>> $rows
     */
    private function buildPlanAnnex(array $group, array $rows): string
    {
        $out = [];
        $out[] = '## Anexo A. CVE del grupo (datos del export de Defender)';
        $out[] = '';
        $out[] = 'Lo añade la aplicación, no la IA: cada dato es rastreable al snapshot '
            . (string)($group['filename'] ?? '') . '.';
        $out[] = '';
        $out[] = '| CVE | Severidad | CVSS | EPSS | Edad | Equipos | Exploit | Amenaza | KEV | Estado TVM | Software |';
        $out[] = '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |';

        $shown = 0;
        $max = 300;
        foreach ($rows as $row) {
            if ($shown >= $max) {
                break;
            }
            $out[] = '| ' . (string)$row['cve_id']
                . ' | ' . ($row['severity'] !== null ? (string)$row['severity'] : '—')
                . ' | ' . ($row['cvss'] !== null ? number_format((float)$row['cvss'], 1) : '—')
                . ' | ' . ($row['epss'] !== null ? number_format((float)$row['epss'], 4) : '—')
                . ' | ' . ($row['age_days'] !== null ? (int)$row['age_days'] . ' d' : '—')
                . ' | ' . (int)($row['exposed_machines'] ?? 0)
                . ' | ' . ((int)($row['has_exploit'] ?? 0) === 1 ? 'sí' : 'no')
                . ' | ' . ((int)($row['has_known_threats'] ?? 0) === 1 ? 'sí' : 'no')
                . ' | ' . ((int)($row['is_kev'] ?? 0) === 1 ? 'sí' : 'no')
                . ' | ' . ((string)($row['tvm_status'] ?? '') !== '' ? (string)$row['tvm_status'] : '—')
                . ' | ' . ((string)($row['software_labels'] ?? '') !== '' ? (string)$row['software_labels'] : '—')
                . ' |';
            $shown++;
        }

        if (count($rows) > $shown) {
            $out[] = '';
            $out[] = 'Se listan ' . $shown . ' de ' . count($rows) . ' CVE del grupo. '
                . 'El resto está disponible en la consola y en la base de datos local.';
        }

        return implode("\n", $out);
    }

    /** @param array<string,mixed> $filters */
    private function describeFilters(array $filters): string
    {
        $parts = [];
        foreach (['severity', 'age', 'threats', 'tags', 'status'] as $key) {
            if (!empty($filters[$key]) && is_array($filters[$key])) {
                $parts[] = $key . ': ' . implode('/', array_map('strval', $filters[$key]));
            }
        }
        if ((int)($filters['machines'] ?? 0) > 0) {
            $parts[] = 'equipos >= ' . (int)$filters['machines'];
        }
        if (!empty($filters['software'])) {
            $parts[] = 'software: ' . (is_array($filters['software'])
                ? implode(' ', array_map('strval', $filters['software']))
                : (string)$filters['software']);
        }
        if (!empty($filters['q'])) {
            $parts[] = 'búsqueda: ' . (string)$filters['q'];
        }
        return $parts === [] ? 'todos los CVE del snapshot (sin filtros)' : implode(' · ', $parts);
    }

    private function clipText(string $value, int $max): string
    {
        $value = preg_replace('/\s+/u', ' ', $value) ?? $value;
        $value = str_replace(['Generated by AI', '|'], ['', '/'], $value);
        $value = trim($value);
        return ExposedConsoleStore::strCut($value, max(0, $max));
    }

    /* =====================================================================
     * Generación del informe (flujo clásico)
     * ================================================================== */

    public function generate(array $params = []): void
    {
        $this->activeTab = 'kql';        $mode = ((string)($_POST['mode'] ?? 'compact')) === 'detailed' ? 'detailed' : 'compact';
        $profileId = max(0, (int)($_POST['profile_id'] ?? 0));

        // El detalle de CVEs solo aplica al informe detallado (el compacto va
        // sin anexos por contrato de la especificación).
        $enrich = (string)($_POST['enrich'] ?? ExposedReportEnrichment::SOURCE_CATALOG);
        if (!array_key_exists($enrich, ExposedReportEnrichment::SOURCES)) {
            $enrich = ExposedReportEnrichment::SOURCE_CATALOG;
        }
        if ($mode !== 'detailed') {
            $enrich = ExposedReportEnrichment::SOURCE_NONE;
        }

        $specOverride = (string)($_POST['spec_json'] ?? '');

        $llm = ModuleManager::get('llm');
        if (!$llm instanceof Module_Llm || !$llm->isConfigured($profileId > 0 ? $profileId : null)) {
            $this->renderPage([
                'error'  => 'La IA no está configurada. Revisa el perfil en Admin → APIs antes de generar informes.',
                'mode'   => $mode,
            ]);
            return;
        }

        $file = $_FILES['csv'] ?? null;
        $uploadError = is_array($file) ? (int)($file['error'] ?? UPLOAD_ERR_NO_FILE) : UPLOAD_ERR_NO_FILE;
        if (!is_array($file) || $uploadError !== UPLOAD_ERR_OK) {
            $this->renderPage([
                'error' => $this->uploadError($uploadError),
                'mode'  => $mode,
            ]);
            return;
        }

        $size = (int)($file['size'] ?? 0);
        if ($size <= 0) {
            $this->renderPage(['error' => 'El fichero está vacío.', 'mode' => $mode]);
            return;
        }
        $maxUpload = ExposedReportParser::maxUploadBytes();
        if ($size > $maxUpload) {
            $this->renderPage([
                'error' => 'El CSV supera el límite de ' . ExposedReportParser::formatBytes($maxUpload)
                    . '. Divide el export y genera un informe por grupo.',
                'mode'  => $mode,
            ]);
            return;
        }

        $tmpName = (string)($file['tmp_name'] ?? '');
        if ($tmpName === '' || !is_uploaded_file($tmpName)) {
            $this->renderPage(['error' => 'No se pudo leer el fichero subido.', 'mode' => $mode]);
            return;
        }

        $filename = trim((string)($file['name'] ?? 'export.csv'));
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if ($extension !== '' && !in_array($extension, ['csv', 'txt'], true)) {
            $this->renderPage([
                'error' => 'Sube el CSV exportado por Advanced Hunting (acciones → Export → CSV).',
                'mode'  => $mode,
            ]);
            return;
        }

        $content = file_get_contents($tmpName);
        if ($content === false || trim($content) === '') {
            $this->renderPage(['error' => 'No se pudo leer el contenido del CSV.', 'mode' => $mode]);
            return;
        }

        $parsed = ExposedReportParser::parse($content);
        if (!$parsed['ok']) {
            $this->renderPage([
                'mode'   => $mode,
                'errors' => $parsed['errors'],
                'filename' => $filename,
            ]);
            return;
        }

        // CVE que el CSV identifica (los que tienen exploit público).
        $cveIds = ExposedReportEnrichment::collectExploitCves($parsed['rows']);

        // JSON de especificación: el editado en pantalla o el de la plantilla.
        $spec = ExposedReportEnrichment::resolveSpec($specOverride, ExposedReportParser::kqlJson());

        // Datos de los CVE para que el modelo los analice en prosa.
        $cveBlock = $enrich !== ExposedReportEnrichment::SOURCE_NONE
            ? ExposedReportEnrichment::promptBlock($cveIds)
            : ['text' => '', 'count' => 0];

        [$system, $user, $maxTokens] = $this->prompts(
            $parsed['csv'],
            $mode,
            $spec['spec'],
            (string)$cveBlock['text']
        );

        $startedAt = microtime(true);
        $res = llm_run('exposed_report', $system, $user, [
            'profile_id'  => $profileId,
            'max_tokens'  => $maxTokens,
            'temperature' => 0.15,
            'think'       => false,
        ]);
        $elapsedMs = (int)round((microtime(true) - $startedAt) * 1000);

        $warnings = $parsed['warnings'];
        $warningsTotal = (int)$parsed['warnings_total'];

        if (empty($res['success'])) {
            $this->renderPage([
                'mode'          => $mode,
                'filename'      => $filename,
                'stats'         => $parsed['stats'],
                'warnings'      => $warnings,
                'warningsTotal' => $warningsTotal,
                'error'         => 'La IA no pudo generar el informe: ' . (string)($res['error'] ?? 'error desconocido'),
                'profileId'     => $profileId,
            ]);
            return;
        }

        $markdown = trim((string)($res['content'] ?? ''));
        if ($markdown === '') {
            $this->renderPage([
                'mode'          => $mode,
                'filename'      => $filename,
                'stats'         => $parsed['stats'],
                'warnings'      => $warnings,
                'warningsTotal' => $warningsTotal,
                'error'         => 'El modelo no devolvió contenido. Repite la generación o cambia de perfil de IA.',
                'profileId'     => $profileId,
            ]);
            return;
        }

        // Anexos deterministas: los añade la aplicación, no los redacta la IA,
        // para que cada dato sea rastreable a su fuente.
        $annexMd = '';
        $enrichNotice = null;
        $analysesMissing = [];
        if ($enrich === ExposedReportEnrichment::SOURCE_CATALOG) {
            $catalog = ExposedReportEnrichment::fromCatalog($cveIds);
            $annex = ExposedReportEnrichment::annexCatalog($parsed['rows'], $catalog);
            $annexMd = (string)$annex['markdown'];
            $enrichNotice = $annex['notice'];
        } elseif ($enrich === ExposedReportEnrichment::SOURCE_INVENTORY) {
            $annex = ExposedReportEnrichment::annexInventory($parsed['rows']);
            $annexMd = (string)$annex['markdown'];
            $enrichNotice = $annex['notice'];
            foreach ((array)($annex['mismatch'] ?? []) as $item) {
                $warnings[] = 'Defender: ' . (string)$item;
                $warningsTotal++;
            }
        }

        // Anexo D: análisis por CVE que ya existen en el módulo CVE.
        if ($enrich !== ExposedReportEnrichment::SOURCE_NONE) {
            $analyses = ExposedReportEnrichment::annexAnalyses($cveIds);
            if ((string)$analyses['markdown'] !== '') {
                $annexMd = trim($annexMd . "\n\n" . (string)$analyses['markdown']);
            }
            // Solo se puede encolar el análisis de los CVE que están en el
            // catálogo local; el resto no tiene datos.
            $analysable = array_keys(ExposedReportEnrichment::cveDetails($cveIds));
            $analysesMissing = array_values(array_intersect(
                (array)($analyses['missing'] ?? []),
                $analysable
            ));
            if ($enrichNotice === null && $analyses['notice'] !== null) {
                $enrichNotice = (string)$analyses['notice'];
            }
        }

        if ($annexMd !== '') {
            $markdown = trim($markdown) . "\n\n---\n\n" . $annexMd;
        }

        $html = render_ai_markdown($markdown);

        log_activity('exposed_report.generated', [
            'servers' => (int)$parsed['stats']['servers'],
            'mode'    => $mode,
            'enrich'  => $enrich,
            'bytes'   => (int)$parsed['bytes'],
            'ms'      => $elapsedMs,
        ]);

        $this->renderPage([
            'mode'          => $mode,
            'filename'      => $filename,
            'stats'         => $parsed['stats'],
            'warnings'      => $warnings,
            'warningsTotal' => $warningsTotal,
            'reportMd'      => $markdown,
            'reportHtml'    => $html,
            'elapsedMs'     => $elapsedMs,
            'profileId'     => $profileId,
            'enrich'        => $enrich,
            'enrichNotice'  => $enrichNotice,
            'specJson'      => $specOverride !== '' ? $specOverride : self::specTemplate(),
            'specCustom'    => (bool)$spec['custom'],
            'specNotice'    => $spec['notice'],
            'cveIds'        => $cveIds,
            'analysesMissing' => $analysesMissing,
            'downloadName'  => 'informe-parcheo-' . gmdate('Ymd-Hi') . '.md',
        ]);
    }

    /* =====================================================================
     * Análisis por CVE (encola el informe IA del módulo CVE)
     * ================================================================== */

    public function analyzeCves(array $params = []): void
    {
        $this->activeTab = 'kql';
        $ids = [];
        foreach ((array)($_POST['cve_ids'] ?? []) as $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $id = strtoupper(trim((string)$value));
            if (preg_match('/^CVE-\d{4}-\d{4,}$/', $id) === 1) {
                $ids[$id] = true;
            }
        }
        $ids = array_keys($ids);

        if ($ids === []) {
            $this->renderPage(['error' => 'No hay CVE válidos para analizar.']);
            return;
        }

        // Solo se pueden analizar los CVE que están en el catálogo local.
        $available = array_keys(ExposedReportEnrichment::cveDetails($ids));
        $skipped = array_values(array_diff($ids, $available));
        $queue = array_slice($available, 0, ExposedReportEnrichment::MAX_ANALYSIS_QUEUE);

        if ($queue === []) {
            $this->renderPage([
                'error' => 'Ninguno de los CVE está en el catálogo local, así que no hay datos para analizar. '
                    . 'Actualiza el catálogo desde el módulo CVE y vuelve a intentarlo.',
            ]);
            return;
        }

        $llm = ModuleManager::get('llm');
        if (!$llm instanceof Module_Llm || !$llm->isConfigured()) {
            $this->renderPage([
                'error' => 'La IA no está configurada. Revisa el perfil en Admin → APIs antes de encolar análisis.',
            ]);
            return;
        }

        try {
            $token = bin2hex(random_bytes(24));
            $reportId = CveDatabase::insert(
                "INSERT INTO cve_ai_reports
                 (cve_ids, title, status, token, ai_profile_id, generated_by, no_ai, mode, total_items)
                 VALUES (?, ?, 'pending', ?, ?, ?, 0, 'extended', ?)",
                [
                    json_encode($queue, JSON_UNESCAPED_SLASHES),
                    'Equipos expuestos · análisis de CVE · ' . date('d/m/Y H:i'),
                    $token,
                    llm_task_profile('cve_report'),
                    Auth::id(),
                    count($queue),
                ]
            );

            CveReportAi::ensureReportItems($reportId);

            $useFpm = function_exists('fastcgi_finish_request');

            log_activity('exposed_report.analyses_queued', [
                'report'  => $reportId,
                'cves'    => count($queue),
                'skipped' => count($skipped),
                'mode'    => $useFpm ? 'fpm-inline' : 'inline',
            ]);

            $notice = count($queue) . ' análisis por CVE en cola (informe IA #' . $reportId . '). '
                . ($useFpm
                    ? 'Se generan en segundo plano; vuelve a generar este informe en unos minutos para adjuntarlos.'
                    : 'Se están generando ahora mismo en esta petición.')
                . ($skipped !== []
                    ? ' ' . count($skipped) . ' CVE no están en el catálogo local y se han omitido.'
                    : '');

            $this->renderPage(['queueNotice' => $notice]);

            // Sin petición HTTP a uno mismo: con FPM se cierra la respuesta y el
            // trabajo continúa en este proceso; sin FPM se resuelve en línea.
            if ($useFpm) {
                @ignore_user_abort(true);
                @set_time_limit(0);
                finish_response();
            }
            try {
                CveReportAi::runPending($token);
            } catch (Throwable $e) {
                app_log('error', 'exposed_report', 'Análisis por CVE fallido', [
                    'report' => $reportId,
                    'error'  => $e->getMessage(),
                ]);
            }
            if ($useFpm) {
                exit;
            }
        } catch (Throwable $e) {
            $this->renderPage(['error' => 'No se pudieron encolar los análisis: ' . $e->getMessage()]);
        }
    }

    /* =====================================================================
     * Vista
     * ================================================================== */

    private function renderPage(array $extra = []): void
    {
        $profiles = llm_profile_list();
        $defaultProfileId = llm_profile_default()['id'] ?? null;

        $llm = ModuleManager::get('llm');
        $configured = $llm instanceof Module_Llm
            ? $llm->isConfigured($defaultProfileId !== null ? (int)$defaultProfileId : null)
            : false;

        $console = $this->consoleState();

        echo $this->page('index', array_merge([
            'module'          => $this,
            'profiles'        => $profiles,
            'defaultProfileId'=> $defaultProfileId,
            'profileId'       => $defaultProfileId,
            'llmConfigured'   => $configured,
            'isAdmin'         => Auth::isAdmin(),
            'activeTab'       => $this->activeTab,
            'console'         => $console,
            'kql'             => ExposedReportParser::KQL,
            'columns'         => ExposedReportParser::COLUMNS,
            'maxUploadLabel'  => ExposedReportParser::formatBytes(ExposedReportParser::maxUploadBytes()),
            'maxRows'         => ExposedReportParser::MAX_ROWS,
            'error'           => null,
            'errors'          => [],
            'warnings'        => [],
            'warningsTotal'   => 0,
            'stats'           => null,
            'reportMd'        => '',
            'reportHtml'      => '',
            'mode'            => 'compact',
            'filename'        => '',
            'elapsedMs'       => 0,
            'downloadName'    => '',
            'enrich'          => ExposedReportEnrichment::SOURCE_CATALOG,
            'enrichNotice'    => null,
            'enrichSources'   => ExposedReportEnrichment::SOURCES,
            'catalogAvailable'=> ExposedReportEnrichment::catalogAvailable(),
            'inventoryAvailable' => ExposedReportEnrichment::inventoryAvailable(),
            'specJson'        => self::specTemplate(),
            'specCustom'      => false,
            'specNotice'      => null,
            'cveIds'          => [],
            'analysesMissing' => [],
            'queueNotice'     => null,
        ], $extra, ['console' => array_merge($console, is_array($extra['console'] ?? null) ? $extra['console'] : [])]));
    }

    /**
     * Estado de la consola para la vista: snapshot activo, filtros, facets,
     * página de resultados y grupos.
     *
     * @return array<string,mixed>
     */
    private function consoleState(): array
    {
        $snapshots = ExposedConsoleStore::listSnapshots(25);
        $requested = (int)($_GET['snapshot'] ?? 0);
        $snapshot = $requested > 0 ? ExposedConsoleStore::getSnapshot($requested) : null;
        if ($snapshot === null) {
            $snapshot = ExposedConsoleStore::latestSnapshot();
        }
        $snapshotId = (int)($snapshot['id'] ?? 0);

        $filters = ExposedConsoleStore::filtersFromInput($_GET);
        $perPage = ExposedConsoleStore::PER_PAGE;
        $total = 0;
        $rows = [];
        $stats = null;
        $facets = ['severity' => [], 'age' => [], 'threats' => [], 'tags' => [], 'status' => []];
        $page = 1;
        $pages = 1;

        if ($snapshotId > 0) {
            $total = ExposedConsoleStore::count($snapshotId, $filters);
            $pages = max(1, (int)ceil($total / $perPage));
            $page = max(1, min($pages, (int)($_GET['page'] ?? 1)));
            $rows = ExposedConsoleStore::rows($snapshotId, $filters, $perPage, ($page - 1) * $perPage);
            $stats = ExposedConsoleStore::stats($snapshotId, $filters);
            $facets = ExposedConsoleStore::facets($snapshotId, $filters);
        }
        $groups = ExposedConsoleStore::listGroups(100);

        return [
            'snapshots'   => $snapshots,
            'snapshot'    => $snapshot,
            'snapshotId'  => $snapshotId,
            'filters'     => $filters,
            'filterQuery' => ExposedConsoleStore::filtersToQuery($filters),
            'rows'        => $rows,
            'stats'       => $stats,
            'facets'      => $facets,
            'total'       => $total,
            'page'        => $page,
            'pages'       => $pages,
            'perPage'     => $perPage,
            'groups'      => $groups,
            'maxBytesLabel' => ExposedConsoleStore::formatBytes(ExposedConsoleStore::maxUploadBytes()),
            'iniLimited'  => ExposedConsoleStore::maxUploadBytes() < CveTvmImport::CONSOLE_MAX_BYTES,
            'maxRowsConsole' => CveTvmImport::CONSOLE_MAX_ROWS,
            'counts'      => $this->countSnapshotTotals($snapshotId),
        ];
    }

    /**
     * Totales sin filtrar del snapshot (para la cabecera de la consola).
     *
     * @return array<string,mixed>
     */
    private function countSnapshotTotals(int $snapshotId): array
    {
        if ($snapshotId <= 0) {
            return ['total' => 0];
        }
        $row = CveDatabase::fetchOne(
            "SELECT COUNT(*) AS total,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN has_exploit = 1 THEN 1 ELSE 0 END) AS exploitable,
                    MAX(exposed_machines) AS machines_max
             FROM exposed_cves WHERE snapshot_id = ?",
            [$snapshotId]
        ) ?? [];
        return [
            'total'        => (int)($row['total'] ?? 0),
            'critical'     => (int)($row['critical'] ?? 0),
            'exploitable'  => (int)($row['exploitable'] ?? 0),
            'machines_max' => (int)($row['machines_max'] ?? 0),
        ];
    }

    /**
     * Página de un grupo de análisis (o el mismo índice con el error).
     */
    private function renderGroup(int $groupId, array $extra = []): void
    {
        $group = $groupId > 0 ? ExposedConsoleStore::getGroup($groupId) : null;
        if ($group === null && !isset($extra['error'])) {
            http_response_code(404);
            $extra['error'] = 'El grupo no existe o se ha eliminado.';
        }

        $rows = $group !== null ? ExposedConsoleStore::groupRows($groupId) : [];
        $plan = $group !== null ? ExposedConsoleStore::getPlan($groupId) : null;

        $profiles = llm_profile_list();
        $defaultProfileId = llm_task_profile_for('exposed_action_plan');
        if ($defaultProfileId <= 0) {
            $defaultProfileId = (int)(llm_profile_default()['id'] ?? 0);
        }

        $llm = ModuleManager::get('llm');
        $configured = $llm instanceof Module_Llm
            ? $llm->isConfigured($defaultProfileId > 0 ? $defaultProfileId : null)
            : false;

        echo $this->page('group', array_merge([
            'module'        => $this,
            'group'         => $group,
            'groupId'       => $groupId,
            'rows'          => $rows,
            'plan'          => $plan,
            'profiles'      => $profiles,
            'profileId'     => $defaultProfileId,
            'llmConfigured' => $configured,
            'isAdmin'       => Auth::isAdmin(),
            'error'         => null,
            'queueNotice'   => null,
            'planFresh'     => false,
            'elapsedMs'     => 0,
            'planContext'   => null,
            'maxAnalysis'   => ExposedReportEnrichment::MAX_ANALYSIS_QUEUE,
            'downloadName'  => 'plan-actuacion-' . preg_replace('/[^a-z0-9]+/i', '-', (string)($group['name'] ?? 'grupo'))
                . '-' . gmdate('Ymd-Hi') . '.md',
        ], $extra));
    }

    /* =====================================================================
     * Prompts
     * ================================================================== */

    /**
     * Construye [system, user, max_tokens] según el modo.
     *
     * Los textos viven en el catálogo de prompts editables (Admin →
     * Plantillas de prompts); aquí solo se resuelven con su valor por defecto.
     *
     * @return array{0:string,1:string,2:int}
     */
    private function prompts(string $csv, string $mode, string $spec, string $cveBlock): array
    {
        $catalog = llm_prompts_catalog();
        $csvBlock = "CSV con los resultados de la KQL (una fila por servidor):\n\n```csv\n" . $csv . "\n```";

        if ($mode === 'detailed') {
            $systemDefault = (string)($catalog['llm.exposed.detailed']['default'] ?? '');
            $system = llm_prompt('llm.exposed.detailed', $systemDefault);

            $user = "JSON de especificación (vínculo vinculante; aplica sus reglas y su estructura):\n\n"
                . "```json\n" . $spec . "\n```\n\n";

            if ($cveBlock !== '') {
                $user .= $cveBlock . "\n\n";
            }

            $user .= $csvBlock;

            return [$system, $user, 4500];
        }

        $systemDefault = (string)($catalog['llm.exposed.compact']['default'] ?? '');
        $system = llm_prompt('llm.exposed.compact', $systemDefault);

        return [$system, $csvBlock, 1500];
    }

    /* =====================================================================
     * Utilidades
     * ================================================================== */

    /** JSON de especificación de la plantilla, con el marcador {kql} intacto. */
    private static function specTemplate(): string
    {
        $catalog = llm_prompts_catalog();
        $default = (string)($catalog['llm.exposed.spec']['default'] ?? '');
        return llm_prompt('llm.exposed.spec', $default);
    }

    private function uploadError(int $code): string
    {
        return match ($code) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'El fichero supera el tamaño permitido por el servidor ('
                . ini_get('upload_max_filesize') . ').',
            UPLOAD_ERR_PARTIAL    => 'La subida se interrumpió. Inténtalo de nuevo.',
            UPLOAD_ERR_NO_FILE    => 'Selecciona el CSV exportado por Advanced Hunting.',
            UPLOAD_ERR_NO_TMP_DIR => 'El servidor no tiene directorio temporal.',
            UPLOAD_ERR_CANT_WRITE => 'No se pudo escribir el fichero en el servidor.',
            default               => 'No se pudo subir el fichero.',
        };
    }
}
