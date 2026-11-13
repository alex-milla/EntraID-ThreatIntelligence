<?php
/**
 * Módulo: Equipos expuestos (exposed_report)
 *
 * Generador de informes de parcheo para servidores internet-exposed a partir
 * del CSV que exporta Microsoft Defender XDR (Advanced Hunting). El módulo no
 * consulta la base de datos de CVE ni ninguna otra fuente: el único dato es el
 * CSV que sube el analista.
 *
 * Flujo: KQL (se copia al portal) → CSV → validación (14 columnas) → prompt
 * compacto o detallado → informe Markdown listo para el equipo de parcheo.
 *
 * Rutas:
 *   GET  /modules/exposed_report           formulario + último informe
 *   POST /modules/exposed_report/generate  valida el CSV y genera el informe
 */

declare(strict_types=1);

require_once INCLUDES_PATH . '/exposed_report_parser.php';
require_once INCLUDES_PATH . '/exposed_report_enrichment.php';

class Module_ExposedReport extends BaseModule
{
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
        return 'Informe de parcheo de servidores internet-exposed (Defender Advanced Hunting)';
    }

    public function version(): string
    {
        return '1.0.0';
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
            ['method' => 'GET',  'pattern' => '',             'handler' => [$this, 'index']],
            ['method' => 'POST', 'pattern' => 'generate',     'handler' => [$this, 'generate']],
            ['method' => 'POST', 'pattern' => 'analyze-cves', 'handler' => [$this, 'analyzeCves']],
        ];
    }

    /* =====================================================================
     * Pantalla principal
     * ================================================================== */

    public function index(array $params = []): void
    {
        $this->renderPage();
    }

    /* =====================================================================
     * Generación del informe
     * ================================================================== */

    public function generate(array $params = []): void
    {
        $mode = ((string)($_POST['mode'] ?? 'compact')) === 'detailed' ? 'detailed' : 'compact';
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

        echo $this->page('index', array_merge([
            'module'          => $this,
            'profiles'        => $profiles,
            'defaultProfileId'=> $defaultProfileId,
            'profileId'       => $defaultProfileId,
            'llmConfigured'   => $configured,
            'isAdmin'         => Auth::isAdmin(),
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
