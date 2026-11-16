<?php
/**
 * Módulo: Incidentes Story (incident_story)
 *
 * Triaje asistido de incidencias de Microsoft Defender XDR sin Graph ni
 * licencia: el analista pega el story del portal o sube el JSON (story del
 * portal, export de Graph o resultado de Advanced Hunting). El módulo
 * normaliza la evidencia, la pseudonimiza y la envía a la IA configurada
 * (Mistral / Ollama Cloud / cualquier perfil del módulo LLM). El veredicto
 * de la IA es asistido: la decisión final la registra siempre una persona.
 *
 * Rutas:
 *   GET  /modules/incident_story                 panel con casos y KPIs
 *   GET  /modules/incident_story/new             formulario de ingesta dual
 *   POST /modules/incident_story/ingest          parsea, anonimiza y guarda
 *   GET  /modules/incident_story/case/{id}       detalle del caso
 *   POST /modules/incident_story/case/{id}/triage   triaje IA
 *   POST /modules/incident_story/case/{id}/decision decisión humana
 *   POST /modules/incident_story/case/{id}/delete   borrar caso
 */

declare(strict_types=1);

class Module_IncidentStory extends BaseModule
{
    public function key(): string
    {
        return 'incident_story';
    }

    public function name(): string
    {
        return 'Incidentes Story';
    }

    public function description(): string
    {
        return 'Triaje asistido de incidencias Defender XDR desde el story pegado o un JSON, sin Graph ni licencia';
    }

    public function version(): string
    {
        return '0.1.0';
    }

    /** No usa Microsoft Graph. */
    public function requiredPermissions(): array
    {
        return [];
    }

    /** No sincroniza por tenant: la evidencia se ingesta a mano. */
    public function isSyncable(): bool
    {
        return false;
    }

    public function sync(int $tenantId): array
    {
        return ['success' => false, 'error' => 'Incidentes Story no se sincroniza por tenant.'];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Incidentes Story',
            'url'   => base_url('modules/incident_story'),
            'icon'  => 'alert-triangle',
            'group' => 'Seguridad',
            'after' => 'incidents',
        ];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                'handler' => [$this, 'index']],
            ['method' => 'GET',  'pattern' => 'new',             'handler' => [$this, 'create']],
            ['method' => 'POST', 'pattern' => 'ingest',          'handler' => [$this, 'ingest']],
            ['method' => 'GET',  'pattern' => 'case/{id}',       'handler' => [$this, 'show']],
            ['method' => 'GET',  'pattern' => 'case/{id}/export', 'handler' => [$this, 'export']],
            ['method' => 'GET',  'pattern' => 'case/{id}/triage-status', 'handler' => [$this, 'triageStatus']],
            ['method' => 'POST', 'pattern' => 'case/{id}/triage-cancel', 'handler' => [$this, 'triageCancel']],
            ['method' => 'POST', 'pattern' => 'case/{id}/triage',   'handler' => [$this, 'triage']],
            ['method' => 'POST', 'pattern' => 'case/{id}/decision', 'handler' => [$this, 'decision']],
            ['method' => 'POST', 'pattern' => 'case/{id}/delete',   'handler' => [$this, 'delete']],
        ];
    }

    private function store(): IncidentStoryStore
    {
        return new IncidentStoryStore();
    }

    /* =====================================================================
     * Panel
     * ================================================================== */

    public function index(array $params = []): void
    {
        $store = $this->store();

        echo $this->page('index', [
            'module'  => $this,
            'cases'   => $store->listCases(),
            'stats'   => $store->stats(),
            'formats' => IncidentStoryParser::FORMATS,
            'notice'  => flash('incident_story'),
        ]);
    }

    /* =====================================================================
     * Ingesta
     * ================================================================== */

    public function create(array $params = []): void
    {
        echo $this->page('new', [
            'module'  => $this,
            'formats' => IncidentStoryParser::FORMATS,
            'notice'  => flash('incident_story'),
            'oldText' => (string)old_input('story_text', ''),
            'oldClientDomains' => (string)old_input('client_domains', ''),
        ]);
        clear_old_input();
    }

    public function ingest(array $params = []): void
    {
        Csrf::validateOrFail();

        $mode = (string)($_POST['mode'] ?? 'text');
        $raw = '';
        $origen = 'Pegado manual';
        $forcedFormat = null;

        if ($mode === 'file') {
            $file = $_FILES['story_file'] ?? null;
            $uploadError = is_array($file) ? (int)($file['error'] ?? UPLOAD_ERR_NO_FILE) : UPLOAD_ERR_NO_FILE;
            if (!is_array($file) || $uploadError !== UPLOAD_ERR_OK) {
                $this->failIngest($this->uploadErrorText($uploadError));
            }
            $size = (int)($file['size'] ?? 0);
            if ($size <= 0) {
                $this->failIngest('El fichero está vacío.');
            }
            if ($size > INCIDENT_STORY_MAX_BYTES) {
                $this->failIngest('El fichero supera el límite de 5 MB.');
            }
            $tmpName = (string)($file['tmp_name'] ?? '');
            if ($tmpName === '' || !is_uploaded_file($tmpName)) {
                $this->failIngest('No se pudo leer el fichero subido.');
            }
            $content = file_get_contents($tmpName);
            if ($content === false || trim($content) === '') {
                $this->failIngest('No se pudo leer el contenido del fichero.');
            }
            $raw = $content;
            $origen = 'Fichero: ' . self::clip(trim((string)($file['name'] ?? 'story')), 180);
            $ext = strtolower(pathinfo((string)($file['name'] ?? ''), PATHINFO_EXTENSION));
            if (!in_array($ext, ['json', 'jsonc', 'txt', 'log'], true)) {
                $this->failIngest('Sube un .json/.jsonc del story o un .txt con la historia copiada.');
            }
            if (in_array($ext, ['txt', 'log'], true)) {
                $forcedFormat = 'texto_pegado';
            }
        } else {
            $raw = trim((string)($_POST['story_text'] ?? ''));
            if ($raw === '') {
                $this->failIngest('Pega el story de Defender o sube el JSON.');
            }
        }

        if (trim($raw) === '') {
            $this->failIngest('No hay contenido que analizar.');
        }

        $clientDomains = preg_split('/[,;\s]+/', (string)($_POST['client_domains'] ?? '')) ?: [];

        try {
            $parsed = IncidentStoryParser::parse($raw, $forcedFormat);
            $anonimizador = new IncidentStoryAnonymizer($clientDomains);
            $anon = $anonimizador->anonymize($parsed['caso']);
        } catch (InvalidArgumentException $e) {
            $this->failIngest($e->getMessage(), $raw, (string)($_POST['client_domains'] ?? ''));
        } catch (Throwable $e) {
            error_log('incident_story: ' . $e->getMessage());
            $this->failIngest('No se pudo procesar la evidencia. Revisa el formato del story.');
        }

        $store = $this->store();
        if ($store->countCases() >= INCIDENT_STORY_MAX_CASES) {
            $this->failIngest('Límite de casos alcanzado (' . INCIDENT_STORY_MAX_CASES . '). Borra algún caso antiguo antes de crear otro.');
        }

        $user = Auth::user();
        $saved = $store->createCase(
            $parsed['caso'],
            $anon['caso'],
            $anon['mapping'],
            $anon['warnings'],
            hash('sha256', $raw),
            $parsed['formato_entrada'],
            $origen,
            $user !== null ? (int)$user['id'] : null
        );

        $text = 'Caso guardado con ' . count((array)($parsed['caso']['eventos'] ?? []))
            . ' eventos (' . (IncidentStoryParser::FORMATS[$parsed['formato_entrada']] ?? $parsed['formato_entrada']) . ').';
        if ($saved['duplicate'] !== null) {
            $text .= ' Aviso: ya existía un caso con el mismo story (#' . $saved['duplicate'] . ').';
        }
        if (!empty($anon['warnings'])) {
            $text .= ' ' . count($anon['warnings']) . ' aviso(s) de pseudonimización: revísalos antes de enviar a la IA.';
        }
        flash('incident_story', ['type' => empty($anon['warnings']) ? 'success' : 'warning', 'text' => $text]);
        redirect(base_url('modules/incident_story/case/' . $saved['id']));
    }

    private function failIngest(string $message, string $raw = '', string $clientDomains = ''): never
    {
        if ($raw !== '') {
            set_old_input(['story_text' => $raw, 'client_domains' => $clientDomains]);
        }
        flash('incident_story', ['type' => 'error', 'text' => $message]);
        redirect(base_url('modules/incident_story/new'));
    }

    private function uploadErrorText(int $code): string
    {
        return match ($code) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'El fichero supera el tamaño permitido por el servidor.',
            UPLOAD_ERR_PARTIAL   => 'La subida se interrumpió. Inténtalo de nuevo.',
            UPLOAD_ERR_NO_FILE   => 'Selecciona un fichero JSON o TXT.',
            UPLOAD_ERR_NO_TMP_DIR=> 'El servidor no tiene directorio temporal.',
            UPLOAD_ERR_CANT_WRITE=> 'No se pudo escribir el fichero en el servidor.',
            default              => 'No se pudo subir el fichero.',
        };
    }

    /* =====================================================================
     * Detalle del caso
     * ================================================================== */

    public function show(array $params = []): void
    {
        $case = $this->loadCaseOrRedirect($params);
        $llm = ModuleManager::get('llm');
        $profiles = llm_profile_list();
        $defaultProfileId = llm_profile_default()['id'] ?? null;
        $llmConfigured = $llm instanceof Module_Llm ? $llm->isConfigured($defaultProfileId !== null ? (int)$defaultProfileId : null) : false;

        $view = ((string)($_GET['view'] ?? '')) === 'original' ? 'original' : 'anon';
        $evidencia = $view === 'original'
            ? (is_array($case['caso'] ?? null) ? $case['caso'] : [])
            : (is_array($case['anon'] ?? null) ? $case['anon'] : []);
        $eventosTotal = count((array)($evidencia['eventos'] ?? []));
        $triageProgreso = safe_json_decode((string)($case['triage_progreso'] ?? ''), []);
        $triageProgreso = is_array($triageProgreso) ? $triageProgreso : [];

        echo $this->page('case', [
            'module'           => $this,
            'case'             => $case,
            'view'             => $view,
            'evidencia'        => $evidencia,
            'eventos'          => array_slice((array)($evidencia['eventos'] ?? []), 0, 500),
            'eventosTotal'     => $eventosTotal,
            'resumen'          => IncidentStoryParser::summarize($evidencia),
            'decisions'        => $this->store()->listDecisions((int)$case['id']),
            'profiles'         => $profiles,
            'defaultProfileId' => $defaultProfileId,
            'llmConfigured'    => $llmConfigured,
            'classifications'  => IncidentStoryStore::CLASSIFICATIONS,
            'determinations'   => IncidentStoryStore::DETERMINATIONS,
            'notice'           => $this->notice(),
            'triageEstado'     => (string)($case['triage_estado'] ?? 'idle'),
            'triageProgreso'   => $triageProgreso,
            'triageError'      => (string)($case['triage_error'] ?? ''),
        ]);
    }

    /**
     * Aviso de la petición. El triaje usa parámetros de URL porque
     * Module_Llm::chat() cierra la sesión (release_session_lock) y un flash
     * escrito después se perdería. El resto de acciones siguen usando flash.
     */
    private function notice(): ?array
    {
        $notice = flash('incident_story');
        if (is_array($notice)) {
            return $notice;
        }
        if (isset($_GET['triage_ok'])) {
            return ['type' => 'success', 'text' => 'Triaje IA completado. Revisa el resultado y registra la decisión humana.'];
        }
        if (isset($_GET['triage_running'])) {
            return [
                'type' => 'info',
                'text' => 'Triaje IA en curso: la evidencia se está analizando por partes para que un modelo local '
                    . 'pueda completarlo. Puedes seguir en esta ficha; se actualiza sola al terminar.',
            ];
        }
        if (isset($_GET['triage_stop'])) {
            return [
                'type' => 'info',
                'text' => 'Detención solicitada: el triaje se cancela al terminar la llamada en curso y se guarda '
                    . 'lo que ya estaba analizado.',
            ];
        }
        if (isset($_GET['triage_error'])) {
            $msg = trim((string)$_GET['triage_error']);
            if ($msg !== '') {
                return ['type' => 'error', 'text' => 'Triaje IA: ' . self::clip($msg, 500)];
            }
        }
        return null;
    }

    /* =====================================================================
     * Exportación a Markdown (para informes / tratamiento posterior)
     * ================================================================== */

    public function export(array $params = []): void
    {
        $case = $this->loadCaseOrRedirect($params);
        $case['decisions'] = $this->store()->listDecisions((int)$case['id']);
        $md = self::exportMarkdown($case);
        $slug = preg_replace('/[^a-z0-9-]/i', '', (string)($case['public_id'] ?? ('caso-' . (int)$case['id']))) ?: ('caso-' . (int)$case['id']);
        $filename = 'incidente-story-' . $slug . '.md';

        header('Content-Type: text/markdown; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('X-Content-Type-Options: nosniff');
        echo $md;
    }

    /**
     * Markdown del caso con la evidencia pseudonimizada, el resumen sin IA,
     * el triaje y las decisiones humanas. Nunca incluye la tabla de mapeo.
     */
    public static function exportMarkdown(array $case): string
    {
        $caso = is_array($case['caso'] ?? null) ? $case['caso'] : [];
        $anon = is_array($case['anon'] ?? null) ? $case['anon'] : [];
        $incidencia = is_array($caso['incidencia'] ?? null) ? $caso['incidencia'] : [];
        $resumen = IncidentStoryParser::summarize($anon);
        $triage = is_array($case['triage'] ?? null) ? $case['triage'] : [];
        $decisions = is_array($case['decisions'] ?? null) ? $case['decisions'] : [];

        $cell = static function (mixed $value): string {
            $s = is_scalar($value) ? (string)$value : '';
            return str_replace(['|', "\r", "\n"], ['\\|', ' ', ' '], $s);
        };
        $fmt = static fn(mixed $value): string => trim((string)(is_scalar($value) ? $value : '')) !== ''
            ? str_replace('T', ' ', (string)$value)
            : '—';
        $listOr = static fn(mixed $value): string => is_array($value) && $value !== []
            ? implode(', ', array_map('strval', array_filter($value, 'is_scalar')))
            : '—';

        $out = [];
        $out[] = '# Incidente: ' . self::mdText((string)($incidencia['nombre'] ?? 'Caso ' . (int)($case['id'] ?? 0)));
        $out[] = '';
        $out[] = '| Campo | Valor |';
        $out[] = '|---|---|';
        $out[] = '| Caso | ' . $cell($case['public_id'] ?? '') . ' |';
        $out[] = '| Incidencia Defender | ' . $cell($incidencia['id_defender'] ?? '—') . ' |';
        $out[] = '| Severidad | ' . $cell($incidencia['severidad'] ?? '—') . ' |';
        $out[] = '| Estado | ' . $cell($incidencia['estado'] ?? '—') . ' |';
        $out[] = '| Formato de entrada | ' . $cell($case['formato_entrada'] ?? '—') . ' |';
        $out[] = '| Origen | ' . $cell($case['origen'] ?? '—') . ' |';
        $out[] = '| Eventos | ' . (int)($resumen['total_eventos'] ?? 0) . ' |';
        $out[] = '| Ventana temporal | ' . $cell($fmt($resumen['desde'] ?? null)) . ' → ' . $cell($fmt($resumen['hasta'] ?? null)) . ' |';
        $out[] = '| Hash del story | `' . $cell($case['story_hash'] ?? '') . '` |';
        $out[] = '| Analizado | ' . $cell($fmt($case['created_at'] ?? null)) . ' |';
        $out[] = '';
        $out[] = '> Evidencia pseudonimizada antes del análisis. Este informe no contiene la tabla de mapeo.';
        $out[] = '';

        $out[] = '## Resumen del story (sin IA)';
        $out[] = '';
        $alertas = is_array($resumen['alertas'] ?? null) ? $resumen['alertas'] : [];
        if ($alertas !== []) {
            $out[] = '### Alertas';
            $out[] = '';
            foreach ($alertas as $al) {
                $out[] = '- ' . self::mdText((string)($al['nombre'] ?? 'Alerta')) . ' (' . self::mdText((string)($al['severidad'] ?? '—')) . ')';
            }
            $out[] = '';
        }

        $procesos = is_array($resumen['procesos'] ?? null) ? $resumen['procesos'] : [];
        $out[] = '### Procesos observados';
        $out[] = '';
        if ($procesos === []) {
            $out[] = '_No se han extraído procesos._';
        } else {
            $out[] = '| Proceso | Eventos | Usuarios | Equipos | Primera | Última |';
            $out[] = '|---|---:|---|---|---|---|';
            foreach ($procesos as $p) {
                $out[] = '| ' . $cell($p['proceso'] ?? '') . ' | ' . (int)($p['eventos'] ?? 0)
                    . ' | ' . $cell($listOr($p['usuarios'] ?? []))
                    . ' | ' . $cell($listOr($p['equipos'] ?? []))
                    . ' | ' . $cell($fmt($p['primera'] ?? null))
                    . ' | ' . $cell($fmt($p['ultima'] ?? null)) . ' |';
            }
        }
        $out[] = '';

        $scripts = is_array($resumen['scripts'] ?? null) ? $resumen['scripts'] : [];
        if ($scripts !== []) {
            $out[] = '### Scripts detectados';
            $out[] = '';
            foreach ($scripts as $s) {
                $out[] = '- **' . self::mdText((string)($s['proceso'] ?? 'script')) . '** · '
                    . self::mdText((string)($s['usuario'] ?? '—')) . ' · '
                    . self::mdText($fmt($s['timestamp'] ?? null)) . ' · '
                    . (int)($s['longitud'] ?? 0) . " caracteres\n  > " . self::mdText((string)($s['preview'] ?? ''));
            }
            $out[] = '';
        }

        $hashes = is_array($resumen['hashes'] ?? null) ? $resumen['hashes'] : [];
        if ($hashes !== []) {
            $out[] = '### Hashes';
            $out[] = '';
            foreach ($hashes as $h) {
                $out[] = '- ' . self::mdText((string)($h['tipo'] ?? 'hash')) . ': `' . self::mdText((string)($h['valor'] ?? '')) . '`';
            }
            $out[] = '';
        }

        $out[] = '## Triaje asistido por IA';
        $out[] = '';
        if ($triage === []) {
            $out[] = '_Sin triaje IA registrado._';
        } else {
            $out[] = '- **Veredicto asistido:** ' . self::mdText((string)($triage['veredicto_asistido'] ?? '—'));
            $out[] = '- **Confianza:** ' . (int)($triage['confianza_pct'] ?? 0) . '%';
            $out[] = '- **Modelo:** ' . self::mdText((string)($case['triage_model'] ?? '—'));
            $out[] = '- **Fecha:** ' . self::mdText($fmt($case['triage_at'] ?? null));
            $out[] = '';
            $campos = [
                'resumen_ejecutivo'       => 'Resumen ejecutivo',
                'cadena_de_eventos'       => 'Cadena de eventos',
                'hipotesis_principal'     => 'Hipótesis principal',
                'tecnicas_attck'          => 'Técnicas ATT&CK',
                'indicadores_benignos'    => 'Indicadores benignos',
                'indicadores_maliciosos'  => 'Indicadores maliciosos',
                'datos_faltantes'         => 'Datos faltantes',
                'acciones_recomendadas'   => 'Acciones recomendadas',
                'preguntas_para_el_analista' => 'Preguntas para el analista',
            ];
            foreach ($campos as $key => $label) {
                $value = $triage[$key] ?? null;
                if (is_array($value)) {
                    $items = array_values(array_filter(array_map(
                        static fn($v) => is_scalar($v) ? trim((string)$v) : '',
                        $value
                    ), static fn($v) => $v !== ''));
                    if ($items === []) {
                        continue;
                    }
                    $out[] = '### ' . $label;
                    $out[] = '';
                    foreach ($items as $item) {
                        $out[] = '- ' . self::mdText($item);
                    }
                    $out[] = '';
                } elseif (is_scalar($value) && trim((string)$value) !== '') {
                    $out[] = '### ' . $label;
                    $out[] = '';
                    $out[] = self::mdText((string)$value);
                    $out[] = '';
                }
            }
            $suggestion = is_array($triage['clasificacion_defender_sugerida'] ?? null) ? $triage['clasificacion_defender_sugerida'] : [];
            if ($suggestion !== []) {
                $out[] = '### Clasificación sugerida en Defender';
                $out[] = '';
                $out[] = '- Clasificación: ' . self::mdText((string)($suggestion['classification'] ?? '—'));
                $out[] = '- Determinación: ' . self::mdText((string)($suggestion['determination'] ?? '—'));
                $out[] = '';
            }
            if (!empty($triage['respuesta_original'])) {
                $out[] = '### Respuesta original del modelo (no era JSON válido)';
                $out[] = '';
                $out[] = '```text';
                $out[] = (string)$triage['respuesta_original'];
                $out[] = '```';
                $out[] = '';
            }
        }

        $out[] = '## Decisión humana';
        $out[] = '';
        if ($decisions === []) {
            $out[] = '_Pendiente de decisión humana._';
        } else {
            $out[] = '| Fecha | Analista | Clasificación | Determinación | Justificación |';
            $out[] = '|---|---|---|---|---|';
            foreach ($decisions as $d) {
                $out[] = '| ' . $cell($fmt($d['created_at'] ?? null))
                    . ' | ' . $cell($d['analista'] ?? '')
                    . ' | ' . $cell($d['classification'] ?? '')
                    . ' | ' . $cell($d['determination'] ?? '')
                    . ' | ' . $cell($d['justificacion'] ?? '') . ' |';
            }
        }
        $out[] = '';

        $out[] = '## Evidencia pseudonimizada (JSON)';
        $out[] = '';
        $out[] = '```json';
        $out[] = (string)json_encode($anon, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $out[] = '```';
        $out[] = '';

        return implode("\n", $out) . "\n";
    }

    private static function mdText(string $text): string
    {
        return str_replace(['\\', '`'], ['\\\\', '\\`'], $text);
    }

    /* =====================================================================
     * Triaje IA
     * ================================================================== */

    public function triage(array $params = []): void
    {
        Csrf::validateOrFail();
        $case = $this->loadCaseOrRedirect($params);
        $caseId = (int)$case['id'];
        $baseCaso = base_url('modules/incident_story/case/' . $caseId);

        $llm = ModuleManager::get('llm');
        if (!$llm instanceof Module_Llm) {
            flash('incident_story', ['type' => 'error', 'text' => 'El módulo de IA no está disponible.']);
            redirect($baseCaso);
        }

        $profileId = (int)($_POST['profile_id'] ?? 0);
        $profileId = $profileId > 0 ? $profileId : null;
        if (!$llm->isConfigured($profileId)) {
            flash('incident_story', ['type' => 'error', 'text' => 'La IA no está configurada (Admin → APIs).']);
            redirect($baseCaso);
        }

        $anon = is_array($case['anon'] ?? null) ? $case['anon'] : [];
        $payload = $this->triagePayload($anon);

        // Un caso grande se analiza por partes: así cada llamada cabe en el
        // timeout del perfil y un modelo local puede terminar el triaje.
        $parts = $this->evidenceParts($anon, $this->evidencePartChars($profileId), $payload);

        // Ruta rápida: la evidencia cabe en una llamada (comportamiento de
        // siempre, sin segundo plano ni parciales).
        if ($parts === []) {
            $this->store()->setTriageState($caseId, 'idle');
            $res = $this->singleTriage($payload, $profileId);
            if (empty($res['success'])) {
                $error = self::clip((string)($res['error'] ?? 'error desconocido'), 500);
                redirect($baseCaso . '?triage_error=' . rawurlencode($error) . '#triaje');
            }
            $this->storeTriageResult($caseId, $res, $profileId);
            redirect($baseCaso . '?triage_ok=1#triaje');
        }

        // Por partes: se responde al instante y se trabaja en segundo plano.
        // Cerrojo único de trabajos de IA: un modelo local tiene una sola
        // ranura; dos análisis a la vez se pisan y acaban en timeout.
        $lockOwner = 'incident_triage:' . $caseId . ':' . bin2hex(random_bytes(6));
        if (!llm_job_acquire($lockOwner, 'incident_triage', 3600)) {
            $busy = 'Hay otro trabajo de IA en curso (cola de informes, traducción o asistente). '
                . 'Vuelve a intentar el triaje cuando termine.';
            redirect($baseCaso . '?triage_error=' . rawurlencode($busy) . '#triaje');
        }

        $total = count($parts);
        $job = llm_job_create('incident_triage', $caseId, $profileId, Auth::id());
        $jobId = (int)$job['id'];
        $iniciado = microtime(true);
        $progreso = [
            'fase'        => 'Preparando el análisis por partes',
            'hechos'      => 0,
            'total'       => $total,
            'ok'          => 0,
            'fallidos'    => 0,
            'iniciado'    => $iniciado,
            'actualizado' => $iniciado,
            'job'         => $jobId,
        ];
        $this->store()->setTriageState($caseId, 'running', $progreso);
        llm_job_progress($jobId, $progreso['fase'], 0, $total);
        app_log('info', 'incident_story', 'Triaje IA por partes', [
            'case'    => $caseId,
            'parts'   => $total,
            'job'     => $jobId,
            'profile' => $profileId,
            'chars'   => llm_str_len($payload),
        ]);

        // Con PHP-FPM: se responde 302 y el trabajo sigue EN ESTE PROCESO
        // (patrón de cve-worker.php / asistente de remediación). Sin FPM:
        // en línea, como el análisis por CVE.
        if (function_exists('fastcgi_finish_request')) {
            @ignore_user_abort(true);
            @set_time_limit(0);
            release_session_lock();
            http_response_code(302);
            header('Location: ' . $baseCaso . '?triage_running=1#triaje');
            finish_response();

            $this->runTriageJob($caseId, $profileId, $parts, $jobId, $iniciado, $lockOwner);
            exit;
        }

        $this->runTriageJob($caseId, $profileId, $parts, $jobId, $iniciado, $lockOwner);

        $final = $this->store()->getCase($caseId);
        if ((string)($final['triage_estado'] ?? '') === 'error') {
            $error = self::clip((string)($final['triage_error'] ?? 'error desconocido'), 500);
            redirect($baseCaso . '?triage_error=' . rawurlencode($error) . '#triaje');
        }
        redirect($baseCaso . '?triage_ok=1#triaje');
    }

    /**
     * Estado del triaje por partes para el sondeo de la ficha.
     */
    public function triageStatus(array $params = []): void
    {
        $case = $this->store()->getCase((int)($params['id'] ?? 0));
        if ($case === null) {
            json_response(['success' => false, 'error' => 'El caso no existe.'], 404);
        }

        $estado = (string)($case['triage_estado'] ?? 'idle');
        $progreso = safe_json_decode((string)($case['triage_progreso'] ?? ''), []);
        $progreso = is_array($progreso) ? $progreso : [];
        $error = (string)($case['triage_error'] ?? '');
        $jobId = (int)($case['triage_job'] ?? 0);

        // Un proceso que murió deja el estado en `running`: se da por caducado
        // en vez de dejar la ficha esperando para siempre. Cada parte renueva
        // `actualizado`, así que una hora sin latido es un trabajo perdido.
        if ($estado === 'running') {
            $actualizado = (float)($progreso['actualizado'] ?? 0);
            if ($actualizado > 0 && (time() - (int)$actualizado) > 3600) {
                $estado = 'error';
                $error = 'El triaje dejó de responder (proceso interrumpido). Vuelve a lanzarlo.';
                $progreso['fase'] = 'Error';
                $this->store()->setTriageState((int)$case['id'], 'error', $progreso, $error);
            }
        }

        // Tiempos para que la ficha pueda decir «cuánto llevo» y «cuánto falta».
        $hechos = (int)($progreso['hechos'] ?? 0);
        $totalPartes = (int)($progreso['total'] ?? 0);
        $iniciado = (float)($progreso['iniciado'] ?? 0);
        $actualizado = (float)($progreso['actualizado'] ?? 0);
        $ahora = microtime(true);
        $transcurridoMs = $iniciado > 0 ? max(0, (int)round(($ahora - $iniciado) * 1000)) : 0;
        $restanteMs = 0;
        if ($estado === 'running' && $hechos > 0 && $totalPartes > $hechos && $transcurridoMs > 0) {
            // Media real por parte + un 25 % para la fase de fusión.
            $restanteMs = (int)round(($transcurridoMs / $hechos) * ($totalPartes - $hechos) * 1.25);
        }

        json_response([
            'success'         => true,
            'estado'          => $estado,
            'fase'            => (string)($progreso['fase'] ?? ''),
            'hechos'          => $hechos,
            'total'           => $totalPartes,
            'ok'              => (int)($progreso['ok'] ?? 0),
            'fallidos'        => (int)($progreso['fallidos'] ?? 0),
            'ms_transcurrido' => $transcurridoMs,
            'ms_restante'     => $restanteMs,
            'hace_ms'         => $actualizado > 0 ? max(0, (time() - $actualizado) * 1000) : 0,
            'error'           => $error,
            'triage_at'       => $case['triage_at'] ?? null,
            'partes'          => (int)($case['triage_partes'] ?? 0),
            'cancelado'       => $jobId > 0 ? llm_job_is_cancelled($jobId) : false,
        ]);
    }

    /**
     * Pide detener el triaje en curso. El trabajo termina la llamada que tiene
     * en vuelo (no se corta un HTTP a medias) y guarda lo ya analizado.
     */
    public function triageCancel(array $params = []): void
    {
        Csrf::validateOrFail();
        $case = $this->loadCaseOrRedirect($params);
        $caseId = (int)$case['id'];
        $baseCaso = base_url('modules/incident_story/case/' . $caseId);

        $jobId = (int)($case['triage_job'] ?? 0);
        if ($jobId <= 0 || !llm_job_cancel($jobId)) {
            redirect($baseCaso . '#triaje');
        }

        // Aviso inmediato en la ficha; el estado real lo cierra el trabajo.
        $progreso = safe_json_decode((string)($case['triage_progreso'] ?? ''), []);
        $progreso = is_array($progreso) ? $progreso : [];
        $progreso['fase'] = 'Deteniendo: se cancelará al terminar la llamada en curso…';
        $this->store()->setTriageState($caseId, 'running', $progreso);
        app_log('info', 'incident_story', 'Triaje IA: detención solicitada', [
            'case' => $caseId,
            'job'  => $jobId,
        ]);
        redirect($baseCaso . '?triage_stop=1#triaje');
    }

    /** Payload del caso anonimizado (recortado por tamaño). */
    private function triagePayload(array $anon): string
    {
        $payload = json_encode($anon, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '{}';
        if (strlen($payload) > INCIDENT_STORY_MAX_PROMPT_CHARS) {
            $payload = self::clip($payload, INCIDENT_STORY_MAX_PROMPT_CHARS)
                . "\n…(evidencia recortada por límite de tamaño)";
        }
        return $payload;
    }

    private function triageSystemPrompt(): string
    {
        return llm_prompt(
            'llm.incident_story.triage.system',
            'Eres un analista senior de un SOC especializado en Microsoft Defender XDR y MITRE ATT&CK. '
            . 'Analizas la evidencia normalizada de una incidencia de Defender a partir de su story. '
            . 'Reglas: (1) trabaja SOLO con la evidencia aportada, no inventes datos ni IOC; '
            . '(2) si falta información imprescindible, pídela en preguntas_para_el_analista (máximo 5); '
            . '(3) no afirmes certeza absoluta: expresa confianza en porcentaje; '
            . '(4) el veredicto es ASISTIDO y la decisión final la toma una persona; '
            . '(5) responde SIEMPRE en español y SOLO con un objeto JSON válido, sin texto alrededor.'
        );
    }

    private function triageFormatPrompt(): string
    {
        return llm_prompt(
            'llm.incident_story.triage.format',
            'Devuelve exactamente este objeto JSON: {'
            . '"resumen_ejecutivo":"2-4 frases",'
            . '"cadena_de_eventos":"narrativa padre->hijo con timestamps clave",'
            . '"hipotesis_principal":"explicación más plausible",'
            . '"veredicto_asistido":"benigna|sospechosa|ataque",'
            . '"confianza_pct":0,'
            . '"tecnicas_attck":["Txxxx"],'
            . '"indicadores_benignos":["..."],'
            . '"indicadores_maliciosos":["..."],'
            . '"datos_faltantes":["..."],'
            . '"acciones_recomendadas":["..."],'
            . '"clasificacion_defender_sugerida":{"classification":"truePositive|falsePositive|informationalExpectedActivity|unknown","determination":"..."},'
            . '"preguntas_para_el_analista":["..."]'
            . '}. Los valores de determination deben pertenecer al enum de Microsoft Graph '
            . '(NotAvailable, Malware, Phishing, UnwantedSoftware, Other, CompromisedAccount, '
            . 'SecurityPersonnel, SecurityTesting, UserReportedPhishing, SuspiciousActivity, '
            . 'SuspiciousButExpected, IncorrectAlert, ConfirmedActivity, LineOfBusinessApplication, '
            . 'MaliciousUserActivity, Apt, ConfidentialInformation, DataExfiltration, DataSpillage, '
            . 'DestructiveAttack, DenialOfService, Fraud, InsiderThreat, PasswordAttack, Ransomware, ValidAccounts).'
        );
    }

    /** Una sola llamada (caso que cabe en la ventana del modelo). */
    private function singleTriage(string $payload, ?int $profileId): array
    {
        $userPrompt = "CASO ANONIMIZADO (JSON):\n" . $payload
            . "\n\nTAREA: Analiza esta incidencia y devuelve únicamente el JSON indicado.";

        return llm_run_json(
            'incident_triage',
            $this->triageSystemPrompt() . ' ' . $this->triageFormatPrompt(),
            $userPrompt,
            [
                'profile_id'  => $profileId ?? 0,
                'max_tokens'  => 2500,
                'think'       => false,
            ]
        );
    }

    /** Guarda el resultado (parcial o final) como triaje del caso. */
    private function storeTriageResult(int $caseId, array $res, ?int $profileId): void
    {
        $rawContent = (string)($res['content'] ?? '');
        $parsed = is_array($res['data'] ?? null) ? $res['data'] : self::parseAiJson($rawContent);
        if ($parsed !== null && !self::isValidTriage($parsed)) {
            // Objeto con claves internas (resumen_parcial…): se promueven antes
            // de darlo por inválido.
            $promoted = self::promotePartialTriage($parsed);
            $parsed = self::isValidTriage($promoted) ? $promoted : null;
        }
        if ($parsed === null) {
            $parsed = [
                'veredicto_asistido' => null,
                'resumen_ejecutivo'  => 'La IA no devolvió un análisis con el formato esperado. '
                    . 'Respuesta original conservada abajo.',
                'respuesta_original' => $rawContent,
            ];
        }

        $this->store()->saveTriage(
            $caseId,
            $parsed,
            isset($res['model']) ? (string)$res['model'] : null,
            $profileId,
            $rawContent
        );
    }

    /**
     * Caracteres por parte: un tercio de la ventana del modelo de entrada,
     * con suelo y techo para no encadenar decenas de llamadas ni mandar una
     * parte que no quepa.
     */
    private function evidencePartChars(?int $profileId): int
    {
        $llm = ModuleManager::get('llm');
        $window = $llm instanceof Module_Llm ? $llm->contextWindow($profileId) : 0;
        if ($window <= 0) {
            return 12000;
        }
        // ~3,6 chars/token en español técnico; se usa el 30 % de la ventana
        // para que quede sitio a la salida.
        $chars = (int)floor($window * 0.30 * 3.6);
        return max(2500, min(12000, $chars));
    }

    /**
     * Divide la evidencia en partes que quepan en el modelo.
     *
     * Es pública para poder probarla sin IA: el smoke test comprueba que el
     * reparto conserva todos los eventos y su orden.
     *
     * @return array<int,array<string,mixed>> Vacío si basta una sola llamada.
     */
    public function evidenceParts(array $anon, int $maxChars, string $payload): array
    {
        if (llm_str_len($payload) <= $maxChars) {
            return [];
        }

        $eventos = array_values(array_filter((array)($anon['eventos'] ?? []), 'is_array'));
        if (count($eventos) < 2) {
            return [];
        }

        $header = $anon;
        unset($header['eventos']);
        $headerJson = (string)json_encode(
            $header,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );
        $headerChars = llm_str_len($headerJson);
        if ($headerChars > intdiv($maxChars, 2)) {
            $headerJson = self::clip($headerJson, intdiv($maxChars, 2)) . "\n…(contexto recortado)";
            $headerChars = llm_str_len($headerJson);
        }

        $lens = [];
        $totalChars = 0;
        foreach ($eventos as $i => $ev) {
            // Se mide el JSON tal y como se envía (con sangría): es lo que
            // ocupa de verdad en el prompt de la parte.
            $lens[$i] = llm_str_len((string)json_encode(
                $ev,
                JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            ));
            $totalChars += $lens[$i];
        }

        $budget = max(1200, $maxChars - $headerChars - 600);
        $needed = (int)ceil($totalChars / max(1, $budget));
        $count = max(2, min(12, $needed));
        if ($count < 2) {
            return [];
        }

        // Reparto equilibrado por tamaño, conservando el orden temporal.
        $target = max(1, (int)ceil($totalChars / $count));
        $groups = [];
        $current = [];
        $size = 0;
        foreach ($eventos as $i => $ev) {
            $current[] = $ev;
            $size += $lens[$i];
            if ($size >= $target && count($groups) < $count - 1) {
                $groups[] = $current;
                $current = [];
                $size = 0;
            }
        }
        if ($current !== []) {
            $groups[] = $current;
        }
        if (count($groups) < 2) {
            return [];
        }

        $total = count($groups);
        $parts = [];
        $offset = 0;
        foreach ($groups as $index => $eventosParte) {
            $desde = $offset + 1;
            $offset += count($eventosParte);
            $parts[] = $this->makeEvidencePart($eventosParte, $headerJson, [
                'label'  => (string)($index + 1),
                'parte'  => $index + 1,
                'total'  => $total,
                'desde'  => $desde,
                'hasta'  => $offset,
            ]);
        }
        return $parts;
    }

    /**
     * Construye una parte (y sus subdivisiones) con el contexto del caso y
     * los eventos que le tocan.
     *
     * @param array<int,array> $eventos
     * @param array<string,mixed> $meta
     * @return array<string,mixed>
     */
    private function makeEvidencePart(array $eventos, string $headerJson, array $meta): array
    {
        $body = [
            'parte'        => (string)($meta['label'] ?? '1'),
            'total_partes' => (int)($meta['total'] ?? 1),
            'eventos'      => $eventos,
            'rango'        => (int)($meta['desde'] ?? 0) . '-' . (int)($meta['hasta'] ?? 0),
        ];

        return [
            'text'    => (string)json_encode(
                $body,
                JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            ),
            'header'  => $headerJson,
            'eventos' => $eventos,
            'meta'    => $meta,
        ];
    }

    /**
     * Parte una parte en dos (solo cuando el modelo la corta por tiempo).
     *
     * @param array<string,mixed> $part
     * @return array<int,array<string,mixed>>
     */
    private function splitEvidencePart(array $part): array
    {
        $eventos = array_values(array_filter((array)($part['eventos'] ?? []), 'is_array'));
        if (count($eventos) < 2) {
            return [];
        }

        $mitad = intdiv(count($eventos) + 1, 2);
        $meta = is_array($part['meta'] ?? null) ? $part['meta'] : [];
        $headerJson = (string)($part['header'] ?? '{}');
        $label = (string)($meta['label'] ?? '1');

        $a = array_slice($eventos, 0, $mitad);
        $b = array_slice($eventos, $mitad);

        return [
            $this->makeEvidencePart($a, $headerJson, [
                'label' => $label . 'a',
                'parte' => (int)($meta['parte'] ?? 1),
                'total' => (int)($meta['total'] ?? 1),
                'desde' => (int)($meta['desde'] ?? 0),
                'hasta' => (int)($meta['desde'] ?? 0) + count($a) - 1,
            ]),
            $this->makeEvidencePart($b, $headerJson, [
                'label' => $label . 'b',
                'parte' => (int)($meta['parte'] ?? 1),
                'total' => (int)($meta['total'] ?? 1),
                'desde' => (int)($meta['desde'] ?? 0) + count($a),
                'hasta' => (int)($meta['hasta'] ?? 0),
            ]),
        ];
    }

    /**
     * Ejecuta el triaje por partes y guarda el resultado final. Corre en
     * segundo plano (FPM) o en línea (sin FPM).
     *
     * @param array<int,array<string,mixed>> $parts
     */
    private function runTriageJob(
        int $caseId,
        ?int $profileId,
        array $parts,
        int $jobId,
        float $iniciado,
        string $lockOwner = ''
    ): void {
        $store = $this->store();
        $total = count($parts);
        $iniciado = $iniciado > 0 ? $iniciado : microtime(true);

        $chunkPrompt = llm_prompt(
            'llm.incident_story.triage.chunk',
            "CONTEXTO DEL CASO (JSON, sin eventos):\n{header}\n\n"
            . "PARTE {parte_num} DE {parte_total} — EVENTOS NORMALIZADOS (JSON):\n{parte}\n\n"
            . 'TAREA: analiza SOLO estos eventos en el contexto del caso. '
            . 'FORMATO OBLIGATORIO: responde SOLO con un objeto JSON (empieza por { y termina en }); '
            . 'NO devuelvas una lista ni texto alrededor. Objeto exacto: '
            . '{"parte":"{parte_num}","rango_eventos":"desde-hasta","resumen_parcial":"2-3 frases",'
            . '"cadena_de_eventos":"narrativa padre->hijo con timestamps clave de esta parte",'
            . '"hipotesis_parcial":"explicación más plausible de esta parte",'
            . '"veredicto_parcial":"benigna|sospechosa|ataque","confianza_pct":0,'
            . '"tecnicas_attck":["Txxxx"],"indicadores_maliciosos":["..."],"datos_faltantes":["..."]}. '
            . 'Sé breve: máximo 4 elementos por lista y 2 frases por campo de texto.'
        );

        $mergePrompt = llm_prompt(
            'llm.incident_story.triage.merge',
            "CONTEXTO DEL CASO (JSON, sin eventos):\n{header}\n\n"
            . "ANÁLISIS PARCIALES DE LA EVIDENCIA (JSON, uno por parte; {total} partes):\n{resultados}\n\n"
            . 'TAREA: fusiona los análisis parciales en UN ÚNICO análisis de la incidencia. '
            . 'FORMATO OBLIGATORIO: responde SOLO con el objeto JSON completo que pide el sistema '
            . '(empieza por { y termina en }); NO devuelvas una lista de técnicas ni texto alrededor. '
            . 'Los parciales son breves y pueden no traer todos los campos: completa el JSON final con lo '
            . 'que se deduzca de cada parte, sin inventar datos. Si dos partes se contradicen, explica la '
            . 'contradicción en datos_faltantes y baja la confianza.'
        );

        try {
            $res = llm_pipeline_run([
                'mode'             => 'json',
                'task'             => 'incident_triage',
                'profile_id'       => $profileId,
                'header'           => (string)($parts[0]['header'] ?? ''),
                'parts'            => $parts,
                'deadline_seconds' => LLM_PIPELINE_MAX_SECONDS,
                'min_split_chars'  => 1200,
                'should_stop'      => static fn(): bool => llm_job_is_cancelled($jobId),
                'validator'        => [self::class, 'isValidPartial'],
                'final_validator'  => [self::class, 'isValidTriage'],
                'system_map'    => $this->triageSystemPrompt() . ' En esta llamada analizas UNA PARTE de la '
                    . 'evidencia: el caso completo se ha dividido para que un modelo local pueda procesarlo. '
                    . 'No des un veredicto definitivo ni supongas eventos que no estén en esta parte.',
                'user_map'      => $chunkPrompt,
                'system_reduce' => $this->triageSystemPrompt() . ' ' . $this->triageFormatPrompt(),
                'user_reduce'   => $mergePrompt,
                'options'       => [
                    'max_tokens_map'     => 500,
                    'max_tokens_reduce'  => 1500,
                    'temperature'        => 0.2,
                    'think'              => false,
                ],
                'reduce_group'  => 4,
                'split'         => fn(array $part): array => $this->splitEvidencePart($part),
                'load_part'     => static function (string $key) use ($store, $caseId, $profileId, $total): ?array {
                    return $store->loadTriagePart($caseId, $key, $profileId, $total);
                },
                'save_part'     => static function (string $key, mixed $data, bool $ok, string $error, string $raw = '') use ($store, $caseId, $profileId, $total): void {
                    $encoded = is_array($data)
                        ? (string)json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
                        : null;
                    $store->saveTriagePart(
                        $caseId,
                        $key,
                        $ok ? 'done' : 'error',
                        $encoded,
                        $error,
                        $profileId,
                        $total,
                        $raw
                    );
                },
                'on_progress'   => static function (int $hechos, int $totalPartes, string $fase, array $stats = []) use ($store, $caseId, $jobId, $lockOwner, $iniciado): void {
                    $store->setTriageState($caseId, 'running', [
                        'fase'        => $fase,
                        'hechos'      => $hechos,
                        'total'       => $totalPartes,
                        'ok'          => (int)($stats['ok'] ?? 0),
                        'fallidos'    => (int)($stats['failed'] ?? 0),
                        'iniciado'    => $iniciado,
                        'actualizado' => microtime(true),
                        'job'         => $jobId,
                    ]);
                    llm_job_progress($jobId, $fase, $hechos, $totalPartes);
                    if ($lockOwner !== '') {
                        llm_job_renew($lockOwner, 3600);
                    }
                },
            ]);

            $data = is_array($res['data'] ?? null) ? $res['data'] : null;
            $motivoForma = '';

            if (empty($res['success'])) {
                // El modelo no respetó el formato, pero sí hay parciales: se
                // monta un informe con ellos en vez de perder el trabajo.
                if (!empty($res['invalid_format']) && !empty($res['partials'])) {
                    $motivoForma = 'El modelo no devolvió un análisis con el formato esperado: '
                        . 'este informe se ha montado con los fragmentos de cada parte.';
                    $data = self::buildFallbackTriage((array)$res['partials'], $motivoForma);
                } else {
                    $error = self::clip((string)($res['error'] ?? 'La IA no completó el análisis por partes.'), 900);
                    $store->setTriageState($caseId, 'error', null, $error);
                    llm_job_fail($jobId, $error);
                    app_log('warning', 'incident_story', 'Triaje IA por partes fallido', [
                        'case'   => $caseId,
                        'parts'  => $total,
                        'calls'  => (int)($res['calls'] ?? 0),
                        'ms'     => (int)($res['elapsed_ms'] ?? 0),
                        'error'  => $error,
                    ]);
                    return;
                }
            } elseif ($data === null || !self::isValidTriage($data)) {
                $motivoForma = 'El modelo no devolvió un análisis con el formato esperado: '
                    . 'este informe se ha montado con los fragmentos de cada parte.';
                $data = self::buildFallbackTriage((array)($res['partials'] ?? []), $motivoForma);
            }

            $stopped = (string)($res['stopped'] ?? '');
            if ($stopped !== '') {
                // Detenido a medias: los parciales traen sus propias claves
                // (resumen_parcial, veredicto_parcial…). Se promueven para que
                // la ficha muestre algo útil en vez de un JSON crudo.
                $data = self::promotePartialTriage($data);
            }

            $data['analisis_por_partes'] = $total;
            if (!empty($res['invalid_format']) && $motivoForma === '') {
                $motivoForma = 'El modelo no devolvió un análisis con el formato esperado: '
                    . 'este informe se ha montado con los fragmentos de cada parte.';
            }
            $avisos = [];
            if ($motivoForma !== '') {
                $avisos[] = $motivoForma;
            }
            if ($stopped !== '') {
                $data['detenido'] = $stopped;
                $avisos[] = $stopped === 'cancel'
                    ? 'Análisis detenido por el usuario: se guarda lo que ya estaba analizado.'
                    : 'El análisis superó el tiempo máximo y se detuvo: se guarda lo que ya estaba analizado.';
            }
            if ((int)($res['failed'] ?? 0) > 0) {
                $data['partes_fallidas'] = (int)$res['failed'];
                $avisos[] = 'El análisis se completó con ' . (int)$res['failed'] . ' de ' . $total
                    . ' partes sin resultado: revisa la cobertura antes de decidir.';
            }
            if (!empty($res['clipped'])) {
                $avisos[] = 'Alguna parte se recortó para caber en la ventana del modelo: la cobertura '
                    . 'puede ser parcial. Reduce el caso o sube la ventana del perfil.';
            }
            if ($avisos !== []) {
                $data['aviso'] = implode(' ', $avisos);
            }

            $store->saveTriage(
                $caseId,
                $data,
                (string)($res['model'] ?? ''),
                $profileId,
                (string)($res['content'] ?? '')
            );
            $store->setTriageState($caseId, 'done', [
                'fase'        => $stopped === 'cancel' ? 'Detenido por el usuario' : 'Análisis completado',
                'hechos'      => $total,
                'total'       => $total,
                'ok'          => (int)($res['parts'] ?? 0) - (int)($res['failed'] ?? 0),
                'fallidos'    => (int)($res['failed'] ?? 0),
                'iniciado'    => $iniciado,
                'actualizado' => microtime(true),
                'job'         => $jobId,
            ]);
            llm_job_finish($jobId, (string)($res['content'] ?? ''), $data);
            app_log('info', 'incident_story', 'Triaje IA por partes completado', [
                'case'     => $caseId,
                'parts'    => $total,
                'failed'   => (int)($res['failed'] ?? 0),
                'calls'    => (int)($res['calls'] ?? 0),
                'merged'   => (int)($res['merged'] ?? 0),
                'ms'       => (int)($res['elapsed_ms'] ?? 0),
                'warnings' => count((array)($res['warnings'] ?? [])),
            ]);
        } catch (Throwable $e) {
            $error = 'Error inesperado durante el triaje por partes: ' . $e->getMessage();
            $store->setTriageState($caseId, 'error', null, self::clip($error, 900));
            llm_job_fail($jobId, $error);
            app_log('error', 'incident_story', 'Triaje IA por partes: excepción', [
                'case'  => $caseId,
                'parts' => $total,
                'error' => $e->getMessage(),
            ]);
        } finally {
            if ($lockOwner !== '') {
                llm_job_release($lockOwner);
            }
        }
    }

    /**
     * ¿El resultado tiene forma de análisis? Una lista (por ejemplo de
     * técnicas ATT&CK) no lo es: se rechaza en lugar de guardarla.
     */
    public static function isValidTriage(mixed $data): bool
    {
        if (!is_array($data) || $data === [] || array_is_list($data)) {
            return false;
        }
        foreach (['resumen_ejecutivo', 'veredicto_asistido'] as $key) {
            if (isset($data[$key]) && is_string($data[$key]) && trim($data[$key]) !== '') {
                return true;
            }
        }
        return false;
    }

    /**
     * Forma mínima de una PARTE: objeto con algún texto de análisis o alguna
     * lista de indicadores/técnicas. Una lista pelada no vale.
     */
    public static function isValidPartial(mixed $data): bool
    {
        if (!is_array($data) || $data === [] || array_is_list($data)) {
            return false;
        }
        foreach ([
            'resumen_parcial', 'resumen_ejecutivo', 'veredicto_parcial', 'veredicto_asistido',
            'hipotesis_parcial', 'hipotesis_principal', 'cadena_de_eventos',
        ] as $key) {
            if (isset($data[$key]) && is_string($data[$key]) && trim($data[$key]) !== '') {
                return true;
            }
        }
        foreach (['tecnicas_attck', 'indicadores_maliciosos', 'acciones_recomendadas'] as $key) {
            if (isset($data[$key]) && is_array($data[$key]) && $data[$key] !== []) {
                return true;
            }
        }
        return false;
    }

    /**
     * Informe de emergencia cuando el modelo no respetó el formato: se monta
     * con lo que traiga cada parte. Nunca devuelve una lista pelada.
     *
     * @param array<int,mixed> $partials
     * @return array<string,mixed>
     */
    public static function buildFallbackTriage(array $partials, string $motivo = ''): array
    {
        $resumen = [];
        $cadena = [];
        $hipotesis = '';
        $veredictos = [];
        $confianzas = [];
        $tecnicas = [];
        $malos = [];
        $faltan = [];

        foreach ($partials as $parte) {
            if (is_array($parte) && array_is_list($parte)) {
                // El modelo contestó una lista: si son cadenas, son técnicas.
                foreach ($parte as $item) {
                    if (is_string($item) && trim($item) !== '') {
                        $tecnicas[] = trim($item);
                    }
                }
                continue;
            }
            if (!is_array($parte)) {
                continue;
            }

            foreach (['resumen_parcial', 'resumen_ejecutivo'] as $key) {
                $v = isset($parte[$key]) && is_string($parte[$key]) ? trim($parte[$key]) : '';
                if ($v !== '') {
                    $resumen[] = $v;
                    break;
                }
            }
            if (isset($parte['cadena_de_eventos']) && is_string($parte['cadena_de_eventos'])) {
                $v = trim($parte['cadena_de_eventos']);
                if ($v !== '') {
                    $cadena[] = $v;
                }
            }
            if ($hipotesis === '') {
                foreach (['hipotesis_parcial', 'hipotesis_principal'] as $key) {
                    $v = isset($parte[$key]) && is_string($parte[$key]) ? trim($parte[$key]) : '';
                    if ($v !== '') {
                        $hipotesis = $v;
                        break;
                    }
                }
            }
            foreach (['veredicto_parcial', 'veredicto_asistido'] as $key) {
                $v = isset($parte[$key]) && is_string($parte[$key]) ? strtolower(trim($parte[$key])) : '';
                if ($v !== '') {
                    $veredictos[] = $v;
                    break;
                }
            }
            if (isset($parte['confianza_pct']) && is_numeric($parte['confianza_pct'])) {
                $confianzas[] = max(0, min(100, (int)$parte['confianza_pct']));
            }
            foreach (['tecnicas_attck', 'indicadores_maliciosos', 'datos_faltantes'] as $key) {
                if (!isset($parte[$key]) || !is_array($parte[$key])) {
                    continue;
                }
                foreach ($parte[$key] as $item) {
                    if (!is_scalar($item)) {
                        continue;
                    }
                    $s = trim((string)$item);
                    if ($s === '') {
                        continue;
                    }
                    if ($key === 'tecnicas_attck') {
                        $tecnicas[] = $s;
                    } elseif ($key === 'indicadores_maliciosos') {
                        $malos[] = $s;
                    } else {
                        $faltan[] = $s;
                    }
                }
            }
        }

        $veredicto = '';
        if ($veredictos !== []) {
            $cuenta = array_count_values($veredictos);
            arsort($cuenta);
            $veredicto = (string)array_key_first($cuenta);
        }
        $confianza = $confianzas !== []
            ? (int)round(array_sum($confianzas) / count($confianzas))
            : 0;

        $out = [
            'resumen_ejecutivo'      => $resumen !== []
                ? implode(' ', array_slice(array_values(array_unique($resumen)), 0, 6))
                : 'El modelo no devolvió un resumen utilizable.',
            'cadena_de_eventos'      => implode("\n", array_slice(array_values(array_unique($cadena)), 0, 8)),
            'hipotesis_principal'    => $hipotesis,
            'veredicto_asistido'     => $veredicto,
            'confianza_pct'          => $confianza,
            'tecnicas_attck'         => array_values(array_unique($tecnicas)),
            'indicadores_maliciosos' => array_values(array_unique($malos)),
            'datos_faltantes'        => array_values(array_unique($faltan)),
            'analisis_automatico'    => false,
        ];
        if ($motivo !== '') {
            $out['aviso'] = $motivo;
        }
        return $out;
    }

    /**
     * Promueve las claves de un análisis parcial (detenido por tiempo o por el
     * usuario) a las del triaje final, para que la ficha muestre algo útil en
     * vez de un JSON con nombres internos.
     */
    public static function promotePartialTriage(array $data): array
    {
        $map = [
            'resumen_parcial'   => 'resumen_ejecutivo',
            'hipotesis_parcial' => 'hipotesis_principal',
            'veredicto_parcial' => 'veredicto_asistido',
        ];
        foreach ($map as $from => $to) {
            if (empty($data[$to]) && !empty($data[$from])) {
                $data[$to] = $data[$from];
            }
        }
        return $data;
    }

    /** Parsea el JSON del LLM tolerando fences y texto envolvente. */
    public static function parseAiJson(string $content): ?array
    {
        $s = trim($content);
        if ($s === '') {
            return null;
        }
        if (preg_match('/```(?:json)?\s*(.*?)```/is', $s, $m)) {
            $s = trim($m[1]);
        }
        $start = strpos($s, '{');
        $end = strrpos($s, '}');
        if ($start === false || $end === false || $end <= $start) {
            return null;
        }
        $data = json_decode(substr($s, $start, $end - $start + 1), true);
        return is_array($data) ? $data : null;
    }

    /* =====================================================================
     * Decisión humana
     * ================================================================== */

    public function decision(array $params = []): void
    {
        Csrf::validateOrFail();
        $case = $this->loadCaseOrRedirect($params);

        $classification = (string)($_POST['classification'] ?? '');
        if (!isset(IncidentStoryStore::CLASSIFICATIONS[$classification])) {
            $this->failDecision('Selecciona una clasificación válida.', (int)$case['id']);
        }

        $determination = (string)($_POST['determination'] ?? 'NotAvailable');
        if (!in_array($determination, IncidentStoryStore::DETERMINATIONS, true)) {
            $this->failDecision('Selecciona una determinación válida.', (int)$case['id']);
        }

        $justificacion = trim((string)($_POST['justificacion'] ?? ''));
        if (strlen($justificacion) > 4000) {
            $justificacion = self::clip($justificacion, 4000);
        }

        $triage = is_array($case['triage'] ?? null) ? $case['triage'] : [];
        $veredicto = strtolower(trim((string)($triage['veredicto_asistido'] ?? '')));
        $contradice = ($veredicto === 'benigna' && in_array($classification, ['truePositive', 'unknown'], true))
            || (in_array($veredicto, ['sospechosa', 'ataque'], true)
                && in_array($classification, ['falsePositive', 'informationalExpectedActivity'], true));

        if ($contradice && $justificacion === '') {
            $this->failDecision('La decisión contradice el veredicto asistido: explica el motivo en la justificación.', (int)$case['id']);
        }

        $user = Auth::user();
        $analista = trim((string)($_POST['analista'] ?? ''));
        if ($analista === '' && $user !== null) {
            $analista = trim((string)($user['display_name'] ?? '')) ?: (string)$user['username'];
        }
        if ($analista === '') {
            $this->failDecision('Indica el nombre del analista.', (int)$case['id']);
        }

        $this->store()->addDecision(
            (int)$case['id'],
            self::clip($analista, 190),
            $classification,
            $determination,
            $justificacion,
            $veredicto !== '' ? $veredicto : null
        );

        flash('incident_story', ['type' => 'success', 'text' => 'Decisión humana registrada en la auditoría del caso.']);
        redirect(base_url('modules/incident_story/case/' . (int)$case['id']));
    }

    private function failDecision(string $message, int $caseId): never
    {
        flash('incident_story', ['type' => 'error', 'text' => $message]);
        redirect(base_url('modules/incident_story/case/' . $caseId));
    }

    public function delete(array $params = []): void
    {
        Csrf::validateOrFail();
        Auth::requireAdmin();
        $case = $this->loadCaseOrRedirect($params);
        $this->store()->deleteCase((int)$case['id']);
        flash('incident_story', ['type' => 'success', 'text' => 'Caso eliminado, junto con sus decisiones.']);
        redirect(base_url('modules/incident_story'));
    }

    private function loadCaseOrRedirect(array $params): array
    {
        $case = $this->store()->getCase((int)($params['id'] ?? 0));
        if ($case === null) {
            flash('incident_story', ['type' => 'error', 'text' => 'El caso no existe.']);
            redirect(base_url('modules/incident_story'));
        }
        return $case;
    }

    /** Recorte seguro aunque el hosting no tenga mbstring. */
    private static function clip(string $text, int $length): string
    {
        if (function_exists('mb_substr')) {
            return mb_substr($text, 0, $length);
        }
        return substr($text, 0, $length);
    }
}
