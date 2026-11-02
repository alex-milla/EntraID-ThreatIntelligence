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

        $llm = ModuleManager::get('llm');
        if (!$llm instanceof Module_Llm) {
            flash('incident_story', ['type' => 'error', 'text' => 'El módulo de IA no está disponible.']);
            redirect(base_url('modules/incident_story/case/' . (int)$case['id']));
        }

        $profileId = (int)($_POST['profile_id'] ?? 0);
        $profileId = $profileId > 0 ? $profileId : null;
        if (!$llm->isConfigured($profileId)) {
            flash('incident_story', ['type' => 'error', 'text' => 'La IA no está configurada (Admin → APIs).']);
            redirect(base_url('modules/incident_story/case/' . (int)$case['id']));
        }

        $anon = is_array($case['anon'] ?? null) ? $case['anon'] : [];
        $payload = json_encode($anon, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '{}';
        if (strlen($payload) > INCIDENT_STORY_MAX_PROMPT_CHARS) {
            $payload = self::clip($payload, INCIDENT_STORY_MAX_PROMPT_CHARS)
                . "\n…(evidencia recortada por límite de tamaño)";
        }

        $system = llm_prompt(
            'llm.incident_story.triage.system',
            'Eres un analista senior de un SOC especializado en Microsoft Defender XDR y MITRE ATT&CK. '
            . 'Analizas la evidencia normalizada de una incidencia de Defender a partir de su story. '
            . 'Reglas: (1) trabaja SOLO con la evidencia aportada, no inventes datos ni IOC; '
            . '(2) si falta información imprescindible, pídela en preguntas_para_el_analista (máximo 5); '
            . '(3) no afirmes certeza absoluta: expresa confianza en porcentaje; '
            . '(4) el veredicto es ASISTIDO y la decisión final la toma una persona; '
            . '(5) responde SIEMPRE en español y SOLO con un objeto JSON válido, sin texto alrededor.'
        );
        $format = llm_prompt(
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

        $userPrompt = "CASO ANONIMIZADO (JSON):\n" . $payload
            . "\n\nTAREA: Analiza esta incidencia y devuelve únicamente el JSON indicado.";

        $res = $llm->chat($system . ' ' . $format, $userPrompt, ['max_tokens' => 2500], $profileId);
        $baseCaso = base_url('modules/incident_story/case/' . (int)$case['id']);
        if (empty($res['success'])) {
            redirect($baseCaso . '?triage_error=' . rawurlencode(self::clip((string)($res['error'] ?? 'error desconocido'), 500)) . '#triaje');
        }

        $rawContent = (string)($res['content'] ?? '');
        $parsed = self::parseAiJson($rawContent);
        if ($parsed === null) {
            $parsed = [
                'veredicto_asistido' => null,
                'resumen_ejecutivo'  => 'La IA no devolvió JSON válido. Respuesta original conservada abajo.',
                'respuesta_original' => $rawContent,
            ];
        }

        $this->store()->saveTriage(
            (int)$case['id'],
            $parsed,
            isset($res['model']) ? (string)$res['model'] : null,
            $profileId,
            $rawContent
        );

        redirect($baseCaso . '?triage_ok=1#triaje');
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
