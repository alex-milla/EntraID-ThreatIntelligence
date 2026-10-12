<?php
/**
 * Módulo: Integración LLM
 * Permite analizar datos almacenados con modelos de lenguaje (OpenAI, Anthropic, Ollama, Azure).
 * La API key NUNCA se expone al frontend; todas las llamadas pasan por el backend.
 */

declare(strict_types=1);

class Module_Llm extends BaseModule
{
    public function key(): string { return 'llm'; }
    public function name(): string { return 'Análisis LLM'; }
    public function description(): string { return 'Análisis de datos con modelos de lenguaje'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return []; // No usa Graph, usa la API del proveedor LLM
    }

    public function isSyncable(): bool
    {
        return false;
    }

    public function sync(int $tenantId): array
    {
        return ['success' => true, 'records' => 0];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Análisis IA',
            'url'   => base_url('modules/llm'),
            'icon'  => 'brain',
            'group' => 'Análisis',
        ];
    }

    /**
     * Configuración efectiva: perfil indicado → perfil predeterminado →
     * configuración única (compat) → constantes .env.
     */
    public function cfg(?int $profileId = null): array
    {
        return llm_config($profileId);
    }

    /**
     * Perfiles de IA disponibles (para el selector).
     */
    public function profiles(): array
    {
        return llm_profile_list();
    }

    /**
     * Verifica si el módulo está configurado (para un perfil concreto o el predeterminado).
     */
    public function isConfigured(?int $profileId = null): bool
    {
        $c = $this->cfg($profileId);
        if ($c['provider'] === '') {
            return false;
        }
        // Ollama y OpenCode Console (modelos gratis) no requieren API key
        if (in_array($c['provider'], ['ollama', 'opencode'], true)) {
            return true;
        }
        return $c['api_key'] !== '';
    }

    /**
     * Envía un prompt al proveedor LLM configurado (perfil opcional).
     */
    public function chat(string $systemPrompt, string $userPrompt, array $options = [], ?int $profileId = null): array
    {
        if (!$this->isConfigured($profileId)) {
            return ['success' => false, 'error' => 'LLM no configurado. Configúralo en Admin → APIs.'];
        }

        $cfg = $this->cfg($profileId);

        try {
            $res = $this->dispatch($cfg, $systemPrompt, $userPrompt, $options);
            if (!empty($res['success']) && isset($res['content'])) {
                // HTML renderizado (Markdown seguro) para pintarlo como los artículos
                $res['content_html'] = render_markdown((string)$res['content']);
            }
            return $res;
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Perfil a usar: el indicado en la petición o el configurado para la tarea.
     */
    private function resolveProfile(array $input, string $task): ?int
    {
        $pid = (int)($input['profile_id'] ?? 0);
        if ($pid > 0) {
            return $pid;
        }
        return llm_task_profile($task);
    }

    /**
     * Enruta la petición al proveedor configurado.
     */
    private function dispatch(array $cfg, string $system, string $user, array $options): array
    {
        return match ($cfg['provider']) {
            // Compatibles con la API de chat/completions de OpenAI
            'openai', 'custom', 'gemini', 'mistral', 'opencode'
                        => $this->callOpenAI($cfg, $system, $user, $options),
            'anthropic' => $this->callAnthropic($cfg, $system, $user, $options),
            'ollama'    => $this->callOllama($cfg, $system, $user, $options),
            'azure'     => $this->callAzure($cfg, $system, $user, $options),
            default     => ['success' => false, 'error' => 'Proveedor no soportado: ' . $cfg['provider']],
        };
    }

    /**
     * Prueba la conexión con el proveedor (config actual o los valores dados).
     * Usado por el panel Admin → APIs.
     */
    public function testConnection(array $override = []): array
    {
        $cfg = array_merge($this->cfg(), $override);
        if (empty($cfg['provider'])) {
            return ['success' => false, 'error' => 'Falta seleccionar un proveedor'];
        }
        if (!in_array($cfg['provider'], ['ollama', 'opencode'], true) && empty($cfg['api_key'])) {
            return ['success' => false, 'error' => 'Falta la API key'];
        }
        try {
            $res = $this->dispatch($cfg, 'Eres un asistente.', 'ping', ['max_tokens' => 5]);
            if (!empty($res['success'])) {
                return ['success' => true, 'message' => 'Conexión correcta con ' . $cfg['provider'] . ' (' . ($res['model'] ?? $cfg['model']) . ')'];
            }
            return $res;
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    // ============================================================
    // Modelos disponibles (carga automática, solo OpenCode Console)
    // ============================================================

    /** Modelos de OpenCode que NO retienen ni entrenan con datos (allowlist propia). */
    private const OPENCODE_ZERO_RETENTION = [
        'space-bunny-free',
        'longcat-2.5-preview-free',
        'step-5-preview-free',
    ];

    /** Modelos gratis de OpenCode que (según su política) SÍ pueden usar datos. */
    private const OPENCODE_TRAINS = [
        'ling-3.1-flash-free',
        'mimo-v2.6-flash-free',
        'nemotron-3.5-lightning-free',
        'muse-spark-1.2-contributor-free',
        'muse-spark-1.3-contributor-free',
        'big-pickle',
    ];

    /**
     * Lista los modelos disponibles del proveedor (solo OpenCode Console),
     * leyendo su endpoint OpenAI-compatible /models. Con caché de 1 h.
     */
    public function listModels(array $cfg = [], bool $refresh = false): array
    {
        $cfg = array_merge($this->cfg(), $cfg);
        if (($cfg['provider'] ?? '') !== 'opencode') {
            return ['success' => false, 'error' => 'La carga automática de modelos solo está disponible para OpenCode Console.'];
        }

        $cacheKey = 'llm_models_cache_opencode';
        if (!$refresh) {
            $cached = setting_get($cacheKey);
            if (is_string($cached) && $cached !== '') {
                $data = safe_json_decode($cached, null);
                if (is_array($data) && isset($data['ts'], $data['models']) && (time() - (int)$data['ts']) < 3600) {
                    return ['success' => true, 'models' => $data['models'], 'cached' => true, 'source' => 'cache'];
                }
            }
        }

        try {
            $res = $this->httpGet('https://opencode.ai/inference/v1/models');
        } catch (Throwable $e) {
            return [
                'success'  => true,
                'models'   => $this->curatedOpenCodeModels(),
                'cached'   => false,
                'fallback' => true,
                'error'    => 'No se pudo consultar OpenCode (' . $e->getMessage() . '). Se muestra la lista conocida.',
            ];
        }

        $ids = [];
        foreach ($res['data'] ?? [] as $m) {
            if (!empty($m['id'])) {
                $ids[] = (string)$m['id'];
            }
        }
        if (empty($ids)) {
            return [
                'success'  => true,
                'models'   => $this->curatedOpenCodeModels(),
                'cached'   => false,
                'fallback' => true,
                'error'    => 'OpenCode no devolvió modelos. Se muestra la lista conocida.',
            ];
        }

        $models = array_map(fn(string $id): array => $this->classifyModel($id), $ids);
        setting_set($cacheKey, json_encode(['ts' => time(), 'models' => $models]));

        return ['success' => true, 'models' => $models, 'cached' => false, 'source' => 'api'];
    }

    /**
     * Etiqueta un modelo de OpenCode según nuestra clasificación de privacidad.
     * (La API no expone la retención: esto es política nuestra.)
     */
    private function classifyModel(string $id): array
    {
        if (in_array($id, self::OPENCODE_ZERO_RETENTION, true)) {
            return ['id' => $id, 'group' => 'zero', 'label' => $id . ' — zero-retention'];
        }
        if (in_array($id, self::OPENCODE_TRAINS, true)) {
            return ['id' => $id, 'group' => 'trains', 'label' => $id . ' — gratis (puede usar datos)'];
        }
        if (str_ends_with($id, '-free')) {
            return ['id' => $id, 'group' => 'free_unknown', 'label' => $id . ' — gratis (sin clasificar)'];
        }
        return ['id' => $id, 'group' => 'other', 'label' => $id];
    }

    /**
     * Lista curada de respaldo (si la API de OpenCode no responde).
     */
    private function curatedOpenCodeModels(): array
    {
        $ids = array_merge(self::OPENCODE_ZERO_RETENTION, self::OPENCODE_TRAINS, ['jev-1.13-free']);
        return array_map(fn(string $id): array => $this->classifyModel($id), $ids);
    }

    // ============================================================
    // Proveedores LLM
    // ============================================================

    private function callOpenAI(array $cfg, string $system, string $user, array $options): array
    {
        // Endpoints y modelos por defecto de los proveedores compatibles con OpenAI
        [$defaultUrl, $defaultModel] = match ($cfg['provider']) {
            'gemini'   => ['https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', 'gemini-1.5-flash'],
            'mistral'  => ['https://api.mistral.ai/v1/chat/completions', 'mistral-large-latest'],
            'opencode' => ['https://opencode.ai/inference/v1/chat/completions', 'space-bunny-free'],
            default    => ['https://api.openai.com/v1/chat/completions', 'gpt-4o-mini'],
        };
        $url = $cfg['api_url'] ?: $defaultUrl;
        $model = $cfg['model'] ?: $defaultModel;

        // OpenCode Console: probar también el endpoint "openai" por si el primero diera 404
        $urls = [$url];
        if ($cfg['provider'] === 'opencode' && $cfg['api_url'] === '') {
            $urls[] = 'https://opencode.ai/inference/openai/v1/chat/completions';
        }

        $body = json_encode([
            'model'       => $model,
            'messages'    => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user',   'content' => $user],
            ],
            'max_tokens'  => $options['max_tokens'] ?? $cfg['max_tokens'],
            'temperature' => $options['temperature'] ?? 0.3,
        ]);

        $lastError = null;
        foreach ($urls as $u) {
            try {
                $response = $this->httpPost($u, $body, [
                    'Authorization: Bearer ' . $cfg['api_key'],
                    'Content-Type: application/json',
                ]);

                $content = $response['choices'][0]['message']['content'] ?? null;
                if ($content === null) {
                    $lastError = new RuntimeException('Respuesta vacía del modelo');
                    continue;
                }

                return ['success' => true, 'content' => $content, 'model' => $model];
            } catch (Throwable $e) {
                $lastError = $e;
            }
        }

        throw $lastError ?? new RuntimeException('Error en la llamada al modelo');
    }

    private function callAnthropic(array $cfg, string $system, string $user, array $options): array
    {
        $url = $cfg['api_url'] ?: 'https://api.anthropic.com/v1/messages';
        $model = $cfg['model'] ?: 'claude-3-5-sonnet-20241022';

        $body = json_encode([
            'model'       => $model,
            'max_tokens'  => $options['max_tokens'] ?? $cfg['max_tokens'],
            'system'      => $system,
            'messages'    => [
                ['role' => 'user', 'content' => $user],
            ],
        ]);

        $response = $this->httpPost($url, $body, [
            'x-api-key: ' . $cfg['api_key'],
            'anthropic-version: 2023-06-01',
            'Content-Type: application/json',
        ]);

        $content = $response['content'][0]['text'] ?? null;
        if ($content === null) {
            return ['success' => false, 'error' => 'Respuesta vacía del modelo', 'raw' => $response];
        }

        return ['success' => true, 'content' => $content, 'model' => $model];
    }

    private function callOllama(array $cfg, string $system, string $user, array $options): array
    {
        $url = rtrim($cfg['api_url'] ?: 'http://localhost:11434', '/') . '/api/chat';
        $model = $cfg['model'] ?: 'llama3.1';

        $body = json_encode([
            'model'    => $model,
            'messages' => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user',   'content' => $user],
            ],
            'stream'   => false,
            'options'  => [
                'num_predict' => $options['max_tokens'] ?? $cfg['max_tokens'],
            ],
        ]);

        $response = $this->httpPost($url, $body, ['Content-Type: application/json']);

        $content = $response['message']['content'] ?? null;
        if ($content === null) {
            return ['success' => false, 'error' => 'Respuesta vacía del modelo', 'raw' => $response];
        }

        return ['success' => true, 'content' => $content, 'model' => $model];
    }

    private function callAzure(array $cfg, string $system, string $user, array $options): array
    {
        $url = rtrim($cfg['api_url'], '/') . '/openai/deployments/' . $cfg['model'] . '/chat/completions?api-version=2024-02-15-preview';

        $body = json_encode([
            'messages'    => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user',   'content' => $user],
            ],
            'max_tokens'  => $options['max_tokens'] ?? $cfg['max_tokens'],
            'temperature' => $options['temperature'] ?? 0.3,
        ]);

        $response = $this->httpPost($url, $body, [
            'api-key: ' . $cfg['api_key'],
            'Content-Type: application/json',
        ]);

        $content = $response['choices'][0]['message']['content'] ?? null;
        if ($content === null) {
            return ['success' => false, 'error' => 'Respuesta vacía del modelo', 'raw' => $response];
        }

        return ['success' => true, 'content' => $content, 'model' => $cfg['model']];
    }

    // ============================================================
    // Análisis predefinidos sobre datos almacenados
    // ============================================================

    /**
     * Analiza un incidente con LLM para obtener resumen ejecutivo.
     */
    public function analyzeIncident(int $incidentId, ?int $profileId = null): array
    {
        $incident = Database::fetchOne("SELECT * FROM incidents WHERE id = ?", [$incidentId]);
        if (!$incident) return ['success' => false, 'error' => 'Incidente no encontrado'];

        $alerts = Database::fetchAll("SELECT * FROM alerts WHERE incident_id = ? LIMIT 10", [$incidentId]);

        $system = 'Eres un analista de ciberseguridad senior. Analiza incidentes de seguridad y proporciona un resumen ejecutivo claro, conciso y accionable en español. Incluye: naturaleza del incidente, impacto potencial, y 3 acciones recomendadas prioritarias.';
        $user = "Incidente: {$incident['display_name']}\nSeveridad: {$incident['severity']}\nEstado: {$incident['status']}\nClasificación: {$incident['classification']}\nAlertas asociadas:\n" . json_encode(array_map(fn($a) => [
            'title' => $a['title'],
            'threat' => $a['threat_display_name'],
            'service' => $a['service_source'],
            'mitre' => safe_json_decode($a['mitre_techniques'], []),
        ], $alerts), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

        return $this->chat($system, $user, [], $profileId);
    }

    /**
     * Analiza un conjunto de IOCs para clasificación.
     */
    public function classifyIocs(int $tenantId, int $limit = 50, ?int $profileId = null): array
    {
        $iocs = Database::fetchAll(
            "SELECT ioc_type, ioc_value, source FROM ti_iocs WHERE tenant_id = ? ORDER BY fetched_at DESC LIMIT ?",
            [$tenantId, $limit]
        );

        $system = 'Eres un analista de threat intelligence. Clasifica cada IOC en: tipo de amenaza (malware, phishing, C2, etc.), nivel de confianza (alta/media/baja) y una breve descripción. Responde en formato JSON array.';
        $user = "Clasifica estos IOCs:\n" . json_encode($iocs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

        $result = $this->chat($system, $user, [], $profileId);
        if ($result['success']) {
            $result['classification'] = safe_json_decode($result['content'], null);
        }
        return $result;
    }

    /**
     * Extrae IOCs y resumen de un texto (artículo o correo) con IA.
     */
    public function extractIocs(string $text, ?int $profileId = null): array
    {
        $system = 'Eres un analista de threat intelligence. A partir del texto (artículo o correo), devuelve EXCLUSIVAMENTE un JSON válido con esta forma: '
            . '{"resumen":"...","iocs":[{"tipo":"ipv4-addr|domain-name|url|file|email-addr|otro","valor":"..."}],"recomendaciones":"..."}. '
            . 'No inventes IOCs; si no hay, deja el array vacío. Responde en español.';
        $user = "Analiza el siguiente contenido:\n\n" . $text;

        $res = $this->chat($system, $user, [], $profileId);
        if (!empty($res['success'])) {
            $res['parsed'] = safe_json_decode($this->cleanJson((string)$res['content']), null);
        }
        return $res;
    }

    /**
     * Limpia posibles fences ```json ... ``` y recorta al primer objeto JSON.
     */
    private function cleanJson(string $s): string
    {
        $s = trim($s);
        if (preg_match('/```(?:json)?\s*(.*?)```/is', $s, $m)) {
            return trim($m[1]);
        }
        $start = strpos($s, '{');
        $end = strrpos($s, '}');
        if ($start !== false && $end !== false && $end > $start) {
            return substr($s, $start, $end - $start + 1);
        }
        return $s;
    }

    /**
     * Genera un resumen narrativo de un reporte.
     */
    public function summarizeReport(int $reportId, ?int $profileId = null): array
    {
        $report = Database::fetchOne("SELECT * FROM reports WHERE id = ?", [$reportId]);
        if (!$report) return ['success' => false, 'error' => 'Reporte no encontrado'];

        $data = safe_json_decode($report['data'], []);

        $system = 'Eres un analista de ciberseguridad que escribe informes ejecutivos. Convierte los datos técnicos en un resumen narrativo profesional en español, destacando los hallazgos más relevantes y el estado general de la seguridad.';
        $user = "Genera un resumen ejecutivo del siguiente reporte ({$report['title']}):\n" . json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

        return $this->chat($system, $user, [], $profileId);
    }

    /**
     * HTTP POST genérico con cURL.
     */
    private function httpPost(string $url, string $body, array $headers): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => 120,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            throw new RuntimeException("Error cURL: $error");
        }

        $decoded = json_decode($response, true);
        if ($httpCode >= 400) {
            $msg = $decoded['error']['message'] ?? $decoded['message'] ?? $response;
            throw new RuntimeException("LLM API Error ($httpCode): $msg");
        }

        return $decoded ?? ['raw' => $response];
    }

    /**
     * HTTP GET genérico con cURL (JSON).
     */
    private function httpGet(string $url): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('cURL no está disponible en el servidor.');
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            throw new RuntimeException("Error cURL: $error");
        }

        $decoded = json_decode($response, true);
        if ($httpCode >= 400) {
            $msg = $decoded['error']['message'] ?? $decoded['message'] ?? $response;
            throw new RuntimeException("HTTP $httpCode: $msg");
        }

        return $decoded ?? [];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                        'handler' => [$this, 'index']],
            ['method' => 'POST', 'pattern' => 'chat',                    'handler' => [$this, 'chatEndpoint']],
            ['method' => 'POST', 'pattern' => 'analyze-incident/{id}',   'handler' => [$this, 'analyzeIncidentEndpoint']],
            ['method' => 'POST', 'pattern' => 'classify-iocs',           'handler' => [$this, 'classifyIocsEndpoint']],
            ['method' => 'POST', 'pattern' => 'extract-iocs',            'handler' => [$this, 'extractIocsEndpoint']],
            ['method' => 'POST', 'pattern' => 'summarize-report/{id}',   'handler' => [$this, 'summarizeReportEndpoint']],
            ['method' => 'GET',  'pattern' => 'status',                  'handler' => [$this, 'getStatus']],
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $cfg = $this->cfg();
        $defaultProfile = llm_profile_default();
        echo $this->page('index', [
            'module' => $this, 'tenants' => $tenants,
            'configured' => $this->isConfigured(),
            'provider' => $cfg['provider'] ?: 'no configurado',
            'model' => $cfg['model'] ?: '—',
            'profiles' => $this->profiles(),
            'defaultProfileId' => $defaultProfile['id'] ?? null,
        ]);
    }

    public function chatEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $result = $this->chat(
            $input['system'] ?? 'Eres un asistente de ciberseguridad.',
            $input['prompt'] ?? '',
            $input['options'] ?? [],
            $this->resolveProfile($input, 'chat')
        );
        json_response($result);
    }

    public function analyzeIncidentEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        json_response($this->analyzeIncident((int)($params['id'] ?? 0), $this->resolveProfile($input, 'analyze_incident')));
    }

    public function classifyIocsEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        json_response($this->classifyIocs((int)($input['tenant_id'] ?? 0), (int)($input['limit'] ?? 50), $this->resolveProfile($input, 'classify_iocs')));
    }

    public function extractIocsEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

        $text = (string)($input['text'] ?? '');
        $articleId = (int)($input['article_id'] ?? 0);

        if ($articleId > 0 && trim($text) === '') {
            $a = Database::fetchOne("SELECT title, summary, body FROM ti_articles WHERE id = ?", [$articleId]);
            if (!$a) {
                json_response(['success' => false, 'error' => 'Artículo no encontrado']);
            }
            $text = ($a['title'] ?? '') . "\n\n" . ($a['summary'] ?? '') . "\n\n" . strip_tags((string)($a['body'] ?? ''));
        }

        if (trim($text) === '') {
            json_response(['success' => false, 'error' => 'No hay texto para analizar']);
        }

        json_response($this->extractIocs($text, $this->resolveProfile($input, 'extract_iocs')));
    }

    public function summarizeReportEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        json_response($this->summarizeReport((int)($params['id'] ?? 0), $this->resolveProfile($input, 'summarize_report')));
    }

    public function getStatus(array $params = []): void
    {
        $cfg = $this->cfg();
        json_response([
            'configured' => $this->isConfigured(),
            'provider'   => $cfg['provider'] ?: null,
            'model'      => $cfg['model'] ?: null,
        ]);
    }
}
