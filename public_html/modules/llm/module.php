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
     * Configuración efectiva: primero la guardada en la BD (Admin → APIs),
     * con fallback a las constantes de .env. Así no rompe instalaciones que
     * sigan configurando el LLM por .env.
     */
    public function cfg(): array
    {
        return llm_config();
    }

    /**
     * Verifica si el módulo está configurado.
     */
    public function isConfigured(): bool
    {
        $c = $this->cfg();
        if ($c['provider'] === '') {
            return false;
        }
        // Ollama y endpoints locales no requieren API key
        if (in_array($c['provider'], ['ollama'], true)) {
            return true;
        }
        return $c['api_key'] !== '';
    }

    /**
     * Envía un prompt al proveedor LLM configurado.
     */
    public function chat(string $systemPrompt, string $userPrompt, array $options = []): array
    {
        if (!$this->isConfigured()) {
            return ['success' => false, 'error' => 'LLM no configurado. Configúralo en Admin → APIs (o en .env).'];
        }

        $cfg = $this->cfg();

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
     * Enruta la petición al proveedor configurado.
     */
    private function dispatch(array $cfg, string $system, string $user, array $options): array
    {
        return match ($cfg['provider']) {
            // Compatibles con la API de chat/completions de OpenAI
            'openai', 'custom', 'gemini', 'mistral'
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
        if ($cfg['provider'] !== 'ollama' && empty($cfg['api_key'])) {
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
    // Proveedores LLM
    // ============================================================

    private function callOpenAI(array $cfg, string $system, string $user, array $options): array
    {
        // Endpoints y modelos por defecto de los proveedores compatibles con OpenAI
        [$defaultUrl, $defaultModel] = match ($cfg['provider']) {
            'gemini'  => ['https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', 'gemini-1.5-flash'],
            'mistral' => ['https://api.mistral.ai/v1/chat/completions', 'mistral-large-latest'],
            default   => ['https://api.openai.com/v1/chat/completions', 'gpt-4o-mini'],
        };
        $url = $cfg['api_url'] ?: $defaultUrl;
        $model = $cfg['model'] ?: $defaultModel;

        $body = json_encode([
            'model'       => $model,
            'messages'    => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user',   'content' => $user],
            ],
            'max_tokens'  => $options['max_tokens'] ?? $cfg['max_tokens'],
            'temperature' => $options['temperature'] ?? 0.3,
        ]);

        $response = $this->httpPost($url, $body, [
            'Authorization: Bearer ' . $cfg['api_key'],
            'Content-Type: application/json',
        ]);

        $content = $response['choices'][0]['message']['content'] ?? null;
        if ($content === null) {
            return ['success' => false, 'error' => 'Respuesta vacía del modelo', 'raw' => $response];
        }

        return ['success' => true, 'content' => $content, 'model' => $model];
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
    public function analyzeIncident(int $incidentId): array
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

        return $this->chat($system, $user);
    }

    /**
     * Analiza un conjunto de IOCs para clasificación.
     */
    public function classifyIocs(int $tenantId, int $limit = 50): array
    {
        $iocs = Database::fetchAll(
            "SELECT ioc_type, ioc_value, source FROM ti_iocs WHERE tenant_id = ? ORDER BY fetched_at DESC LIMIT ?",
            [$tenantId, $limit]
        );

        $system = 'Eres un analista de threat intelligence. Clasifica cada IOC en: tipo de amenaza (malware, phishing, C2, etc.), nivel de confianza (alta/media/baja) y una breve descripción. Responde en formato JSON array.';
        $user = "Clasifica estos IOCs:\n" . json_encode($iocs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

        $result = $this->chat($system, $user);
        if ($result['success']) {
            $result['classification'] = safe_json_decode($result['content'], null);
        }
        return $result;
    }

    /**
     * Extrae IOCs y resumen de un texto (artículo o correo) con IA.
     */
    public function extractIocs(string $text): array
    {
        $system = 'Eres un analista de threat intelligence. A partir del texto (artículo o correo), devuelve EXCLUSIVAMENTE un JSON válido con esta forma: '
            . '{"resumen":"...","iocs":[{"tipo":"ipv4-addr|domain-name|url|file|email-addr|otro","valor":"..."}],"recomendaciones":"..."}. '
            . 'No inventes IOCs; si no hay, deja el array vacío. Responde en español.';
        $user = "Analiza el siguiente contenido:\n\n" . $text;

        $res = $this->chat($system, $user);
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
    public function summarizeReport(int $reportId): array
    {
        $report = Database::fetchOne("SELECT * FROM reports WHERE id = ?", [$reportId]);
        if (!$report) return ['success' => false, 'error' => 'Reporte no encontrado'];

        $data = safe_json_decode($report['data'], []);

        $system = 'Eres un analista de ciberseguridad que escribe informes ejecutivos. Convierte los datos técnicos en un resumen narrativo profesional en español, destacando los hallazgos más relevantes y el estado general de la seguridad.';
        $user = "Genera un resumen ejecutivo del siguiente reporte ({$report['title']}):\n" . json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

        return $this->chat($system, $user);
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
        echo $this->page('index', [
            'module' => $this, 'tenants' => $tenants,
            'configured' => $this->isConfigured(),
            'provider' => $cfg['provider'] ?: 'no configurado',
            'model' => $cfg['model'] ?: '—',
        ]);
    }

    public function chatEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $result = $this->chat(
            $input['system'] ?? 'Eres un asistente de ciberseguridad.',
            $input['prompt'] ?? '',
            $input['options'] ?? []
        );
        json_response($result);
    }

    public function analyzeIncidentEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        json_response($this->analyzeIncident((int)($params['id'] ?? 0)));
    }

    public function classifyIocsEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        json_response($this->classifyIocs((int)($input['tenant_id'] ?? 0), (int)($input['limit'] ?? 50)));
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

        json_response($this->extractIocs($text));
    }

    public function summarizeReportEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        json_response($this->summarizeReport((int)($params['id'] ?? 0)));
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
