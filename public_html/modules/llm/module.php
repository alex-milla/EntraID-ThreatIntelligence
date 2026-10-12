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
     * Verifica si el módulo está configurado.
     */
    public function isConfigured(): bool
    {
        return !empty(LLM_PROVIDER) && !empty(LLM_API_KEY);
    }

    /**
     * Envía un prompt al proveedor LLM configurado.
     */
    public function chat(string $systemPrompt, string $userPrompt, array $options = []): array
    {
        if (!$this->isConfigured()) {
            return ['success' => false, 'error' => 'LLM no configurado. Define LLM_PROVIDER y LLM_API_KEY en .env'];
        }

        $provider = strtolower(LLM_PROVIDER);

        try {
            return match ($provider) {
                'openai'    => $this->callOpenAI($systemPrompt, $userPrompt, $options),
                'anthropic' => $this->callAnthropic($systemPrompt, $userPrompt, $options),
                'ollama'    => $this->callOllama($systemPrompt, $userPrompt, $options),
                'azure'     => $this->callAzure($systemPrompt, $userPrompt, $options),
                default     => ['success' => false, 'error' => "Proveedor no soportado: $provider"],
            };
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    // ============================================================
    // Proveedores LLM
    // ============================================================

    private function callOpenAI(string $system, string $user, array $options): array
    {
        $url = LLM_API_URL ?: 'https://api.openai.com/v1/chat/completions';
        $model = LLM_MODEL ?: 'gpt-4o-mini';

        $body = json_encode([
            'model'       => $model,
            'messages'    => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user',   'content' => $user],
            ],
            'max_tokens'  => $options['max_tokens'] ?? LLM_MAX_TOKENS,
            'temperature' => $options['temperature'] ?? 0.3,
        ]);

        $response = $this->httpPost($url, $body, [
            'Authorization: Bearer ' . LLM_API_KEY,
            'Content-Type: application/json',
        ]);

        $content = $response['choices'][0]['message']['content'] ?? null;
        if ($content === null) {
            return ['success' => false, 'error' => 'Respuesta vacía del modelo', 'raw' => $response];
        }

        return ['success' => true, 'content' => $content, 'model' => $model];
    }

    private function callAnthropic(string $system, string $user, array $options): array
    {
        $url = LLM_API_URL ?: 'https://api.anthropic.com/v1/messages';
        $model = LLM_MODEL ?: 'claude-3-5-sonnet-20241022';

        $body = json_encode([
            'model'       => $model,
            'max_tokens'  => $options['max_tokens'] ?? LLM_MAX_TOKENS,
            'system'      => $system,
            'messages'    => [
                ['role' => 'user', 'content' => $user],
            ],
        ]);

        $response = $this->httpPost($url, $body, [
            'x-api-key: ' . LLM_API_KEY,
            'anthropic-version: 2023-06-01',
            'Content-Type: application/json',
        ]);

        $content = $response['content'][0]['text'] ?? null;
        if ($content === null) {
            return ['success' => false, 'error' => 'Respuesta vacía del modelo', 'raw' => $response];
        }

        return ['success' => true, 'content' => $content, 'model' => $model];
    }

    private function callOllama(string $system, string $user, array $options): array
    {
        $url = rtrim(LLM_API_URL ?: 'http://localhost:11434', '/') . '/api/chat';
        $model = LLM_MODEL ?: 'llama3.1';

        $body = json_encode([
            'model'    => $model,
            'messages' => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user',   'content' => $user],
            ],
            'stream'   => false,
            'options'  => [
                'num_predict' => $options['max_tokens'] ?? LLM_MAX_TOKENS,
            ],
        ]);

        $response = $this->httpPost($url, $body, ['Content-Type: application/json']);

        $content = $response['message']['content'] ?? null;
        if ($content === null) {
            return ['success' => false, 'error' => 'Respuesta vacía del modelo', 'raw' => $response];
        }

        return ['success' => true, 'content' => $content, 'model' => $model];
    }

    private function callAzure(string $system, string $user, array $options): array
    {
        $url = rtrim(LLM_API_URL, '/') . '/openai/deployments/' . LLM_MODEL . '/chat/completions?api-version=2024-02-15-preview';

        $body = json_encode([
            'messages'    => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user',   'content' => $user],
            ],
            'max_tokens'  => $options['max_tokens'] ?? LLM_MAX_TOKENS,
            'temperature' => $options['temperature'] ?? 0.3,
        ]);

        $response = $this->httpPost($url, $body, [
            'api-key: ' . LLM_API_KEY,
            'Content-Type: application/json',
        ]);

        $content = $response['choices'][0]['message']['content'] ?? null;
        if ($content === null) {
            return ['success' => false, 'error' => 'Respuesta vacía del modelo', 'raw' => $response];
        }

        return ['success' => true, 'content' => $content, 'model' => LLM_MODEL];
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
            ['method' => 'POST', 'pattern' => 'summarize-report/{id}',   'handler' => [$this, 'summarizeReportEndpoint']],
            ['method' => 'GET',  'pattern' => 'status',                  'handler' => [$this, 'getStatus']],
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        echo $this->render('index', [
            'module' => $this, 'tenants' => $tenants,
            'configured' => $this->isConfigured(),
            'provider' => LLM_PROVIDER ?: 'no configurado',
            'model' => LLM_MODEL ?: '—',
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

    public function summarizeReportEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        json_response($this->summarizeReport((int)($params['id'] ?? 0)));
    }

    public function getStatus(array $params = []): void
    {
        json_response([
            'configured' => $this->isConfigured(),
            'provider'   => LLM_PROVIDER ?: null,
            'model'      => LLM_MODEL ?: null,
        ]);
    }
}
