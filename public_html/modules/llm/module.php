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
     * ¿La clave es opcional? Ollama local no la usa y un servidor propio
     * compatible con OpenAI puede no exigirla (LM Studio, llama.cpp sin auth).
     */
    private function keyOptional(array $cfg): bool
    {
        $provider = (string)($cfg['provider'] ?? '');
        if ($provider === 'ollama') {
            return true;
        }
        return $provider === 'custom' && trim((string)($cfg['api_url'] ?? '')) !== '';
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
        // Ollama (local) no requiere API key; un servidor propio tampoco.
        if ($this->keyOptional($c)) {
            return true;
        }
        return $c['api_key'] !== '';
    }

    /**
     * Envía un prompt al proveedor LLM configurado (perfil opcional).
     */
    public function chat(string $systemPrompt, string $userPrompt, array $options = [], ?int $profileId = null): array
    {
        // Liberar el bloqueo de sesión: las llamadas al LLM pueden tardar y no
        // deben impedir que el resto del portal siga respondiendo.
        release_session_lock();

        if (!$this->isConfigured($profileId)) {
            return ['success' => false, 'error' => 'LLM no configurado. Configúralo en Admin → APIs.'];
        }

        $cfg = $this->cfg($profileId);

        try {
            $res = $this->dispatch($cfg, $systemPrompt, $userPrompt, $options);
            if (!empty($res['success']) && isset($res['content'])) {
                // HTML renderizado (Markdown seguro) para pintarlo como los artículos
                $res['content_html'] = render_ai_markdown((string)$res['content']);
            }
            return $res;
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $this->friendlyError($e->getMessage(), $cfg)];
        }
    }

    /**
     * Traduce los errores más comunes de los proveedores a mensajes claros.
     */
    private function friendlyError(string $msg, array $cfg): string
    {
        $provider = (string)($cfg['provider'] ?? '');
        $model = (string)($cfg['model'] ?? '');
        $low = strtolower($msg);
        $who = $provider !== '' ? $provider : 'el proveedor';

        if (llm_err_is_context_overflow($msg)) {
            return $this->contextOverflowMessage($msg, $cfg);
        }
        if (llm_err_is_model_error($msg)) {
            return 'El modelo «' . ($model !== '' ? $model : '(vacío)') . '» no existe en ' . $who
                 . '. Usa «Listar modelos» en Admin → APIs para copiar el identificador exacto que sirve el servidor.';
        }
        if (llm_err_is_unavailable($msg)) {
            return 'El servidor de ' . $who . ' está ocupado (503): el modelo se está cargando. '
                 . 'Espera 15-30 s y reinténtalo.';
        }
        if (llm_err_is_timeout($msg)) {
            return 'Tiempo de espera agotado con ' . $who . '. La generación es larga (modelo local): '
                 . 'reduce el tamaño de la petición o vuelve a intentarlo.';
        }
        if (llm_err_is_not_found($msg)) {
            return 'Ruta inexistente (404) en ' . $who . '. La Base URL debe ser la raíz del servidor '
                 . '(p. ej. https://host): la aplicación añade /v1/chat/completions. No pegues '
                 . '/api/chat ni /chat/completions en el perfil.';
        }
        if (str_contains($low, 'invalid api key') || str_contains($low, 'incorrect api key') || str_contains($low, 'invalid credential') || str_contains($low, 'unauthorized') || str_contains($low, '(401)')) {
            $hint = '';
            if (str_contains($provider, 'ollama')) {
                $hint = ' Comprueba que es una API key de ollama.com/settings/keys (no la Public Key de "ollama signin").';
            }
            return 'La API key de ' . $who . ' es inválida o falta.' . $hint . ' Revísala en Admin → APIs.';
        }
        if (str_contains($low, 'free tier can only be used from within opencode')) {
            return 'Los modelos gratis de OpenCode solo funcionan dentro de la app OpenCode; no se pueden usar desde aquí. Usa otro proveedor.';
        }
        if (str_contains($low, 'rate limit') || str_contains($low, 'too many requests') || str_contains($low, '(429)')) {
            return 'Límite de peticiones o cuota agotada (429) en ' . $who . '. Inténtalo más tarde.';
        }
        if (str_contains($low, 'forbidden') || str_contains($low, '(403)')) {
            return 'Acceso denegado (403) por ' . $who . '. Revisa la API key, los permisos o la Base URL.';
        }
        return $msg;
    }

    /**
     * Mensaje accionable para el «fin de contexto»: el prompt no cabe en la
     * ventana del modelo. Se aprovechan los contadores que manda el servidor
     * (llama.cpp) y, si no vienen, se consulta /props una vez.
     */
    private function contextOverflowMessage(string $msg, array $cfg): string
    {
        $nums = llm_err_context_numbers($msg);
        $prompt = (int)($nums['prompt'] ?? 0);
        $ctx = (int)($nums['ctx'] ?? 0);
        if ($ctx === 0) {
            $ctx = $this->serverContext($cfg);
        }

        $detail = '';
        if ($prompt > 0 && $ctx > 0) {
            $detail = ' (' . number_format($prompt, 0, ',', '.') . ' tokens pedidos > '
                . number_format($ctx, 0, ',', '.') . ' de ventana)';
        } elseif ($ctx > 0) {
            $detail = ' (la ventana del servidor es de ' . number_format($ctx, 0, ',', '.') . ' tokens)';
        } elseif ($prompt > 0) {
            $detail = ' (' . number_format($prompt, 0, ',', '.') . ' tokens pedidos)';
        }

        return 'Fin de contexto: el prompt no cabe en la ventana del modelo' . $detail . '. '
             . 'Sube el contexto del servidor (--ctx-size en llama.cpp, num_ctx/OLLAMA_CONTEXT_LENGTH en Ollama) '
             . 'o reduce los datos del informe.';
    }

    /**
     * Ventana de contexto del servidor, leída de `GET /props` (llama.cpp).
     * 0 si el servidor no la expone. Se cachea por host en la petición.
     */
    private function serverContext(array $cfg): int
    {
        // Los proveedores cloud no publican /props: no se les molesta.
        $provider = (string)($cfg['provider'] ?? '');
        if (in_array($provider, ['openai', 'anthropic', 'azure', 'gemini', 'mistral', 'ollama_cloud'], true)) {
            return 0;
        }

        $host = $this->providerHost($cfg);
        if ($host === '') {
            return 0;
        }
        static $cache = [];
        if (array_key_exists($host, $cache)) {
            return $cache[$host];
        }

        $ctx = 0;
        $base = llm_ollama_base($host);
        foreach (array_unique([rtrim($host, '/'), $base]) as $candidate) {
            if ($candidate === '') {
                continue;
            }
            try {
                $res = $this->httpGet($candidate . '/props', (string)($cfg['api_key'] ?? ''), 5);
            } catch (Throwable $e) {
                continue;
            }
            $ctx = llm_props_ctx($res);
            if ($ctx > 0) {
                break;
            }
        }

        return $cache[$host] = $ctx;
    }

    /**
     * Ventana de contexto efectiva del perfil: la declarada o, si es 0, la
     * que publique el servidor en /props (llama.cpp).
     */
    private function windowTokens(array $cfg): int
    {
        $declared = (int)($cfg['context_tokens'] ?? 0);
        if ($declared > 0) {
            return $declared;
        }
        return $this->serverContext($cfg);
    }

    /**
     * Aplica el presupuesto de contexto a las partes de un prompt.
     *
     * @param array<string,array{text:string,priority?:int,min?:int}> $parts
     * @return array{text:string,max_tokens:int,note:string,fits:bool,tokens:int}
     */
    private function budgetContext(array $cfg, array $parts, int $taskMaxTokens): array
    {
        $maxTokens = llm_effective_max_tokens($taskMaxTokens, $cfg);
        $fit = llm_fit_parts($parts, $maxTokens, $this->windowTokens($cfg));
        return [
            'text'       => implode("\n\n", array_filter($fit['parts'], static fn($v) => $v !== '')),
            'max_tokens' => $maxTokens,
            'note'       => (string)$fit['note'],
            'fits'       => (bool)$fit['fits'],
            'tokens'     => (int)$fit['tokens'],
        ];
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
            'openai', 'custom', 'gemini', 'mistral'
                        => $this->callOpenAI($cfg, $system, $user, $options),
            'anthropic' => $this->callAnthropic($cfg, $system, $user, $options),
            'ollama', 'ollama_cloud'
                        => $this->callOllama($cfg, $system, $user, $options),
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
        if ($cfg['provider'] !== '' && !$this->keyOptional($cfg) && empty($cfg['api_key'])) {
            return ['success' => false, 'error' => 'Falta la API key'];
        }
        try {
            $res = $this->dispatch($cfg, 'Eres un asistente.', 'ping', ['max_tokens' => 5]);
            if (!empty($res['success'])) {
                return ['success' => true, 'message' => 'Conexión correcta con ' . $cfg['provider'] . ' (' . ($res['model'] ?? $cfg['model']) . ')'];
            }
            return $res;
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $this->friendlyError($e->getMessage(), $cfg)];
        }
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
            default    => ['https://api.openai.com/v1/chat/completions', 'gpt-4o-mini'],
        };
        $apiUrl = trim((string)($cfg['api_url'] ?? ''));
        $base = $apiUrl !== '' ? $apiUrl : $defaultUrl;
        $urls = llm_openai_endpoints($base) ?: [$defaultUrl];
        $model = trim((string)($cfg['model'] ?? ''));

        // Sin modelo configurado en un servidor propio: se pregunta cuál sirve.
        if ($model === '' && $apiUrl !== '') {
            $model = $this->firstModel($cfg, $base);
        }
        if ($model === '') {
            $model = $defaultModel;
        }

        $lastError = null;
        $modelError = null;
        $modelRetried = false;
        foreach ($urls as $url) {
            try {
                return $this->openaiChat($url, $cfg, $model, $system, $user, $options);
            } catch (Throwable $e) {
                $lastError = $e;
                if (llm_err_is_model_error($e->getMessage())) {
                    $modelError = $modelError ?? $e;
                }

                // El servidor existe pero el modelo pedido no es el cargado:
                // se resuelve por /v1/models y se reintenta una sola vez.
                if (!$modelRetried && llm_err_is_model_error($e->getMessage())) {
                    $modelRetried = true;
                    $found = $this->firstModel($cfg, $base);
                    if ($found !== '' && $found !== $model) {
                        $model = $found;
                        try {
                            return $this->openaiChat($url, $cfg, $model, $system, $user, $options);
                        } catch (Throwable $e2) {
                            $lastError = $e2;
                        }
                    }
                }

                // Solo se prueban rutas alternativas ante un 404: un 401, un 429
                // o un timeout no mejoran cambiando de ruta.
                if (!llm_err_is_not_found($lastError->getMessage())) {
                    throw $lastError;
                }
            }
        }

        // Si lo que falló fue el modelo, ese error es más útil que el 404 de la
        // última ruta probada (p. ej. «Model not found» frente a «File Not Found»).
        throw $modelError ?? $lastError ?? new RuntimeException('Error en la llamada al modelo');
    }

    /**
     * POST /chat/completions y extracción del texto (formato OpenAI).
     * La URL se recibe ya resuelta por llm_openai_endpoints().
     */
    private function openaiChat(string $url, array $cfg, string $model, string $system, string $user, array $options): array
    {
        $body = json_encode([
            'model'       => $model,
            'messages'    => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user',   'content' => $user],
            ],
            'max_tokens'  => llm_effective_max_tokens((int)($options['max_tokens'] ?? $cfg['max_tokens']), $cfg),
            'temperature' => (float)($options['temperature'] ?? 0.3),
            'stream'      => false,
        ]);

        $headers = ['Content-Type: application/json'];
        $key = trim((string)($cfg['api_key'] ?? ''));
        if ($key !== '') {
            $headers[] = 'Authorization: Bearer ' . $key;
        }

        $response = $this->httpPost($url, (string)$body, $headers, (int)($options['timeout'] ?? ($cfg['timeout'] ?? 120)));
        $content = $response['choices'][0]['message']['content'] ?? null;
        if ($content === null) {
            throw new RuntimeException('Respuesta vacía del modelo (' . $url . ')');
        }

        return ['success' => true, 'content' => $content, 'model' => $model];
    }

    private function callAnthropic(array $cfg, string $system, string $user, array $options): array
    {
        $url = $cfg['api_url'] ?: 'https://api.anthropic.com/v1/messages';
        $model = $cfg['model'] ?: 'claude-3-5-sonnet-20241022';

        $body = json_encode([
            'model'       => $model,
            'max_tokens'  => llm_effective_max_tokens((int)($options['max_tokens'] ?? $cfg['max_tokens']), $cfg),
            'system'      => $system,
            'messages'    => [
                ['role' => 'user', 'content' => $user],
            ],
        ]);

        $response = $this->httpPost($url, $body, [
            'x-api-key: ' . $cfg['api_key'],
            'anthropic-version: 2023-06-01',
            'Content-Type: application/json',
        ], (int)($options['timeout'] ?? ($cfg['timeout'] ?? 120)));

        $content = $response['content'][0]['text'] ?? null;
        if ($content === null) {
            return ['success' => false, 'error' => 'Respuesta vacía del modelo', 'raw' => $response];
        }

        return ['success' => true, 'content' => $content, 'model' => $model];
    }

    /**
     * Host efectivo del proveedor: su Base URL o el host por defecto.
     */
    private function providerHost(array $cfg): string
    {
        $url = trim((string)($cfg['api_url'] ?? ''));
        if ($url !== '') {
            return $url;
        }
        return match ((string)($cfg['provider'] ?? '')) {
            'ollama'       => 'http://localhost:11434',
            'ollama_cloud' => 'https://ollama.com',
            'openai'       => 'https://api.openai.com',
            'mistral'      => 'https://api.mistral.ai',
            'gemini'       => 'https://generativelanguage.googleapis.com/v1beta/openai',
            default        => '',
        };
    }

    /**
     * Primer modelo que publica el servidor ('' si no se puede averiguar).
     * Prueba /v1/models (OpenAI) y /api/tags (Ollama nativo).
     */
    private function firstModel(array $cfg, string $url): string
    {
        $key = trim((string)($cfg['api_key'] ?? ''));
        foreach (llm_model_endpoints($url) as $endpoint) {
            try {
                $models = llm_models_from_response($this->httpGet($endpoint, $key));
            } catch (Throwable $e) {
                continue;
            }
            if ($models) {
                return $models[0];
            }
        }
        return '';
    }

    /**
     * Comprueba la conexión listando modelos. Vale igual para un servidor
     * compatible con OpenAI (/v1/models) y para Ollama nativo (/api/tags).
     */
    public function verifyOllama(array $cfg = []): array
    {
        $cfg = array_merge($this->cfg(), $cfg);
        $provider = (string)($cfg['provider'] ?? '');
        if ($provider === '') {
            return ['success' => false, 'error' => 'Falta seleccionar un proveedor.'];
        }
        if (in_array($provider, ['anthropic', 'azure'], true)) {
            return ['success' => false, 'error' => 'La verificación automática solo aplica a proveedores con listado de modelos (OpenAI-compatible y Ollama). Usa «Probar conexión».'];
        }

        $host = $this->providerHost($cfg);
        if ($host === '') {
            return ['success' => false, 'error' => 'Falta la Base URL del proveedor.'];
        }

        $errors = [];
        $key = trim((string)($cfg['api_key'] ?? ''));
        foreach (llm_model_endpoints($host) as $url) {
            try {
                $res = $this->httpGet($url, $key);
            } catch (Throwable $e) {
                $errors[] = $this->friendlyError($e->getMessage(), $cfg);
                continue;
            }
            $models = llm_models_from_response($res);
            if ($models) {
                $kind = str_contains($url, '/api/tags') ? 'API nativa de Ollama' : 'API compatible con OpenAI';
                $context = $this->serverContext($cfg);
                return [
                    'success'  => true,
                    'message'  => 'Conexión correcta. Endpoint detectado: ' . $url . ' (' . $kind . '). Modelos disponibles: ' . count($models) . '.'
                        . ($context > 0 ? ' Ventana de contexto: ' . number_format($context, 0, ',', '.') . ' tokens.' : ''),
                    'models'   => count($models),
                    'endpoint' => $url,
                    'context'  => $context,
                ];
            }
            $errors[] = 'El endpoint ' . $url . ' respondió sin modelos.';
        }

        return ['success' => false, 'error' => 'No se pudo verificar: ' . implode(' | ', array_unique($errors))];
    }

    /**
     * Lista los modelos del servidor configurado (para rellenar el campo
     * Modelo con el identificador exacto que sirve, sin hardcodear).
     */
    public function listModels(array $cfg = []): array
    {
        $cfg = array_merge($this->cfg(), $cfg);
        $provider = (string)($cfg['provider'] ?? '');
        if ($provider === '') {
            return ['success' => false, 'error' => 'Falta seleccionar un proveedor.'];
        }
        if ($provider === 'azure') {
            return ['success' => false, 'error' => 'Azure OpenAI no lista modelos: en este proveedor el campo Modelo es el nombre del deployment.'];
        }

        $host = $this->providerHost($cfg);
        if ($host === '') {
            return ['success' => false, 'error' => 'Falta la Base URL del proveedor.'];
        }

        $errors = [];
        $key = trim((string)($cfg['api_key'] ?? ''));
        foreach (llm_model_endpoints($host) as $url) {
            try {
                $res = $this->httpGet($url, $key);
            } catch (Throwable $e) {
                $errors[] = $url . ' → ' . $this->friendlyError($e->getMessage(), $cfg);
                continue;
            }
            $models = llm_models_from_response($res);
            if ($models) {
                return [
                    'success'   => true,
                    'models'    => $models,
                    'endpoint'  => $url,
                    'suggested' => $models[0],
                    'context'   => $this->serverContext($cfg),
                ];
            }
            $errors[] = $url . ' → respuesta sin modelos';
        }

        return ['success' => false, 'error' => 'No se pudo listar modelos. ' . implode(' | ', $errors)];
    }

    private function callOllama(array $cfg, string $system, string $user, array $options): array
    {
        // Ollama local (sin API key) u Ollama Cloud (API oficial, con API key)
        $isCloud = ($cfg['provider'] ?? '') === 'ollama_cloud';
        $host = (string)($cfg['api_url'] ?: ($isCloud ? 'https://ollama.com' : 'http://localhost:11434'));
        $root = llm_ollama_base($host);
        $url = ($root !== '' ? $root : rtrim($host, '/')) . '/api/chat';
        $model = trim((string)($cfg['model'] ?? ''));

        try {
            return $this->ollamaChat($url, $cfg, $model !== '' ? $model : ($isCloud ? 'gpt-oss:120b' : 'llama3.1'), $system, $user, $options);
        } catch (Throwable $e) {
            $msg = $e->getMessage();

            // Modelo nativo inexistente: se resuelve por /api/tags y se reintenta.
            if (llm_err_is_model_error($msg)) {
                $found = $this->firstModel($cfg, $host);
                if ($found !== '' && $found !== $model) {
                    return $this->ollamaChat($url, $cfg, $found, $system, $user, $options);
                }
                throw $e;
            }

            // Sin API nativa de Ollama (llama.cpp, vLLM, LM Studio, la Orin…):
            // se reintenta con el transporte compatible con OpenAI.
            if (!llm_err_is_not_found($msg)) {
                throw $e;
            }

            $fallback = $cfg;
            $fallback['api_url'] = $host;
            // El modelo por defecto del transporte nativo no sirve aquí: sin
            // modelo configurado se pregunta al servidor por el cargado.
            if ($model === '') {
                $fallback['model'] = '';
            }
            try {
                return $this->callOpenAI($fallback, $system, $user, $options);
            } catch (Throwable $e2) {
                throw new RuntimeException(
                    'El servidor no responde a la API nativa de Ollama (/api/chat) ni a la compatible con OpenAI (/v1/chat/completions): '
                    . $e2->getMessage()
                );
            }
        }
    }

    /**
     * POST /api/chat y extracción del texto (formato nativo de Ollama).
     */
    private function ollamaChat(string $url, array $cfg, string $model, string $system, string $user, array $options): array
    {
        $body = json_encode([
            'model'    => $model,
            'messages' => [
                ['role' => 'system', 'content' => $system],
                ['role' => 'user',   'content' => $user],
            ],
            'stream'   => false,
            'options'  => [
                'num_predict' => llm_effective_max_tokens((int)($options['max_tokens'] ?? $cfg['max_tokens']), $cfg),
            ],
        ]);

        $headers = ['Content-Type: application/json'];
        $key = trim((string)($cfg['api_key'] ?? ''));
        if ($key !== '') {
            $headers[] = 'Authorization: Bearer ' . $key;
        }

        $response = $this->httpPost($url, (string)$body, $headers, (int)($options['timeout'] ?? ($cfg['timeout'] ?? 120)));

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
            'max_tokens'  => llm_effective_max_tokens((int)($options['max_tokens'] ?? $cfg['max_tokens']), $cfg),
            'temperature' => $options['temperature'] ?? 0.3,
        ]);

        $response = $this->httpPost($url, $body, [
            'api-key: ' . $cfg['api_key'],
            'Content-Type: application/json',
        ], (int)($options['timeout'] ?? ($cfg['timeout'] ?? 120)));

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

        $alerts = Database::fetchAll(
            "SELECT * FROM alerts WHERE incident_id = ? ORDER BY COALESCE(first_activity, last_activity) ASC LIMIT 25",
            [$incidentId]
        );
        $tenant = TenantManager::getById((int)$incident['tenant_id']);

        $alertLines = [];
        $evidenceLines = [];
        foreach ($alerts as $a) {
            $mitre = safe_json_decode((string)$a['mitre_techniques'], []);
            $alertLines[] = '- «' . $a['title'] . '»'
                . (!empty($a['threat_display_name']) ? ' · amenaza: ' . $a['threat_display_name'] : '')
                . (!empty($a['threat_family_name']) ? ' (' . $a['threat_family_name'] . ')' : '')
                . (!empty($a['category']) ? ' · categoría: ' . $a['category'] : '')
                . ' · severidad: ' . ($a['severity'] ?: '?')
                . (!empty($a['service_source']) ? ' · servicio: ' . $a['service_source'] : '')
                . (!empty($a['detection_source']) ? ' · detección: ' . $a['detection_source'] : '')
                . (is_array($mitre) && $mitre ? ' · MITRE: ' . implode(', ', array_map('strval', $mitre)) : '')
                . (!empty($a['first_activity']) ? ' · primera: ' . $a['first_activity'] : '')
                . (!empty($a['last_activity']) ? ' · última: ' . $a['last_activity'] : '');

            $raw = safe_json_decode((string)$a['raw_data'], []);
            $ev = (is_array($raw) && isset($raw['evidence']) && is_array($raw['evidence'])) ? $raw['evidence'] : [];
            foreach ($ev as $e) {
                if (!is_array($e)) { continue; }
                $lab = $e['ipAddress'] ?? $e['url'] ?? ($e['userAccount']['accountName'] ?? null)
                    ?? $e['deviceDnsName'] ?? ($e['fileDetails']['fileName'] ?? null)
                    ?? ($e['process']['filePath'] ?? null) ?? $e['processCommandLine'] ?? null;
                if (!empty($lab)) { $evidenceLines[] = '- ' . $lab; }
            }
        }

        $ctx = "INCIDENTE: {$incident['display_name']}\n"
            . 'Tenant: ' . ($tenant['name'] ?? '') . "\n"
            . 'Severidad: ' . ($incident['severity'] ?: '—') . "\n"
            . 'Estado: ' . ($incident['status'] ?: '—') . "\n"
            . 'Clasificación: ' . ($incident['classification'] ?: '—') . "\n"
            . 'Determinación: ' . ($incident['determination'] ?: '—') . "\n"
            . 'Asignado a: ' . ($incident['assigned_to'] ?: '—') . "\n"
            . 'Creado: ' . ($incident['created_date'] ?: '—') . ' · Actualizado: ' . ($incident['last_update_date'] ?: '—') . "\n\n"
            . 'ALERTAS (' . count($alerts) . "):\n" . ($alertLines ? implode("\n", $alertLines) : '- (sin alertas)') . "\n";

        if ($evidenceLines) {
            $ctx .= "\nEVIDENCIA/ENTIDADES:\n" . implode("\n", array_slice($evidenceLines, 0, 40)) . "\n";
        }
        if (!empty($incident['recommended_actions'])) {
            $ctx .= "\nACCIONES RECOMENDADAS (Microsoft): " . truncate((string)$incident['recommended_actions'], 500) . "\n";
        }

        $system = llm_prompt(
            'llm.analysis.incident.system',
            'Eres un analista de ciberseguridad senior de un SOC. Responde SIEMPRE en español y en Markdown, basándote '
            . 'EXCLUSIVAMENTE en los datos del incidente que se te dan; no inventes.'
        ) . ' ' . llm_prompt(
            'llm.analysis.incident.format',
            'Estructura la respuesta con: '
            . '1) Resumen ejecutivo; 2) Naturaleza y vector (mapea las técnicas MITRE); 3) Impacto potencial; '
            . '4) Indicadores (IoCs) relevantes; 5) Acciones recomendadas priorizadas (3-5). Sé concreto y accionable.'
        );

        $user = $ctx . "\nTAREA: Analiza este incidente y devuelve el informe según la estructura indicada.";

        $maxTokens = llm_effective_max_tokens(2000, $this->cfg($profileId));
        return $this->chat($system, $user, ['max_tokens' => $maxTokens], $profileId);
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

        $system = llm_prompt(
            'llm.ioc.classify.system',
            'Eres un analista de threat intelligence. Clasifica cada IOC en: tipo de amenaza '
            . '(malware, phishing, C2, etc.), nivel de confianza (alta/media/baja) y una breve descripción.'
        ) . ' ' . llm_prompt('llm.ioc.classify.format', 'Responde en formato JSON array.');
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
        $system = llm_prompt(
            'llm.ioc.extract.system',
            'Eres un analista de threat intelligence. A partir del texto (artículo o correo), devuelve EXCLUSIVAMENTE un JSON válido con esta forma: '
            . '{"resumen":"...","iocs":[{"tipo":"ipv4-addr|domain-name|url|file|email-addr|otro","valor":"..."}],"recomendaciones":"..."}. '
            . 'No inventes IOCs; si no hay, deja el array vacío. Responde en español.'
        );
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

        $system = llm_prompt(
            'llm.analysis.report.system',
            'Eres un analista de ciberseguridad que escribe informes ejecutivos. Convierte los datos técnicos en un resumen narrativo profesional en español, destacando los hallazgos más relevantes y el estado general de la seguridad.'
        );
        $user = "Genera un resumen ejecutivo del siguiente reporte ({$report['title']}):\n" . json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

        return $this->chat($system, $user, [], $profileId);
    }

    /**
     * HTTP POST genérico con cURL (con fallback si la extensión no está).
     * Ante un 503 (modelo cargando) reintenta una vez tras un backoff corto.
     */
    private function httpPost(string $url, string $body, array $headers, int $timeout = 120): array
    {
        if (!function_exists('curl_init')) {
            /* Hosting sin cURL: se usa el wrapper HTTP de PHP. */
            $attempt = 0;
            while (true) {
                $attempt++;
                $context = stream_context_create([
                    'http' => [
                        'method'        => 'POST',
                        'header'        => implode("\r\n", $headers),
                        'content'       => $body,
                        'timeout'       => max(10, $timeout),
                        'ignore_errors' => true,
                    ],
                    'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
                ]);
                $response = @file_get_contents($url, false, $context);
                if ($response === false) {
                    $err = error_get_last()['message'] ?? 'error desconocido';
                    throw new RuntimeException('No se pudo conectar con el proveedor (sin cURL): ' . $err);
                }
                $httpCode = 0;
                foreach ($http_response_header ?? [] as $line) {
                    if (preg_match('#^HTTP/\S+\s+(\d{3})#', (string)$line, $m)) {
                        $httpCode = (int)$m[1];
                    }
                }

                // 503 = el modelo se está cargando: un reintento con espera.
                if ($httpCode === 503 && $attempt === 1) {
                    $wait = $this->retryDelay();
                    if ($wait > 0) {
                        sleep($wait);
                    }
                    continue;
                }

                $decoded = json_decode($response, true);
                if ($httpCode >= 400) {
                    throw new RuntimeException($this->httpErrorMessage($httpCode, $response, $decoded));
                }
                return is_array($decoded) ? $decoded : ['raw' => $response];
            }
        }

        $attempt = 0;
        while (true) {
            $attempt++;
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $body,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_TIMEOUT        => max(10, $timeout),
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

            // 503 = el modelo se está cargando: un reintento con espera.
            if ($httpCode === 503 && $attempt === 1) {
                $wait = $this->retryDelay();
                if ($wait > 0) {
                    sleep($wait);
                }
                continue;
            }

            $decoded = json_decode($response, true);
            if ($httpCode >= 400) {
                throw new RuntimeException($this->httpErrorMessage($httpCode, $response, $decoded));
            }

            return $decoded ?? ['raw' => $response];
        }
    }

    /**
     * Espera del reintento ante 503, recortada si no hay margen de ejecución
     * (hosting compartido con max_execution_time bajo).
     */
    private function retryDelay(): int
    {
        $seconds = defined('LLM_503_RETRY_DELAY') ? (int)LLM_503_RETRY_DELAY : 20;
        if ($seconds <= 0) {
            return 0;
        }
        $max = (int)ini_get('max_execution_time');
        if ($max > 0) {
            $left = $max - (time() - (int)($_SERVER['REQUEST_TIME'] ?? time()));
            if ($left <= $seconds + 15) {
                return 0;
            }
        }
        return $seconds;
    }

    /**
     * HTTP GET genérico con cURL (JSON), con API key opcional.
     */
    private function httpGet(string $url, string $apiKey = '', int $timeout = 30): array
    {
        $headers = ['Accept: application/json'];
        if ($apiKey !== '') {
            $headers[] = 'Authorization: Bearer ' . $apiKey;
        }

        if (!function_exists('curl_init')) {
            /* Hosting sin cURL: wrapper HTTP de PHP (mismo criterio que httpPost). */
            $context = stream_context_create([
                'http' => [
                    'method'        => 'GET',
                    'header'        => implode("\r\n", $headers),
                    'timeout'       => max(3, $timeout),
                    'ignore_errors' => true,
                ],
                'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
            ]);
            $response = @file_get_contents($url, false, $context);
            if ($response === false) {
                $err = error_get_last()['message'] ?? 'error desconocido';
                throw new RuntimeException('No se pudo conectar con el proveedor (sin cURL): ' . $err);
            }
            $httpCode = 0;
            foreach ($http_response_header ?? [] as $line) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', (string)$line, $m)) {
                    $httpCode = (int)$m[1];
                }
            }
            $decoded = json_decode($response, true);
            if ($httpCode >= 400) {
                throw new RuntimeException($this->httpErrorMessage($httpCode, $response, $decoded));
            }
            return is_array($decoded) ? $decoded : [];
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => max(3, $timeout),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_HTTPHEADER     => $headers,
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
            throw new RuntimeException($this->httpErrorMessage($httpCode, $response, $decoded));
        }

        return $decoded ?? [];
    }

    /**
     * Mensaje de error HTTP con el detalle del proveedor. Conserva los
     * contadores de contexto que llama.cpp pone fuera de `error.message`
     * (n_prompt_tokens, n_ctx) para poder explicar el fin de contexto.
     */
    private function httpErrorMessage(int $code, string $raw, mixed $decoded): string
    {
        $msg = '';
        $extra = [];

        if (is_array($decoded)) {
            $err = $decoded['error'] ?? null;
            if (is_array($err)) {
                $msg = (string)($err['message'] ?? '');
                if (!empty($err['type']) && is_string($err['type'])) {
                    $extra[] = 'type=' . $err['type'];
                }
                if (!empty($err['code']) && is_string($err['code'])) {
                    $extra[] = 'code=' . $err['code'];
                }
            } elseif (is_string($err)) {
                $msg = $err;
            }
            if ($msg === '' && isset($decoded['message']) && is_string($decoded['message'])) {
                $msg = $decoded['message'];
            }
            foreach (['n_prompt_tokens', 'n_ctx', 'n_predict'] as $field) {
                if (isset($decoded[$field]) && is_numeric($decoded[$field])) {
                    $extra[] = $field . '=' . (int)$decoded[$field];
                }
            }
        }

        if ($msg === '') {
            $msg = trim(strip_tags($raw));
            if (strlen($msg) > 300) {
                $msg = substr($msg, 0, 300) . '…';
            }
        }

        return 'LLM API Error (' . $code . '): ' . $msg
            . ($extra !== [] ? ' [' . implode(', ', array_unique($extra)) . ']' : '');
    }

    // ============================================================
    // Análisis del tenant (usa datos locales)
    // ============================================================

    /** Instrucción usada para la pregunta libre. */
    private function questionInstruction(): string
    {
        return 'Responde a la pregunta del analista usando EXCLUSIVAMENTE los datos del tenant. '
             . 'Cuando se pidan títulos, enlaces, valores o cifras, devuélvelos de forma CONCRETA y completa.';
    }

    /**
     * Analiza los datos locales de un tenant con el LLM.
     */
    public function analyzeTenant(int $tenantId, string $instruction, string $question = '', ?int $profileId = null, bool $detailed = false): array
    {
        $tenant = TenantManager::getById($tenantId);
        if (!$tenant) {
            return ['success' => false, 'error' => 'Tenant no encontrado'];
        }

        $instruction = trim($instruction);
        if ($instruction === '') {
            $instruction = $this->questionInstruction();
        }

        $context = $this->tenantContextText($tenantId, $detailed);

        $system = llm_prompt(
            'llm.analysis.tenant.system',
            'Eres un analista de ciberseguridad senior. Responde SIEMPRE en español y en Markdown. '
            . 'Básate EXCLUSIVAMENTE en los datos del tenant que se te proporcionan; no inventes cifras ni hechos. '
            . 'Si falta información, dilo explícitamente. Sé concreto, prioriza y propón acciones.'
        );

        $budget = $this->budgetContext($this->cfg($profileId), [
            'datos' => ['text' => $context, 'priority' => 1, 'min' => 2000],
        ], 2500);

        $user = "DATOS DEL TENANT «{$tenant['name']}»:\n\n" . $budget['text'] . "\n\nTAREA: {$instruction}";
        if (trim($question) !== '') {
            $user .= "\n\nPREGUNTA DEL ANALISTA: " . trim($question);
        }

        $res = $this->chat($system, $user, ['max_tokens' => $budget['max_tokens']], $profileId);
        if ($budget['note'] !== '') {
            $res['notice'] = $budget['note'];
        }
        if (!empty($res['success'])) {
            $res['tenant'] = $tenant['name'];
        }
        return $res;
    }

    /**
     * Texto con el resumen de los datos locales del tenant (acotado).
     */
    private function tenantContextText(int $tenantId, bool $detailed = false): string
    {
        $artLimit  = $detailed ? 25 : 12;
        $iocLimit  = $detailed ? 60 : 20;
        $incLimit  = $detailed ? 20 : 10;
        $vulnLimit = $detailed ? 25 : 12;
        $base = rtrim(base_url('modules/threat_intelligence/article'), '/');

        $L = [];
        $tenant = TenantManager::getById($tenantId);
        if ($tenant) {
            $extra = [];
            if (!empty($tenant['industry'])) { $extra[] = 'sector: ' . $tenant['industry']; }
            if (!empty($tenant['country']))  { $extra[] = 'país: ' . $tenant['country']; }
            $L[] = 'TENANT: ' . $tenant['name'] . ' (Graph: ' . $tenant['tenant_id'] . ')'
                 . ($extra ? ' · ' . implode(', ', $extra) : '')
                 . ' · última sync: ' . ($tenant['last_sync_at'] ?: 'nunca') . ' (' . ($tenant['last_sync_status'] ?: '—') . ')';
        }
        $L[] = 'NOTA: los enlaces de artículos son internos de la app (' . $base . '/{id}); cada artículo incluye su enlace directo.';

        // Incidentes
        $n = (int)$this->ctxScalar("SELECT COUNT(*) FROM incidents WHERE tenant_id = ?", $tenantId);
        if ($n > 0) {
            $L[] = 'INCIDENTES: ' . $n
                 . ' · severidad: ' . $this->ctxFmt($this->ctxPairs("SELECT severity, COUNT(*) n FROM incidents WHERE tenant_id = ? GROUP BY severity", $tenantId))
                 . ' · estado: ' . $this->ctxFmt($this->ctxPairs("SELECT status, COUNT(*) n FROM incidents WHERE tenant_id = ? GROUP BY status", $tenantId));
            foreach (Database::fetchAll("SELECT display_name, severity, status, classification, created_date FROM incidents WHERE tenant_id = ? ORDER BY COALESCE(created_date,'') DESC LIMIT ?", [$tenantId, $incLimit]) as $r) {
                $L[] = '  - [' . ($r['severity'] ?: '?') . '/' . ($r['status'] ?: '?') . '] ' . $this->ctxClip((string)$r['display_name'], 140) . (!empty($r['classification']) ? ' · clasificación: ' . $r['classification'] : '') . ' (' . ($r['created_date'] ?: '?') . ')';
            }
        } else {
            $L[] = 'INCIDENTES: sin datos sincronizados.';
        }

        // Alertas
        $a = (int)$this->ctxScalar("SELECT COUNT(*) FROM alerts WHERE tenant_id = ?", $tenantId);
        if ($a > 0) {
            $L[] = 'ALERTAS: ' . $a
                 . ' · severidad: ' . $this->ctxFmt($this->ctxPairs("SELECT severity, COUNT(*) n FROM alerts WHERE tenant_id = ? GROUP BY severity", $tenantId));
            $thr = $this->ctxPairs("SELECT threat_display_name, COUNT(*) n FROM alerts WHERE tenant_id = ? AND threat_display_name IS NOT NULL AND threat_display_name <> '' GROUP BY threat_display_name ORDER BY n DESC LIMIT 5", $tenantId);
            if ($thr) { $L[] = '  Amenazas más frecuentes: ' . $this->ctxFmt($thr); }
            $mitre = $this->ctxPairs("SELECT mitre_techniques, COUNT(*) n FROM alerts WHERE tenant_id = ? AND mitre_techniques IS NOT NULL AND mitre_techniques <> '' GROUP BY mitre_techniques ORDER BY n DESC LIMIT 5", $tenantId);
            if ($mitre) { $L[] = '  Técnicas MITRE más frecuentes: ' . $this->ctxFmt($mitre); }
        }

        // Threat Intel (artículos con enlace + sus IOCs)
        $arts = (int)$this->ctxScalar("SELECT COUNT(*) FROM ti_articles WHERE tenant_id = ?", $tenantId);
        $iocs = (int)$this->ctxScalar("SELECT COUNT(*) FROM ti_iocs WHERE tenant_id = ?", $tenantId);
        if ($arts > 0 || $iocs > 0) {
            $L[] = 'THREAT INTEL: artículos=' . $arts . ', IOCs=' . $iocs
                 . ' · tipos de IOC: ' . $this->ctxFmt($this->ctxPairs("SELECT ioc_type, COUNT(*) n FROM ti_iocs WHERE tenant_id = ? GROUP BY ioc_type ORDER BY n DESC", $tenantId));

            $L[] = 'ARTÍCULOS TI (título · fecha · enlace · tags · IOCs):';
            foreach (Database::fetchAll("SELECT id, title, created_date, last_updated, tags, summary FROM ti_articles WHERE tenant_id = ? ORDER BY COALESCE(last_updated, created_date, fetched_at) DESC LIMIT ?", [$tenantId, $artLimit]) as $ar) {
                $artId = (int)$ar['id'];
                $tags = '';
                if (!empty($ar['tags'])) {
                    $t = json_decode((string)$ar['tags'], true);
                    if (is_array($t)) { $tags = implode(', ', array_slice(array_map('strval', $t), 0, 6)); }
                }
                $sum = $this->ctxClip((string)($ar['summary'] ?? ''), 160);
                $artTotal = (int)(Database::fetchOne("SELECT COUNT(*) c FROM ti_iocs WHERE tenant_id = ? AND article_id = ?", [$tenantId, $artId])['c'] ?? 0);
                $samples = [];
                foreach (Database::fetchAll("SELECT ioc_type, ioc_value FROM ti_iocs WHERE tenant_id = ? AND article_id = ? ORDER BY ioc_type LIMIT 6", [$tenantId, $artId]) as $ii) {
                    $samples[] = $ii['ioc_type'] . ':' . $this->ctxClip((string)$ii['ioc_value'], 60);
                }
                $L[] = '  - «' . $this->ctxClip((string)$ar['title'], 160) . '» [' . ($ar['last_updated'] ?: $ar['created_date'] ?: '?') . ']'
                     . ($tags ? ' · tags: ' . $tags : '')
                     . ' · enlace: ' . $base . '/' . $artId
                     . ($sum ? ' · resumen: "' . $sum . '"' : '')
                     . ' · IOCs (' . $artTotal . ')' . ($samples ? ': ' . implode(', ', $samples) : '');
            }

            $L[] = 'IOCs RECIENTES (tipo · valor · severidad · artículo):';
            foreach (Database::fetchAll("SELECT i.ioc_type, i.ioc_value, i.severity, a.title AS article_title FROM ti_iocs i LEFT JOIN ti_articles a ON a.id = i.article_id WHERE i.tenant_id = ? ORDER BY COALESCE(i.last_seen, i.fetched_at) DESC LIMIT ?", [$tenantId, $iocLimit]) as $r) {
                $L[] = '  - [' . $r['ioc_type'] . '] ' . $this->ctxClip((string)$r['ioc_value'], 80)
                     . ($r['severity'] ? ' (' . $r['severity'] . ')' : '')
                     . (!empty($r['article_title']) ? ' — artículo: «' . $this->ctxClip((string)$r['article_title'], 120) . '»' : ' (sin artículo asociado)');
            }
        } else {
            $L[] = 'THREAT INTEL: sin datos sincronizados.';
        }

        // Intel profiles (threat actors / tools)
        $profCount = (int)$this->ctxScalar("SELECT COUNT(*) FROM ti_intel_profiles WHERE tenant_id = ?", $tenantId);
        if ($profCount > 0) {
            $L[] = 'INTEL PROFILES: total=' . $profCount
                 . ' · por tipo: ' . $this->ctxFmt($this->ctxPairs("SELECT kind, COUNT(*) n FROM ti_intel_profiles WHERE tenant_id = ? GROUP BY kind", $tenantId));
            $topProfiles = Database::fetchAll(
                "SELECT title, kind FROM ti_intel_profiles WHERE tenant_id = ? " . ($detailed ? '' : "AND kind = 'actor' ") . "ORDER BY title LIMIT 12",
                [$tenantId]
            );
            foreach ($topProfiles as $t) {
                $L[] = '  - [' . ($t['kind'] ?: '?') . '] ' . $this->ctxClip((string)$t['title'], 120);
            }
        }

        // Vulnerabilidades
        $v = (int)$this->ctxScalar("SELECT COUNT(*) FROM vulnerabilities WHERE tenant_id = ?", $tenantId);
        if ($v > 0) {
            $exp = (int)$this->ctxScalar("SELECT COUNT(*) FROM vulnerabilities WHERE tenant_id = ? AND public_exploit = 1", $tenantId);
            $L[] = 'VULNERABILIDADES: ' . $v
                 . ' · severidad: ' . $this->ctxFmt($this->ctxPairs("SELECT severity, COUNT(*) n FROM vulnerabilities WHERE tenant_id = ? GROUP BY severity", $tenantId))
                 . ' · con exploit público: ' . $exp;
            foreach (Database::fetchAll("SELECT cve_id, product_name, cvss_v3, epss, public_exploit FROM vulnerabilities WHERE tenant_id = ? ORDER BY (cvss_v3 IS NULL), cvss_v3 DESC LIMIT ?", [$tenantId, $vulnLimit]) as $r) {
                $L[] = '  - ' . $r['cve_id'] . ' (' . $this->ctxClip((string)$r['product_name'], 60) . ') cvss=' . ($r['cvss_v3'] ?? '?') . ' epss=' . ($r['epss'] ?? '?') . ($r['public_exploit'] ? ' [EXPLOIT PÚBLICO]' : '');
            }
        }

        // Máquinas
        $m = (int)$this->ctxScalar("SELECT COUNT(*) FROM machines WHERE tenant_id = ?", $tenantId);
        if ($m > 0) {
            $L[] = 'MÁQUINAS: ' . $m
                 . ' · riesgo: ' . $this->ctxFmt($this->ctxPairs("SELECT risk_score, COUNT(*) n FROM machines WHERE tenant_id = ? GROUP BY risk_score", $tenantId))
                 . ' · exposición: ' . $this->ctxFmt($this->ctxPairs("SELECT exposure_level, COUNT(*) n FROM machines WHERE tenant_id = ? GROUP BY exposure_level", $tenantId));
        }

        // Secure Score
        $scores = Database::fetchAll("SELECT score_date, current_score, max_score FROM secure_scores WHERE tenant_id = ? ORDER BY score_date DESC LIMIT 2", [$tenantId]);
        if ($scores) {
            $cur = $scores[0];
            $line = 'SECURE SCORE: ' . $cur['current_score'] . '/' . $cur['max_score'] . ' (' . $cur['score_date'] . ')';
            if (isset($scores[1])) {
                $diff = (float)$cur['current_score'] - (float)$scores[1]['current_score'];
                $line .= ' · anterior ' . $scores[1]['current_score'] . ' (' . ($diff >= 0 ? '+' : '') . round($diff, 2) . ')';
            }
            $L[] = $line;
        }

        // Sync por módulo
        $sync = Database::fetchAll("SELECT module_key, MAX(started_at) AS last_at FROM sync_log WHERE tenant_id = ? GROUP BY module_key ORDER BY module_key", [$tenantId]);
        if ($sync) {
            $parts = [];
            foreach ($sync as $s) { $parts[] = $s['module_key'] . '=' . ($s['last_at'] ?: '?'); }
            $L[] = 'ÚLTIMA SINCRONIZACIÓN por módulo: ' . implode(', ', $parts);
        }

        $text = implode("\n", $L);
        $cap = $detailed ? 60000 : 24000;
        if (strlen($text) > $cap) {
            $text = substr($text, 0, $cap) . "\n[... contexto truncado ...]";
        }
        return $text;
    }

    private function ctxScalar(string $sql, int $tenantId): int
    {
        try {
            $row = Database::fetchOne($sql, [$tenantId]);
            return $row ? (int)array_values($row)[0] : 0;
        } catch (Throwable $e) {
            return 0;
        }
    }

    /** Pares clave=valor de una consulta de 2 columnas (clave, COUNT). */
    private function ctxPairs(string $sql, int $tenantId): array
    {
        try {
            $out = [];
            foreach (Database::fetchAll($sql, [$tenantId]) as $r) {
                $v = array_values($r);
                $k = (string)($v[0] ?? '?');
                if ($k === '' || $k === 'null') { $k = '(vacío)'; }
                $out[$k] = (int)($v[1] ?? 0);
            }
            return $out;
        } catch (Throwable $e) {
            return [];
        }
    }

    private function ctxFmt(array $pairs): string
    {
        if (!$pairs) { return 'sin datos'; }
        $parts = [];
        foreach ($pairs as $k => $n) { $parts[] = $k . '=' . $n; }
        return implode(', ', $parts);
    }

    private function ctxClip(string $s, int $max): string
    {
        $s = trim($s);
        return (strlen($s) > $max) ? (substr($s, 0, $max - 1) . '…') : $s;
    }

    // ============================================================
    // Análisis IA de Intel Profiles e Indicadores (con scope)
    // ============================================================

    public function analyzeProfile(int $id, string $instruction, string $question = '', ?int $llmProfileId = null): array
    {
        $p = Database::fetchOne("SELECT * FROM ti_intel_profiles WHERE id = ?", [$id]);
        if (!$p) { return ['success' => false, 'error' => 'Perfil no encontrado']; }

        $iocs = Database::fetchAll("SELECT ioc_type, ioc_value FROM ti_iocs WHERE profile_id = ? ORDER BY ioc_type LIMIT 150", [$id]);

        $ctx = 'PERFIL (' . ucfirst((string)$p['kind']) . "): {$p['title']}\n";
        $aliases = safe_json_decode((string)($p['aliases'] ?? ''), []);
        if (is_array($aliases) && $aliases) { $ctx .= 'Alias: ' . implode(', ', array_map('strval', array_slice($aliases, 0, 20))) . "\n"; }
        if (!empty($p['first_active'])) { $ctx .= 'Primera actividad: ' . $p['first_active'] . "\n"; }
        if (!empty($p['summary'])) { $ctx .= "\nRESUMEN:\n" . $this->ctxClip((string)$p['summary'], 1500) . "\n"; }
        if (!empty($p['description'])) { $ctx .= "\nDESCRIPCIÓN:\n" . $this->ctxClip((string)$p['description'], 3000) . "\n"; }
        if (!empty($p['tradecraft'])) { $ctx .= "\nTRADECRAFT:\n" . $this->ctxClip((string)$p['tradecraft'], 3000) . "\n"; }
        if ($iocs) {
            $lines = [];
            foreach ($iocs as $i) { $lines[] = '- [' . $i['ioc_type'] . '] ' . $this->ctxClip((string)$i['ioc_value'], 100); }
            $ctx .= "\nINDICADORES (" . count($iocs) . "):\n" . implode("\n", $lines) . "\n";
        }

        $instruction = trim($instruction) ?: 'Analiza este perfil de amenaza y resume lo más relevante.';
        $system = llm_prompt(
            'llm.analysis.profile.system',
            'Eres un analista de threat intelligence senior. Responde SIEMPRE en español y en Markdown, basándote EXCLUSIVAMENTE en los datos del perfil; no inventes. Sé concreto y accionable.'
        );
        $budget = $this->budgetContext($this->cfg($llmProfileId), [
            'perfil' => ['text' => $ctx, 'priority' => 1, 'min' => 1200],
        ], 2000);
        $user = "DATOS DEL PERFIL:\n\n" . $budget['text'] . "\n\nTAREA: {$instruction}";
        if (trim($question) !== '') { $user .= "\n\nPREGUNTA DEL ANALISTA: " . trim($question); }

        $res = $this->chat($system, $user, ['max_tokens' => $budget['max_tokens']], $llmProfileId);
        if ($budget['note'] !== '') { $res['notice'] = $budget['note']; }
        return $res;
    }

    public function analyzeIndicators(int $tenantId, string $instruction, string $question = '', array $filters = [], ?int $llmProfileId = null): array
    {
        $where = ['tenant_id = ?'];
        $params = [$tenantId];
        if (!empty($filters['type'])) { $where[] = 'ioc_type = ?'; $params[] = $filters['type']; }
        if (!empty($filters['search'])) { $where[] = 'ioc_value LIKE ?'; $params[] = '%' . $filters['search'] . '%'; }
        $params[] = 200;
        $iocs = Database::fetchAll("SELECT ioc_type, ioc_value, severity FROM ti_iocs WHERE " . implode(' AND ', $where) . " ORDER BY fetched_at DESC LIMIT ?", $params);

        $lines = [];
        foreach ($iocs as $i) { $lines[] = '- [' . $i['ioc_type'] . '] ' . $this->ctxClip((string)$i['ioc_value'], 120) . (!empty($i['severity']) ? ' (' . $i['severity'] . ')' : ''); }
        $ctx = 'INDICADORES (mostrando ' . count($iocs) . '):' . "\n" . ($lines ? implode("\n", $lines) : '(sin indicadores con esos filtros)');

        $instruction = trim($instruction) ?: 'Analiza estos indicadores y resume lo más relevante.';
        $system = llm_prompt(
            'llm.analysis.indicators.system',
            'Eres un analista de threat intelligence senior. Responde SIEMPRE en español y en Markdown, basándote EXCLUSIVAMENTE en los indicadores proporcionados; no inventes.'
        );
        $budget = $this->budgetContext($this->cfg($llmProfileId), [
            'indicadores' => ['text' => $ctx, 'priority' => 1, 'min' => 800],
        ], 2000);
        $user = "DATOS:\n\n" . $budget['text'] . "\n\nTAREA: {$instruction}";
        if (trim($question) !== '') { $user .= "\n\nPREGUNTA DEL ANALISTA: " . trim($question); }

        $res = $this->chat($system, $user, ['max_tokens' => $budget['max_tokens']], $llmProfileId);
        if ($budget['note'] !== '') { $res['notice'] = $budget['note']; }
        return $res;
    }

    /**
     * Análisis IA de un artículo de Threat Intelligence (ámbito "article").
     * Contexto rico (tags/MITRE, resumen, cuerpo, IOCs y sector del tenant) y
     * salida en Markdown. Con $defang se ofuscan IP/dominio ([.]) en los IOCs.
     */
    public function analyzeArticle(int $id, string $instruction, string $question = '', bool $defang = false, ?int $llmProfileId = null): array
    {
        $a = Database::fetchOne("SELECT * FROM ti_articles WHERE id = ?", [$id]);
        if (!$a) { return ['success' => false, 'error' => 'Artículo no encontrado']; }

        $ctx = 'ARTÍCULO: ' . ($a['title'] ?? '') . "\n";
        $date = $a['last_updated'] ?? $a['created_date'] ?? '';
        if (!empty($date)) { $ctx .= 'Fecha: ' . substr((string)$date, 0, 10) . "\n"; }

        $tags = safe_json_decode((string)($a['tags'] ?? ''), []);
        if (is_array($tags) && $tags) {
            $vals = [];
            foreach ($tags as $t) {
                $v = trim((string)(is_array($t) ? ($t['value'] ?? $t['name'] ?? '') : $t));
                if ($v !== '') { $vals[] = $v; }
            }
            if ($vals) { $ctx .= 'Tags / MITRE: ' . implode(', ', array_slice($vals, 0, 40)) . "\n"; }
        }

        // Contexto de la organización (sector/industria) para prompts de cliente e impacto.
        $tenant = TenantManager::getById((int)$a['tenant_id']);
        if ($tenant) {
            $org = [];
            if (!empty($tenant['name']))     { $org[] = 'organización: ' . $tenant['name']; }
            if (!empty($tenant['industry'])) { $org[] = 'sector/industria: ' . $tenant['industry']; }
            if (!empty($tenant['country']))  { $org[] = 'país: ' . $tenant['country']; }
            if ($org) { $ctx .= 'CONTEXTO DEL CLIENTE (' . implode(' · ', $org) . ")\n"; }
        }

        if (!empty($a['summary'])) { $summaryPart = "RESUMEN:\n" . $this->ctxClip(strip_tags((string)$a['summary']), 3000); }
        if (!empty($a['body']))    { $bodyPart    = "CUERPO:\n" . $this->ctxClip(strip_tags((string)$a['body']), 6000); }

        $iocPart = '';
        $iocs = Database::fetchAll("SELECT ioc_type, ioc_value FROM ti_iocs WHERE article_id = ? ORDER BY ioc_type, ioc_value LIMIT 500", [$id]);
        if ($iocs) {
            $lines = [];
            foreach ($iocs as $i) {
                $val = (string)$i['ioc_value'];
                if ($defang) { $val = defang_ioc($val, (string)$i['ioc_type']); }
                $lines[] = '- [' . $i['ioc_type'] . '] ' . $this->ctxClip($val, 200);
            }
            $iocPart = 'INDICADORES (' . count($iocs) . "):\n" . implode("\n", $lines);
        }

        $instruction = trim($instruction) ?: 'Resume este artículo y destaca lo más relevante para nuestra organización.';
        $system = llm_prompt(
            'llm.analysis.article.system',
            'Eres un analista de threat intelligence senior. Responde SIEMPRE en español y en Markdown. Usa EXCLUSIVAMENTE la información del artículo proporcionado; no inventes datos. Si algo no consta, dilo.'
        );

        // Presupuesto de contexto: el cuerpo se recorta antes que el resumen o
        // los indicadores, y nunca se pierde la cabecera del artículo.
        $budget = $this->budgetContext($this->cfg($llmProfileId), [
            'cuerpo'      => ['text' => $bodyPart ?? '', 'priority' => 1, 'min' => 600],
            'resumen'     => ['text' => $summaryPart ?? '', 'priority' => 2, 'min' => 400],
            'indicadores' => ['text' => $iocPart, 'priority' => 3, 'min' => 300],
            'articulo'    => ['text' => $ctx, 'priority' => 5, 'min' => 200],
        ], 3000);

        $user = "DATOS DEL ARTÍCULO:\n\n" . $budget['text'] . "\n\nTAREA: {$instruction}";
        if ($defang) {
            $user .= "\n\n" . llm_prompt(
                'llm.analysis.article.defang',
                'IMPORTANTE: al listar direcciones IP y dominios, ofusca el ÚLTIMO punto como "[.]" (defanging) para que el texto sea seguro de publicar.'
            );
        }
        if (trim($question) !== '') { $user .= "\n\nPREGUNTA DEL ANALISTA: " . trim($question); }
        $user .= "\n\n" . llm_prompt(
            'llm.analysis.article.limit',
            'LÍMITE DE EXTENSIÓN: responde como máximo con 12 viñetas o 400 palabras (lo que sea menor). '
            . 'Sé directo: no repitas el artículo, no añadas introducciones ni conclusiones. '
            . 'Si la tarea pide una tabla, limita la tabla a las 10 filas más relevantes.'
        );

        $res = $this->chat($system, $user, ['max_tokens' => $budget['max_tokens']], $llmProfileId);
        if ($budget['note'] !== '') {
            $res['notice'] = $budget['note'];
        }
        return $res;
    }

    /**
     * Traduce un artículo de Threat Intelligence al español con IA.
     * Cachea el resultado (Markdown) en ti_article_translations y lo reutiliza
     * mientras el artículo no cambie y la caché tenga menos de 90 días.
     */
    /** Texto fuente (título + resumen + cuerpo) del artículo, sin recortar. */
    private function articleSource(array $a): string
    {
        $parts = [];
        if (!empty($a['title']))   { $parts[] = '# ' . trim((string)$a['title']); }
        if (!empty($a['summary'])) { $parts[] = trim((string)$a['summary']); }
        if (!empty($a['body']))    { $parts[] = trim((string)$a['body']); }
        return trim(implode("\n\n", $parts));
    }

    /** Traducción vigente en caché (artículo sin cambios y < 90 días). */
    private function cachedTranslation(array $a): ?array
    {
        try {
            $cached = Database::fetchOne(
                "SELECT content, source_updated, created_at FROM ti_article_translations WHERE article_id = ? AND lang = 'es'",
                [(int)$a['id']]
            );
        } catch (Throwable $e) {
            return null;
        }
        if (!$cached) {
            return null;
        }
        $fresh  = (string)($cached['source_updated'] ?? '') === (string)($a['last_updated'] ?? '');
        $ts     = strtotime((string)$cached['created_at']);
        $notOld = ($ts !== false) && (time() - $ts) < 90 * 86400;
        if ($fresh && $notOld && trim((string)$cached['content']) !== '') {
            return $cached;
        }
        return null;
    }

    /** Segmentos tipados (prosa/código) de un artículo para traducirlo. */
    private function articleSegments(array $a): array
    {
        $src = $this->articleSource($a);
        return $src !== '' ? llm_split_markdown_segments($src, 1400) : [];
    }

    /**
     * Plan de traducción: segmentos (prosa/código), progreso guardado y si ya
     * está en caché. La UI lo usa para traducir segmento a segmento.
     */
    public function translationPlan(int $id, bool $force = false): array
    {
        $a = Database::fetchOne("SELECT * FROM ti_articles WHERE id = ?", [$id]);
        if (!$a) {
            return ['success' => false, 'error' => 'Artículo no encontrado'];
        }

        $cached = $force ? null : $this->cachedTranslation($a);
        $segments = $this->articleSegments($a);

        // Progreso guardado. Si la segmentación cambió (v0.4.5 guardaba textos
        // planos sin tipo), se descarta para no mezclar contenidos.
        $done = [];
        try {
            $stored = Database::fetchAll(
                "SELECT chunk_index, content, kind FROM ti_article_translation_chunks
                 WHERE article_id = ? ORDER BY chunk_index",
                [$id]
            );
            $stale = false;
            if ($stored !== []) {
                if (count($stored) !== count($segments)) {
                    $stale = true;
                } else {
                    foreach ($stored as $pos => $row) {
                        $rowType = (string)($row['kind'] ?? '');
                        if ($rowType !== '' && $rowType !== (string)($segments[$pos]['type'] ?? '')) {
                            $stale = true;
                            break;
                        }
                    }
                }
            }
            if ($stale) {
                Database::query("DELETE FROM ti_article_translation_chunks WHERE article_id = ?", [$id]);
            } else {
                foreach ($stored as $row) {
                    $done[(int)$row['chunk_index']] = (string)$row['content'];
                }
            }
        } catch (Throwable $e) {
            $done = [];
        }

        $items = [];
        foreach ($segments as $index => $segment) {
            $items[] = [
                'index'   => $index,
                'type'    => (string)$segment['type'],
                'chars'   => llm_str_len((string)$segment['text']),
                'text'    => (string)$segment['text'],
                'done'    => isset($done[$index]),
                'content' => $done[$index] ?? null,
            ];
        }

        return [
            'success'     => true,
            'article_id'  => $id,
            'cached'      => $cached !== null,
            'cached_html' => $cached !== null ? render_ai_markdown((string)$cached['content']) : null,
            'total'       => count($items),
            'chunks'      => $items,
        ];
    }

    /**
     * Traduce un segmento y lo persiste.
     *
     * - `codigo`: no se llama a la IA; se copia literal (el KQL/comandos del
     *   original quedan byte a byte y no se descuadran las vallas).
     * - `prosa`: se traduce; si la respuesta trae vallas que el original no
     *   tenía, se reintenta una vez con la instrucción estricta.
     */
    public function translateArticleChunk(int $id, int $index, string $text, string $type = 'prosa', ?int $profileId = null): array
    {
        $a = Database::fetchOne("SELECT * FROM ti_articles WHERE id = ?", [$id]);
        if (!$a) {
            return ['success' => false, 'error' => 'Artículo no encontrado'];
        }

        $text = trim($text);
        $type = $type === 'codigo' ? 'codigo' : 'prosa';
        if ($index < 0 || $index > 500) {
            return ['success' => false, 'error' => 'Bloque no válido'];
        }
        if ($text === '') {
            return ['success' => false, 'error' => 'El bloque está vacío'];
        }
        if (llm_str_len($text) > 4000) {
            return ['success' => false, 'error' => 'Bloque demasiado grande para traducir'];
        }

        if ($type === 'codigo') {
            // Copia literal: nada de IA.
            $this->storeTranslationChunk($id, $index, $text, 'codigo');
            return [
                'success'      => true,
                'index'        => $index,
                'type'         => 'codigo',
                'content'      => $text,
                'content_html' => '',
                'model'        => 'literal',
            ];
        }

        $cfg = $this->cfg($profileId);
        // La traducción ocupa del orden del original: se reserva ~1,8× y 200
        // tokens de margen, sin pasarse nunca del tope del perfil.
        $maxTokens = llm_effective_max_tokens((int)ceil(llm_estimate_tokens($text) * 1.8) + 200, $cfg);

        $system = llm_prompt(
            'llm.article.translate.system',
            'Eres un traductor profesional especializado en ciberseguridad. Traduce al ESPAÑOL (de España) el fragmento que se te proporciona. Reglas: devuelve SOLO la traducción del fragmento, sin introducciones ni comentarios; NO uses vallas de código (```) ni ```markdown; no incluyas ni traduzcas líneas de código (KQL, comandos): no forman parte del fragmento; conserva el formato Markdown (títulos, listas, tablas) y los acentos graves de las expresiones `código`; NO traduzcas indicadores técnicos ni términos que deban permanecer literales (direcciones IP, dominios, URLs, hashes, nombres de malware/actores, comandos, identificadores CVE/MITRE); no añadas ni omitas información; no resumas. Si el fragmento empieza a mitad de frase, tradúcelo tal cual.'
        );
        $user = "FRAGMENTO A TRADUCIR (Markdown):\n\n{$text}";

        $res = $this->chat($system, $user, ['max_tokens' => $maxTokens], $profileId);
        if (empty($res['success'])) {
            return $res;
        }

        $content = trim((string)($res['content'] ?? ''));
        if ($content === '') {
            return ['success' => false, 'error' => 'La IA devolvió una traducción vacía'];
        }

        // Si el modelo ha añadido vallas que el original no tenía, un reintento
        // con la instrucción más estricta (se guarda lo que devuelva igualmente:
        // el saneado al renderizar lo deja presentable).
        $fenceCount = static fn(string $s): int => substr_count($s, '```') + substr_count($s, '~~~');
        if ($fenceCount($content) > $fenceCount($text)) {
            $retry = $this->chat(
                $system,
                $user . "\n\nIMPORTANTE: NO rodees la respuesta con ``` ni ```markdown. Empieza directamente por el texto traducido.",
                ['max_tokens' => $maxTokens],
                $profileId
            );
            if (!empty($retry['success']) && trim((string)($retry['content'] ?? '')) !== '') {
                $content = trim((string)$retry['content']);
                $res = $retry;
            }
        }

        $this->storeTranslationChunk($id, $index, $content, 'prosa');

        return [
            'success'      => true,
            'index'        => $index,
            'type'         => 'prosa',
            'content'      => $content,
            'content_html' => render_ai_markdown($content),
            'model'        => (string)($res['model'] ?? ''),
        ];
    }

    /** Guarda el contenido de un segmento (crudo) con su tipo. */
    private function storeTranslationChunk(int $reportId, int $index, string $content, string $kind): void
    {
        try {
            Database::query(
                "INSERT INTO ti_article_translation_chunks (article_id, chunk_index, content, status, kind, created_at)
                 VALUES (?, ?, ?, 'done', ?, datetime('now'))
                 ON CONFLICT(article_id, chunk_index) DO UPDATE SET
                    content = excluded.content, status = 'done', kind = excluded.kind,
                    created_at = datetime('now')",
                [$reportId, $index, $content, $kind]
            );
        } catch (Throwable $e) {
            // Si no se puede persistir el bloque, la traducción sigue siendo válida.
        }
    }

    /**
     * Ensambla los bloques traducidos y guarda la traducción final.
     */
    public function saveArticleTranslation(int $id): array
    {
        $a = Database::fetchOne("SELECT * FROM ti_articles WHERE id = ?", [$id]);
        if (!$a) {
            return ['success' => false, 'error' => 'Artículo no encontrado'];
        }

        $chunks = $this->articleSegments($a);
        $total = count($chunks);
        if ($total === 0) {
            return ['success' => false, 'error' => 'El artículo no tiene contenido para traducir'];
        }

        $rows = [];
        try {
            foreach (Database::fetchAll(
                "SELECT chunk_index, content, status FROM ti_article_translation_chunks WHERE article_id = ?",
                [$id]
            ) as $row) {
                $rows[(int)$row['chunk_index']] = $row;
            }
        } catch (Throwable $e) {
            $rows = [];
        }

        $parts = [];
        $failed = 0;
        foreach ($chunks as $index => $segment) {
            $row = $rows[$index] ?? null;
            $type = (string)($segment['type'] ?? 'prosa');
            if ($row !== null && (string)$row['status'] === 'done' && trim((string)$row['content']) !== '') {
                $text = (string)$row['content'];
                // El código se copia literal; la prosa se sanea (vallas de
                // envoltorio, prefijos y separadores `===`).
                $parts[] = $type === 'codigo' ? $text : ai_clean_prose($text);
            } else {
                $parts[] = '[bloque ' . ((int)$index + 1) . ' sin traducir]';
                $failed++;
            }
        }

        $content = implode("\n\n", $parts);

        // Aviso si el código del original no aparece igual en la traducción.
        $originalCodeLines = llm_count_code_lines($this->articleSource($a));
        $translatedCodeLines = llm_count_code_lines($content);
        $notices = [];
        if ($failed > 0) {
            $notices[] = $failed . ' de ' . $total . ' bloques no se pudieron traducir; el resto queda guardado.';
        }
        if ($originalCodeLines > 0 && $translatedCodeLines < $originalCodeLines) {
            $notices[] = 'El código no coincide con el original: ' . $originalCodeLines
                . ' línea(s) de código frente a ' . $translatedCodeLines . ' en la traducción.';
        }
        $notice = implode(' ', $notices);

        try {
            Database::query("DELETE FROM ti_article_translations WHERE created_at < datetime('now', '-90 days')");
            Database::query(
                "INSERT INTO ti_article_translations
                    (article_id, lang, content, source_updated, chunks, failed_chunks, mode, created_at)
                 VALUES (?, 'es', ?, ?, ?, ?, 'chunks', datetime('now'))
                 ON CONFLICT(article_id, lang) DO UPDATE SET
                    content = excluded.content,
                    source_updated = excluded.source_updated,
                    chunks = excluded.chunks,
                    failed_chunks = excluded.failed_chunks,
                    mode = excluded.mode,
                    created_at = datetime('now')",
                [$id, $content, (string)($a['last_updated'] ?? ''), $total, $failed]
            );
        } catch (Throwable $e) {
            return ['success' => false, 'error' => 'No se pudo guardar la traducción: ' . $e->getMessage()];
        }

        return [
            'success'        => true,
            'content'        => $content,
            'content_html'   => render_ai_markdown($content),
            'cached'         => false,
            'chunks'         => $total,
            'failed_chunks'  => $failed,
            'code_lines_original'   => $originalCodeLines,
            'code_lines_translation' => $translatedCodeLines,
            'notice'         => $notice,
        ];
    }

    /**
     * Traducción completa en una sola llamada (compatibilidad con la API y
     * con perfiles rápidos): usa la caché y, si no hay, traduce por bloques.
     */
    public function translateArticle(int $id, ?int $profileId = null): array
    {
        $a = Database::fetchOne("SELECT * FROM ti_articles WHERE id = ?", [$id]);
        if (!$a) { return ['success' => false, 'error' => 'Artículo no encontrado']; }

        $cached = $this->cachedTranslation($a);
        if ($cached !== null) {
            return [
                'success'      => true,
                'content'      => (string)$cached['content'],
                'content_html' => render_ai_markdown((string)$cached['content']),
                'cached'       => true,
            ];
        }

        $chunks = $this->articleSegments($a);
        if ($chunks === []) {
            return ['success' => false, 'error' => 'El artículo no tiene contenido para traducir'];
        }

        $failed = 0;
        foreach ($chunks as $index => $segment) {
            $res = $this->translateArticleChunk(
                $id,
                (int)$index,
                (string)($segment['text'] ?? ''),
                (string)($segment['type'] ?? 'prosa'),
                $profileId
            );
            if (empty($res['success'])) {
                $failed++;
                if ($failed >= 2) {
                    // Dos fallos seguidos: mejor parar que encadenar timeouts.
                    return [
                        'success' => false,
                        'error'   => (string)($res['error'] ?? 'No se pudo traducir el artículo'),
                    ];
                }
            }
        }

        return $this->saveArticleTranslation($id);
    }

    public function translateArticleEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        json_response($this->translateArticle(
            (int)($params['id'] ?? 0),
            $this->resolveProfile($input, 'translate_article')
        ));
    }

    public function translatePlanEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        json_response($this->translationPlan((int)($params['id'] ?? 0), !empty($input['force'])));
    }

    public function translateChunkEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        json_response($this->translateArticleChunk(
            (int)($params['id'] ?? 0),
            (int)($input['index'] ?? -1),
            (string)($input['text'] ?? ''),
            (string)($input['type'] ?? 'prosa'),
            $this->resolveProfile($input, 'translate_article')
        ));
    }

    public function translateSaveEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        json_response($this->saveArticleTranslation((int)($params['id'] ?? 0)));
    }

    public function analyzeProfileEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $instruction = '';
        $actionId = (int)($input['action_id'] ?? 0);
        if ($actionId > 0) { $a = llm_action_get($actionId); if ($a) { $instruction = (string)$a['prompt']; } }
        json_response($this->analyzeProfile(
            (int)($params['id'] ?? 0),
            $instruction,
            (string)($input['question'] ?? ''),
            $this->resolveProfile($input, 'analyze_tenant')
        ));
    }

    public function analyzeIndicatorsEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $instruction = '';
        $actionId = (int)($input['action_id'] ?? 0);
        if ($actionId > 0) { $a = llm_action_get($actionId); if ($a) { $instruction = (string)$a['prompt']; } }
        json_response($this->analyzeIndicators(
            (int)($input['tenant_id'] ?? 0),
            $instruction,
            (string)($input['question'] ?? ''),
            ['type' => (string)($input['type'] ?? ''), 'search' => (string)($input['search'] ?? '')],
            $this->resolveProfile($input, 'analyze_tenant')
        ));
    }

    public function analyzeArticleEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $instruction = '';
        $actionId = (int)($input['action_id'] ?? 0);
        if ($actionId > 0) { $a = llm_action_get($actionId); if ($a) { $instruction = (string)$a['prompt']; } }
        json_response($this->analyzeArticle(
            (int)($params['id'] ?? 0),
            $instruction,
            (string)($input['question'] ?? ''),
            !empty($input['defang']),
            $this->resolveProfile($input, 'analyze_article')
        ));
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                        'handler' => [$this, 'index']],
            ['method' => 'POST', 'pattern' => 'chat',                    'handler' => [$this, 'chatEndpoint']],
            ['method' => 'POST', 'pattern' => 'analyze-tenant',          'handler' => [$this, 'analyzeTenantEndpoint']],
            ['method' => 'POST', 'pattern' => 'analyze-profile/{id}',    'handler' => [$this, 'analyzeProfileEndpoint']],
            ['method' => 'POST', 'pattern' => 'analyze-indicators',      'handler' => [$this, 'analyzeIndicatorsEndpoint']],
            ['method' => 'POST', 'pattern' => 'analyze-article/{id}',    'handler' => [$this, 'analyzeArticleEndpoint']],
            ['method' => 'POST', 'pattern' => 'translate-article/{id}',  'handler' => [$this, 'translateArticleEndpoint']],
            ['method' => 'POST', 'pattern' => 'translate-article-plan/{id}',  'handler' => [$this, 'translatePlanEndpoint']],
            ['method' => 'POST', 'pattern' => 'translate-article-chunk/{id}', 'handler' => [$this, 'translateChunkEndpoint']],
            ['method' => 'POST', 'pattern' => 'translate-article-save/{id}',  'handler' => [$this, 'translateSaveEndpoint']],
            ['method' => 'POST', 'pattern' => 'actions/save',            'handler' => [$this, 'actionsSaveEndpoint']],
            ['method' => 'POST', 'pattern' => 'actions/delete',          'handler' => [$this, 'actionsDeleteEndpoint']],
            ['method' => 'POST', 'pattern' => 'actions/restore',         'handler' => [$this, 'actionsRestoreEndpoint']],
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
            'actions' => llm_actions_list(true),
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

    public function analyzeTenantEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

        $instruction = '';
        $actionId = (int)($input['action_id'] ?? 0);
        if ($actionId > 0) {
            $action = llm_action_get($actionId);
            if ($action) { $instruction = (string)$action['prompt']; }
        }

        json_response($this->analyzeTenant(
            (int)($input['tenant_id'] ?? 0),
            $instruction,
            (string)($input['question'] ?? ''),
            $this->resolveProfile($input, 'analyze_tenant'),
            !empty($input['detailed'])
        ));
    }

    /**
     * Guarda (crea o edita) una acción rápida de Análisis IA (solo admin).
     */
    public function actionsSaveEndpoint(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

        $prompt = trim((string)($input['prompt'] ?? ''));
        if ($prompt === '') {
            json_response(['success' => false, 'error' => 'El prompt de la acción no puede estar vacío.'], 400);
        }

        $id = llm_action_save([
            'label'     => trim((string)($input['label'] ?? '')),
            'prompt'    => $prompt,
            'position'  => (int)($input['position'] ?? 0),
            'is_active' => $input['is_active'] ?? '',
            'scope'     => trim((string)($input['scope'] ?? '')) ?: 'tenant',
        ], ((int)($input['id'] ?? 0)) ?: null);

        log_activity('llm.action_saved', ['action_id' => $id]);
        json_response(['success' => true, 'id' => $id]);
    }

    /**
     * Elimina una acción rápida de Análisis IA (solo admin).
     */
    public function actionsDeleteEndpoint(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $id = (int)($input['id'] ?? 0);
        if ($id > 0) {
            llm_action_delete($id);
        }
        json_response(['success' => true]);
    }

    /**
     * Restaura las acciones rápidas por defecto (solo admin).
     */
    public function actionsRestoreEndpoint(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $scope = trim((string)($input['scope'] ?? '')) ?: 'tenant';
        Database::resetDefaultActions($scope);
        json_response(['success' => true]);
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
