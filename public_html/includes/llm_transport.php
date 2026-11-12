<?php
/**
 * Normalización de endpoints y errores del transporte LLM.
 *
 * Un mismo servidor puede exponer la API nativa de Ollama (/api/chat) o la
 * compatible con OpenAI (/v1/chat/completions): llama.cpp (llama-server),
 * vLLM, LM Studio, LiteLLM, Ollama ≥ 0.1.24, etc. Aquí se resuelven las rutas
 * a partir de la Base URL que escribe el usuario, sin duplicar prefijos y
 * admitiendo tanto la raíz como un endpoint completo.
 *
 * Funciones puras (sin red ni estado) para poder probarlas desde los smoke
 * tests y para que el módulo LLM no acumule reglas de URL.
 */

declare(strict_types=1);

if (!function_exists('llm_openai_base')) {
    /**
     * Reduce una URL a su base (sin el endpoint de chat).
     * https://host/v1/chat/completions -> https://host/v1
     */
    function llm_openai_base(string $url): string
    {
        $u = rtrim(trim($url), '/');
        if ($u === '') {
            return '';
        }
        $u = preg_replace('#/chat/completions$#i', '', $u) ?? $u;
        return rtrim($u, '/');
    }
}

if (!function_exists('llm_is_versioned_base')) {
    /** ¿La URL ya acaba en un prefijo versionado (/v1, /v1beta/openai, /api/v1)? */
    function llm_is_versioned_base(string $url): bool
    {
        return (bool)preg_match('#/v\d+[a-z0-9]*(?:/openai)?$#i', rtrim($url, '/'));
    }
}

if (!function_exists('llm_openai_endpoints')) {
    /**
     * Endpoints de chat compatibles con OpenAI, en orden de preferencia.
     *
     * - Si la URL ya es un endpoint (/chat/completions) se respeta tal cual.
     * - Si acaba en un prefijo versionado (/v1, /v1beta/openai, /api/v1) se
     *   añade solo /chat/completions.
     * - Si es una raíz se prueba /v1/chat/completions y, como respaldo,
     *   /chat/completions.
     *
     * @return string[]
     */
    function llm_openai_endpoints(string $url): array
    {
        $raw = rtrim(trim($url), '/');
        if ($raw === '') {
            return [];
        }
        if (preg_match('#/chat/completions$#i', $raw)) {
            return [$raw];
        }

        $out = [];
        if (llm_is_versioned_base($raw)) {
            $out[] = $raw . '/chat/completions';
        } else {
            $out[] = $raw . '/v1/chat/completions';
            $out[] = $raw . '/chat/completions';
        }
        return array_values(array_unique($out));
    }
}

if (!function_exists('llm_ollama_base')) {
    /**
     * Normaliza el host de Ollama: admite solo el host o una URL con
     * /api/chat, /api/tags, /api, /v1/chat/completions o /v1 de más
     * (no duplica rutas).
     */
    function llm_ollama_base(string $host): string
    {
        $base = rtrim(trim($host), '/');
        $changed = true;
        while ($changed && $base !== '') {
            $changed = false;
            foreach (['/api/chat', '/v1/chat/completions', '/api/tags', '/api', '/v1'] as $suffix) {
                if (str_ends_with($base, $suffix)) {
                    $base = rtrim(substr($base, 0, -strlen($suffix)), '/');
                    $changed = true;
                    break;
                }
            }
        }
        return $base;
    }
}

if (!function_exists('llm_model_endpoints')) {
    /**
     * Endpoints para listar modelos, en orden de preferencia:
     * /v1/models (OpenAI) -> /models -> /api/tags (Ollama nativo).
     *
     * @return string[]
     */
    function llm_model_endpoints(string $url): array
    {
        $raw = rtrim(trim($url), '/');
        if ($raw === '') {
            return [];
        }
        // Si llega un endpoint de chat, se reduce a la base.
        $raw = preg_replace('#/(?:chat/)?completions$#i', '', $raw) ?? $raw;
        $raw = rtrim($raw, '/');

        $out = [];
        if (llm_is_versioned_base($raw)) {
            $out[] = $raw . '/models';
        } else {
            $out[] = $raw . '/v1/models';
            $out[] = $raw . '/models';
        }
        $native = llm_ollama_base($raw);
        if ($native !== '') {
            $out[] = $native . '/api/tags';
        }
        return array_values(array_unique($out));
    }
}

if (!function_exists('llm_models_from_response')) {
    /**
     * Extrae los identificadores de modelo de una respuesta de listado:
     * OpenAI (`data[].id`) u Ollama nativo (`models[].name`).
     *
     * @return string[]
     */
    function llm_models_from_response(array $res): array
    {
        $ids = [];

        if (isset($res['data']) && is_array($res['data'])) {
            foreach ($res['data'] as $row) {
                if (is_array($row) && isset($row['id']) && is_string($row['id']) && trim($row['id']) !== '') {
                    $ids[] = trim($row['id']);
                }
            }
        }

        if (isset($res['models']) && is_array($res['models'])) {
            foreach ($res['models'] as $row) {
                $id = '';
                if (is_array($row)) {
                    $id = (string)($row['name'] ?? $row['model'] ?? $row['id'] ?? '');
                } elseif (is_string($row)) {
                    $id = $row;
                }
                $id = trim($id);
                if ($id !== '') {
                    $ids[] = $id;
                }
            }
        }

        return array_values(array_unique($ids));
    }
}

if (!function_exists('llm_err_is_not_found')) {
    /** ¿El error es un 404 (ruta o modelo inexistente)? */
    function llm_err_is_not_found(string $msg): bool
    {
        return (bool)preg_match('/\(\s*404\s*\)|\bhttp\s*404\b|\b404\b/i', $msg);
    }
}

if (!function_exists('llm_err_is_model_error')) {
    /** ¿El error es porque el modelo pedido no existe en el servidor? */
    function llm_err_is_model_error(string $msg): bool
    {
        $low = strtolower($msg);
        foreach (['model not found', 'model_not_found', 'invalid model', 'unknown model', 'no such model', 'model does not exist', 'model is not loaded', 'modelo no encontrado'] as $needle) {
            if (str_contains($low, $needle)) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('llm_err_is_unavailable')) {
    /** ¿El error es un 503 (servidor/modelo cargando)? */
    function llm_err_is_unavailable(string $msg): bool
    {
        $low = strtolower($msg);
        if ((bool)preg_match('/\(\s*503\s*\)|\bhttp\s*503\b|\b503\b/i', $msg)) {
            return true;
        }
        return str_contains($low, 'loading') || str_contains($low, 'unavailable') || str_contains($low, 'overloaded');
    }
}

if (!function_exists('llm_err_is_timeout')) {
    /** ¿El error es un timeout de transporte? */
    function llm_err_is_timeout(string $msg): bool
    {
        $low = strtolower($msg);
        foreach (['timed out', 'timeout', 'operation timeout', 'curl error 28', 'resolving timed out'] as $needle) {
            if (str_contains($low, $needle)) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('llm_err_is_context_overflow')) {
    /**
     * ¿El error es que el prompt no cabe en la ventana de contexto?
     *
     * Firmas conocidas:
     *  - llama.cpp: "the request exceeds the available context size. try increasing
     *    the context size or enable context shift" / type "exceed_context_size_error"
     *    / "input is too large to process".
     *  - Ollama: "prompt too long; exceeded max context length by N tokens".
     *  - vLLM: "This model's maximum context length is N tokens".
     *  - OpenAI: "maximum context length exceeded" / "context_length_exceeded".
     */
    function llm_err_is_context_overflow(string $msg): bool
    {
        $low = strtolower($msg);
        foreach ([
            'exceeds the available context size',
            'exceed_context_size_error',
            'exceeds the context size',
            'input is too large to process',
            'context shift',
            'prompt too long',
            'too long; exceeded max context length',
            'exceeded max context length',
            'maximum context length',
            'context_length_exceeded',
            'context length exceeded',
            'requires more context',
        ] as $needle) {
            if (str_contains($low, $needle)) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('llm_err_context_numbers')) {
    /**
     * Extrae los contadores de contexto de un mensaje de error.
     *
     * Admite el formato de llama.cpp ("request (2100 tokens) exceeds the
     * available context size (1536 tokens)") y el resumen que añade
     * Module_Llm ("[n_prompt_tokens=2100, n_ctx=1536]").
     *
     * @return array{prompt:int,ctx:int} 0 = desconocido
     */
    function llm_err_context_numbers(string $msg): array
    {
        $prompt = 0;
        $ctx = 0;

        if (preg_match('/request\s*\(\s*(\d+)\s*tokens?\s*\)\s*exceeds the available context size\s*\(\s*(\d+)\s*tokens?\s*\)/i', $msg, $m)) {
            $prompt = (int)$m[1];
            $ctx = (int)$m[2];
        }
        if ($prompt === 0 && preg_match('/n_prompt_tokens\s*=\s*(\d+)/i', $msg, $m)) {
            $prompt = (int)$m[1];
        }
        if ($ctx === 0 && preg_match('/\bn_ctx\s*=\s*(\d+)/i', $msg, $m)) {
            $ctx = (int)$m[1];
        }
        if ($prompt === 0 && preg_match('/exceeded max context length by\s+(\d+)\s+tokens/i', $msg, $m)) {
            $prompt = (int)$m[1];
        }

        return ['prompt' => $prompt, 'ctx' => $ctx];
    }
}

if (!function_exists('llm_props_ctx')) {
    /**
     * Ventana de contexto a partir de `GET /props` de llama.cpp.
     * Devuelve 0 si la respuesta no la expone (Ollama, vLLM, OpenAI…).
     */
    function llm_props_ctx(array $res): int
    {
        $candidates = [
            $res['default_generation_settings']['n_ctx'] ?? null,
            $res['n_ctx'] ?? null,
            $res['default_generation_settings']['n_ctx_per_seq'] ?? null,
        ];
        foreach ($candidates as $value) {
            if (is_numeric($value) && (int)$value > 0) {
                return (int)$value;
            }
        }
        return 0;
    }
}
