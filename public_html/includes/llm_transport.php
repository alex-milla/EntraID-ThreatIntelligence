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

if (!function_exists('llm_estimate_tokens')) {
    /**
     * Estimación de tokens para texto técnico en español (~3,6 chars/token)
     * con un 10 % de margen. No sustituye al tokenizador del servidor, pero
     * sirve para no pasarse de la ventana.
     */
    function llm_estimate_tokens(string $text): int
    {
        $len = function_exists('mb_strlen') ? mb_strlen($text) : strlen($text);
        return (int)ceil(($len / 3.6) * 1.10);
    }
}

if (!function_exists('llm_effective_max_tokens')) {
    /**
     * Tope de salida efectivo: el de la tarea, recortado por el del perfil.
     * Un perfil con max_tokens > 0 no deja pedir más de lo que admite.
     */
    function llm_effective_max_tokens(int $taskMax, array $cfg): int
    {
        $taskMax = max(1, $taskMax);
        $profileMax = (int)($cfg['max_tokens'] ?? 0);
        return $profileMax > 0 ? max(1, min($taskMax, $profileMax)) : $taskMax;
    }
}

if (!function_exists('llm_str_len')) {
    function llm_str_len(string $s): int
    {
        return function_exists('mb_strlen') ? mb_strlen($s) : strlen($s);
    }
}

if (!function_exists('llm_str_cut')) {
    function llm_str_cut(string $s, int $n): string
    {
        return function_exists('mb_substr') ? mb_substr($s, 0, $n) : substr($s, 0, $n);
    }
}

if (!function_exists('llm_split_long_block')) {
    /**
     * Parte un bloque demasiado largo por líneas y, si una línea sigue siendo
     * enorme, por palabras (nunca en mitad de un token).
     *
     * @return string[]
     */
    function llm_split_long_block(string $block, int $maxChars): array
    {
        $maxChars = max(300, $maxChars);
        $out = [];
        $buffer = '';

        foreach (explode("\n", $block) as $line) {
            $lineLen = llm_str_len($line);

            if ($lineLen > $maxChars) {
                if ($buffer !== '') {
                    $out[] = $buffer;
                    $buffer = '';
                }
                $piece = '';
                foreach (preg_split('/\s+/u', $line) ?: [] as $word) {
                    if ($piece !== '' && llm_str_len($piece) + 1 + llm_str_len($word) > $maxChars) {
                        $out[] = $piece;
                        $piece = $word;
                    } else {
                        $piece .= ($piece !== '' ? ' ' : '') . $word;
                    }
                }
                if ($piece !== '') {
                    $out[] = $piece;
                }
                continue;
            }

            if ($buffer !== '' && llm_str_len($buffer) + 1 + $lineLen > $maxChars) {
                $out[] = $buffer;
                $buffer = $line;
            } else {
                $buffer .= ($buffer !== '' ? "\n" : '') . $line;
            }
        }

        if ($buffer !== '') {
            $out[] = $buffer;
        }
        return $out;
    }
}

if (!function_exists('llm_split_markdown')) {
    /**
     * Trocea Markdown en bloques de como máximo $maxChars para traducir por
     * partes. Respeta tablas, listas y bloques de código (```), que nunca se
     * parten por la mitad.
     *
     * @return string[]
     */
    function llm_split_markdown(string $text, int $maxChars = 1400): array
    {
        $maxChars = max(400, $maxChars);
        $text = str_replace(["\r\n", "\r"], "\n", trim($text));
        if ($text === '') {
            return [];
        }

        $blocks = preg_split("/\n{2,}/", $text) ?: [];
        $chunks = [];
        $buffer = '';
        $openFence = false;

        foreach ($blocks as $block) {
            $block = trim($block);
            if ($block === '') {
                continue;
            }

            $fences = substr_count($block, '```');
            if ($openFence || ($fences % 2 === 1)) {
                $buffer .= ($buffer !== '' ? "\n\n" : '') . $block;
                if ($fences % 2 === 1) {
                    $openFence = !$openFence;
                }
                continue;
            }

            if (llm_str_len($block) > $maxChars) {
                if ($buffer !== '') {
                    $chunks[] = $buffer;
                    $buffer = '';
                }
                foreach (llm_split_long_block($block, $maxChars) as $piece) {
                    $chunks[] = $piece;
                }
                continue;
            }

            if ($buffer === '') {
                $buffer = $block;
            } elseif (llm_str_len($buffer) + 2 + llm_str_len($block) <= $maxChars) {
                $buffer .= "\n\n" . $block;
            } else {
                $chunks[] = $buffer;
                $buffer = $block;
            }
        }

        if ($buffer !== '') {
            $chunks[] = $buffer;
        }
        return $chunks;
    }
}

if (!function_exists('llm_fit_parts')) {
    /**
     * Ajusta el contexto al presupuesto del modelo.
     *
     * Cada parte: ['text' => string, 'priority' => int, 'min' => int].
     * La prioridad más baja (1) se recorta primero; `min` son los caracteres
     * que se conservan siempre de esa parte.
     *
     * @return array{parts: array<string,string>, clipped: bool, fits: bool, note: string, tokens: int, budget: int}
     */
    function llm_fit_parts(array $parts, int $maxTokens, int $window, int $reserved = 0): array
    {
        $texts = [];
        foreach ($parts as $key => $part) {
            $texts[$key] = (string)($part['text'] ?? '');
        }

        $join = static fn(array $t): string => implode("\n\n", array_filter($t, static fn($v) => $v !== ''));

        if ($window <= 0) {
            return [
                'parts'   => $texts,
                'clipped' => false,
                'fits'    => true,
                'note'    => '',
                'tokens'  => llm_estimate_tokens($join($texts)),
                'budget'  => 0,
            ];
        }

        $budget = max(64, $window - max(1, $maxTokens) - max(0, $reserved));
        $tokens = llm_estimate_tokens($join($texts));
        if ($tokens <= $budget) {
            return ['parts' => $texts, 'clipped' => false, 'fits' => true, 'note' => '', 'tokens' => $tokens, 'budget' => $budget];
        }

        $len  = static fn(string $s): int => llm_str_len($s);
        $cut  = static fn(string $s, int $n): string => llm_str_cut($s, $n);

        // De menor a mayor prioridad (después se recorta más si hace falta).
        $order = array_keys($parts);
        usort($order, static function (string $a, string $b) use ($parts): int {
            return ((int)($parts[$a]['priority'] ?? 5)) <=> ((int)($parts[$b]['priority'] ?? 5));
        });

        $clippedKeys = [];
        $rounds = 0;
        while ($tokens > $budget && $rounds < 4) {
            $rounds++;
            $progress = false;
            foreach ($order as $key) {
                $tokens = llm_estimate_tokens($join($texts));
                if ($tokens <= $budget) {
                    break 2;
                }
                $current = $texts[$key];
                $currentLen = $len($current);
                if ($currentLen <= 200) {
                    continue;
                }
                $minKeep = max(0, min($currentLen, (int)($parts[$key]['min'] ?? 200)));
                $excess = $tokens - $budget;
                $keep = (int)floor($currentLen - ($excess * 3.6 / max(1.0, 1.10)));
                $keep = max($minKeep, min($currentLen, $keep));
                if ($keep < $currentLen) {
                    $texts[$key] = $cut($current, $keep) . '…';
                    $clippedKeys[] = $key;
                    $progress = true;
                }
            }
            if (!$progress) {
                break;
            }
        }

        $finalTokens = llm_estimate_tokens($join($texts));
        $clipped = $clippedKeys !== [];
        $note = '';
        if ($clipped) {
            $note = 'Contexto recortado (' . implode(', ', array_unique($clippedKeys)) . ') para caber en la ventana de '
                . number_format($window, 0, ',', '.') . ' tokens del modelo.';
        }

        return [
            'parts'   => $texts,
            'clipped' => $clipped,
            'fits'    => $finalTokens <= $budget,
            'note'    => $note,
            'tokens'  => $finalTokens,
            'budget'  => $budget,
        ];
    }
}
