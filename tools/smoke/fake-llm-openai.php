<?php
/**
 * LLM falso que emula llama-server (la API de la Orin).
 *
 * - Exige `Authorization: Bearer e2e-orin-key` en todas las rutas (401 sin ella).
 * - `GET  /v1/models`            -> modelo cargado (`e2e-orin-model.gguf`).
 * - `POST /v1/chat/completions`  -> formato OpenAI; 404 «Model not found» si el
 *                                   `model` no coincide y 400 si `stream` no es
 *                                   explícitamente false.
 * - `POST /api/chat` y el resto -> 404 «File Not Found» (no existe la API
 *                                   nativa de Ollama).
 *
 * Guarda cada petición en `sys_get_temp_dir()/entraid-fake-llm-openai.log` para
 * que el E2E compruebe el orden de rutas probadas. `TRIGGER-503` en el prompt
 * provoca un 503 la primera vez (modelo cargando).
 *
 * Uso: php -S 127.0.0.1:8896 tools/smoke/fake-llm-openai.php
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

const FAKE_KEY   = 'e2e-orin-key';
const FAKE_MODEL = 'e2e-orin-model.gguf';
const FAKE_CTX_MODEL = 'e2e-ctx-model';
const FAKE_CTX = 1536;

$logFile = sys_get_temp_dir() . '/entraid-fake-llm-openai.log';
$flag503 = sys_get_temp_dir() . '/entraid-fake-llm-openai-503.flag';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$raw    = file_get_contents('php://input') ?: '';
$body   = json_decode($raw, true);
$body   = is_array($body) ? $body : [];

$prompt = '';
foreach (($body['messages'] ?? []) as $m) {
    if (is_array($m) && ($m['role'] ?? '') === 'user') {
        $prompt = (string)($m['content'] ?? '');
    }
}

$authOk = hash_equals('Bearer ' . FAKE_KEY, (string)($_SERVER['HTTP_AUTHORIZATION'] ?? ''));

@file_put_contents($logFile, json_encode([
    'method' => $method,
    'path'   => $path,
    'model'  => $body['model'] ?? null,
    'stream' => $body['stream'] ?? null,
    'auth'   => $authOk,
    'prompt' => substr($prompt, 0, 80),
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND);

function fakeOut(int $code, array $payload): void
{
    http_response_code($code);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

if (!$authOk) {
    fakeOut(401, ['error' => ['message' => 'unauthorized: Invalid API Key']]);
}

if ($method === 'GET' && $path === '/v1/models') {
    fakeOut(200, [
        'object' => 'list',
        'data'   => [
            ['id' => FAKE_MODEL, 'object' => 'model', 'owned_by' => 'orin'],
        ],
    ]);
}

// llama.cpp expone la ventana real del servidor en GET /props.
if ($method === 'GET' && $path === '/props') {
    fakeOut(200, [
        'default_generation_settings' => ['n_ctx' => FAKE_CTX],
        'total_slots' => 1,
        'model_path'  => FAKE_MODEL,
    ]);
}

if ($method === 'POST' && $path === '/v1/chat/completions') {
    $model = (string)($body['model'] ?? '');
    if ($model !== FAKE_MODEL && $model !== FAKE_CTX_MODEL) {
        fakeOut(404, ['error' => ['code' => 404, 'message' => 'Model not found']]);
    }
    if (($body['stream'] ?? null) !== false) {
        fakeOut(400, ['error' => ['message' => 'stream must be explicitly false']]);
    }

    // Traducción por segmentos: devuelve el texto marcado y ENVUELTO en un
    // fence markdown a propósito, para que el E2E compruebe el saneado.
    if (str_starts_with($prompt, 'FRAGMENTO A TRADUCIR (Markdown):')) {
        $text = trim(substr($prompt, strlen('FRAGMENTO A TRADUCIR (Markdown):')));
        fakeOut(200, [
            'choices' => [[
                'message'       => ['role' => 'assistant', 'content' => "```markdown\n[ES] " . $text . "\n```"],
                'finish_reason' => 'stop',
            ]],
            'usage' => ['prompt_tokens' => 20, 'completion_tokens' => 20, 'total_tokens' => 40],
        ]);
    }

    // Fin de contexto con el formato real de llama.cpp.
    if ($model === FAKE_CTX_MODEL || str_contains($prompt, 'TRIGGER-CTX')) {
        fakeOut(400, [
            'error' => [
                'code'    => 400,
                'message' => 'request (2100 tokens) exceeds the available context size (' . FAKE_CTX . ' tokens), try increasing it',
                'type'    => 'exceed_context_size_error',
            ],
            'n_prompt_tokens' => 2100,
            'n_ctx'           => FAKE_CTX,
        ]);
    }

    // Fin de contexto con el formato de Ollama.
    if (str_contains($prompt, 'TRIGGER-CTX-OLLAMA')) {
        fakeOut(400, ['error' => 'prompt too long; exceeded max context length by 1200 tokens']);
    }

    if (str_contains($prompt, 'TRIGGER-503')) {
        $n = (int)@file_get_contents($flag503);
        if ($n < 1) {
            @file_put_contents($flag503, (string)($n + 1));
            fakeOut(503, ['error' => ['message' => 'Loading model']]);
        }
        fakeOut(200, [
            'choices' => [[
                'message'       => ['role' => 'assistant', 'content' => 'E2E-RETRY-OK'],
                'finish_reason' => 'stop',
            ]],
            'usage' => ['prompt_tokens' => 8, 'completion_tokens' => 3, 'total_tokens' => 11],
        ]);
    }

    fakeOut(200, [
        'choices' => [[
            'message'       => ['role' => 'assistant', 'content' => 'E2E-ORIN-OK model=' . FAKE_MODEL],
            'finish_reason' => 'stop',
        ]],
        'usage' => ['prompt_tokens' => 8, 'completion_tokens' => 4, 'total_tokens' => 12],
    ]);
}

// Cualquier otra ruta: llama-server devuelve 404 «File Not Found».
fakeOut(404, ['error' => ['message' => 'File Not Found']]);
