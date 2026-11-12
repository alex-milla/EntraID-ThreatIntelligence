<?php
/**
 * llm-transport.php - Pruebas de la normalización de endpoints del LLM.
 *
 *   php tools/smoke/llm-transport.php
 *
 * Verifica (sin red) que una Base URL escrita de cualquier forma se resuelve
 * al endpoint correcto, que los listados de modelos se interpretan igual en
 * formato OpenAI y Ollama, y que los errores se clasifican bien (404 de ruta
 * frente a 404 de modelo, 503 y timeout). No toca la base de datos.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    echo ($ok ? 'OK   ' : 'FALLO ') . $label . (!$ok && $detail !== '' ? ' - ' . $detail : '') . PHP_EOL;
    if (!$ok) { $fail++; }
}

function sameList(array $got, array $want): bool
{
    return array_values($got) === array_values($want);
}

try {
    // ============================================================
    // 1 - Endpoints de chat compatibles con OpenAI
    // ============================================================
    check('helper llm_transport cargado', function_exists('llm_openai_endpoints'));

    $cases = [
        'raíz'                => ['https://orin.taila89a32.ts.net', ['https://orin.taila89a32.ts.net/v1/chat/completions', 'https://orin.taila89a32.ts.net/chat/completions']],
        'raíz con barra'      => ['https://orin.taila89a32.ts.net/', ['https://orin.taila89a32.ts.net/v1/chat/completions', 'https://orin.taila89a32.ts.net/chat/completions']],
        'base /v1'            => ['https://orin.taila89a32.ts.net/v1', ['https://orin.taila89a32.ts.net/v1/chat/completions']],
        '/v1 con barra'       => ['https://orin.taila89a32.ts.net/v1/', ['https://orin.taila89a32.ts.net/v1/chat/completions']],
        'endpoint completo'   => ['https://api.openai.com/v1/chat/completions', ['https://api.openai.com/v1/chat/completions']],
        'gemini por defecto'  => ['https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', ['https://generativelanguage.googleapis.com/v1beta/openai/chat/completions']],
        'mistral por defecto' => ['https://api.mistral.ai/v1/chat/completions', ['https://api.mistral.ai/v1/chat/completions']],
        'base /api/v1'        => ['https://host.local/api/v1', ['https://host.local/api/v1/chat/completions']],
        'v1beta/openai'       => ['https://host.local/v1beta/openai', ['https://host.local/v1beta/openai/chat/completions']],
    ];
    foreach ($cases as $label => $pair) {
        $got = llm_openai_endpoints($pair[0]);
        check('endpoints: ' . $label, sameList($got, $pair[1]), json_encode($got));
    }
    check('endpoints: URL vacía', llm_openai_endpoints('   ') === []);

    // ============================================================
    // 2 - llm_openai_base
    // ============================================================
    check('base de endpoint', llm_openai_base('https://host/v1/chat/completions') === 'https://host/v1');
    check('base de raíz', llm_openai_base('https://host/') === 'https://host');
    check('base de vacío', llm_openai_base('') === '');

    // ============================================================
    // 3 - Host nativo de Ollama (no duplica rutas)
    // ============================================================
    $ollamaCases = [
        'https://host'                            => 'https://host',
        'https://host/'                           => 'https://host',
        'https://host/api/chat'                   => 'https://host',
        'https://host/api'                        => 'https://host',
        'https://host/v1'                         => 'https://host',
        'https://host/v1/chat/completions'        => 'https://host',
        'https://host/api/chat/api/chat'          => 'https://host',
        'http://localhost:11434/api/tags'         => 'http://localhost:11434',
        'https://ollama.com'                      => 'https://ollama.com',
    ];
    foreach ($ollamaCases as $in => $want) {
        $got = llm_ollama_base($in);
        check('ollama base: ' . $in, $got === $want, 'got=' . $got);
    }

    // ============================================================
    // 4 - Endpoints de listado de modelos
    // ============================================================
    check(
        'modelos desde raíz',
        sameList(llm_model_endpoints('https://host'), ['https://host/v1/models', 'https://host/models', 'https://host/api/tags'])
    );
    check(
        'modelos desde /v1',
        sameList(llm_model_endpoints('https://host/v1'), ['https://host/v1/models', 'https://host/api/tags'])
    );
    check(
        'modelos desde endpoint de chat',
        sameList(llm_model_endpoints('https://host/v1/chat/completions'), ['https://host/v1/models', 'https://host/api/tags'])
    );
    check(
        'modelos de gemini',
        sameList(llm_model_endpoints('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions'), ['https://generativelanguage.googleapis.com/v1beta/openai/models', 'https://generativelanguage.googleapis.com/v1beta/openai/api/tags']),
        json_encode(llm_model_endpoints('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions'))
    );

    // ============================================================
    // 5 - Interpretación de los listados de modelos
    // ============================================================
    $openai = ['object' => 'list', 'data' => [['id' => 'gemma-4-E2B-it-Q4_K_M.gguf'], ['id' => 'otro']]];
    check('modelos OpenAI', sameList(llm_models_from_response($openai), ['gemma-4-E2B-it-Q4_K_M.gguf', 'otro']));

    $native = ['models' => [['name' => 'llama3.1:latest'], ['name' => 'qwen2.5:7b']]];
    check('modelos Ollama nativo', sameList(llm_models_from_response($native), ['llama3.1:latest', 'qwen2.5:7b']));

    $both = ['data' => [['id' => 'a']], 'models' => [['name' => 'a'], ['name' => 'b']]];
    check('modelos duplicados', sameList(llm_models_from_response($both), ['a', 'b']));
    check('modelos respuesta vacía', llm_models_from_response([]) === []);
    check('modelos respuesta basura', llm_models_from_response(['data' => [['x' => 1], null], 'models' => [123]]) === []);

    // ============================================================
    // 6 - Clasificación de errores
    // ============================================================
    $msg404 = 'LLM API Error (404): File Not Found';
    check('404 de ruta es not_found', llm_err_is_not_found($msg404));
    check('404 de ruta NO es de modelo', !llm_err_is_model_error($msg404));

    $msgModel = 'LLM API Error (404): Model not found';
    check('404 de modelo es not_found', llm_err_is_not_found($msgModel));
    check('404 de modelo se detecta', llm_err_is_model_error($msgModel));

    check('modelo inválido (invalid model)', llm_err_is_model_error('LLM API Error (400): invalid model name'));
    check('503 se detecta', llm_err_is_unavailable('LLM API Error (503): Loading model'));
    check('503 en texto', llm_err_is_unavailable('server is loading the model'));
    check('timeout se detecta', llm_err_is_timeout('Error cURL: Operation timed out after 120000 milliseconds'));
    check('timeout en castellano no aplica', !llm_err_is_timeout('Ruta inexistente (404)'));
    check('401 no es not_found', !llm_err_is_not_found('LLM API Error (401): unauthorized: Invalid API Key'));
    check('401 no es 503', !llm_err_is_unavailable('LLM API Error (401): unauthorized: Invalid API Key'));

    // ============================================================
    // 7 - Constantes y API pública del módulo
    // ============================================================
    check('constante LLM_503_RETRY_DELAY', defined('LLM_503_RETRY_DELAY') && is_int(LLM_503_RETRY_DELAY));
    check('Module_Llm::listModels existe', method_exists('Module_Llm', 'listModels'));
    check('Module_Llm::verifyOllama existe', method_exists('Module_Llm', 'verifyOllama'));
    check('Module_Llm::testConnection existe', method_exists('Module_Llm', 'testConnection'));
} catch (Throwable $e) {
    check('excepción inesperada: ' . $e->getMessage(), false, $e->getFile() . ':' . $e->getLine());
}

echo PHP_EOL . ($total - $fail) . '/' . $total . ' OK' . PHP_EOL;
exit($fail === 0 ? 0 : 1);
