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
    // 6 bis - Fin de contexto
    // ============================================================
    $ctxLlama = 'LLM API Error (400): request (2100 tokens) exceeds the available context size (1536 tokens), try increasing it'
        . ' [type=exceed_context_size_error, n_prompt_tokens=2100, n_ctx=1536]';
    check('contexto llama.cpp se detecta', llm_err_is_context_overflow($ctxLlama));
    $ctxNums = llm_err_context_numbers($ctxLlama);
    check('contexto llama.cpp: 2100/1536', $ctxNums['prompt'] === 2100 && $ctxNums['ctx'] === 1536, json_encode($ctxNums));

    $ctxOllama = 'LLM API Error (400): prompt too long; exceeded max context length by 1200 tokens';
    check('contexto Ollama se detecta', llm_err_is_context_overflow($ctxOllama));
    check('contexto Ollama: exceso 1200', llm_err_context_numbers($ctxOllama)['prompt'] === 1200);

    check(
        'contexto vLLM se detecta',
        llm_err_is_context_overflow("This model's maximum context length is 4096 tokens. However, you requested 5000 tokens")
    );
    check(
        'contexto OpenAI se detecta',
        llm_err_is_context_overflow('LLM API Error (400): maximum context length exceeded [code=context_length_exceeded]')
    );
    check('404 no es contexto', !llm_err_is_context_overflow('LLM API Error (404): File Not Found'));
    check('401 no es contexto', !llm_err_is_context_overflow('LLM API Error (401): unauthorized: Invalid API Key'));
    check('timeout no es contexto', !llm_err_is_context_overflow('Error cURL: Operation timed out after 120000 milliseconds'));

    check('props: default_generation_settings.n_ctx', llm_props_ctx(['default_generation_settings' => ['n_ctx' => 8192]]) === 8192);
    check('props: n_ctx en la raíz', llm_props_ctx(['n_ctx' => 4096]) === 4096);
    check('props: sin datos', llm_props_ctx(['model_path' => 'x']) === 0);
    check('props: valor inválido', llm_props_ctx(['n_ctx' => 'abc']) === 0);

    // ============================================================
    // 6 bis2 - Errores de proxy (502/504) y HTML
    // ============================================================
    check('gateway: 502', llm_err_is_gateway('LLM API Error (502): el proxy devolvió una página HTML'));
    check('gateway: Bad Gateway', llm_err_is_gateway('502 Bad Gateway'));
    check('gateway: 504', llm_err_is_gateway('Gateway Time-out (504)'));
    check('gateway: 503 no es gateway', !llm_err_is_gateway('LLM API Error (503): el modelo se está cargando'));
    check('gateway: 401 no es gateway', !llm_err_is_gateway('LLM API Error (401): unauthorized'));
    check('html: doctype', llm_err_has_html("<!DOCTYPE html>\n<html lang=\"en\">"));
    check('html: head/title', llm_err_has_html('<head><title>502 Bad Gateway</title></head>'));
    check('html: texto normal no', !llm_err_has_html('LLM API Error (404): File Not Found'));

    // ============================================================
    // 6 bis3 - Modelo local pequeño
    // ============================================================
    check('modelo pequeño: Ministral-3B', llm_profile_is_small(['provider' => 'ollama', 'model' => 'Ministral-3B-Instruct-2512-Q4_K_M']));
    check('modelo pequeño: LFM3-1.7B', llm_profile_is_small(['provider' => 'custom', 'model' => 'LFM3-1.7B-Q4_K_M']));
    check('modelo pequeño: qwen 4b', llm_profile_is_small(['provider' => 'custom', 'model' => 'qwen3.8-4b-q4_k_m']));
    check('modelo pequeño: gpt-oss 20b no', !llm_profile_is_small(['provider' => 'ollama_cloud', 'model' => 'gpt-oss:20b']));
    check('modelo pequeño: openai no aplica', !llm_profile_is_small(['provider' => 'openai', 'model' => 'gpt-4o-mini']));
    check('modelo pequeño: sin tamaño no se asume', !llm_profile_is_small(['provider' => 'ollama', 'model' => 'llama3.1']));
    check('modelo pequeño: perfil nulo', !llm_profile_is_small(null));

    // ============================================================
    // 6 ter - Presupuesto de contexto y troceado
    // ============================================================
    check('max_tokens: manda la tarea si el perfil es 0', llm_effective_max_tokens(3000, ['max_tokens' => 0]) === 3000);
    check('max_tokens: el perfil recorta', llm_effective_max_tokens(3000, ['max_tokens' => 1000]) === 1000);
    check('max_tokens: no sube el del perfil', llm_effective_max_tokens(500, ['max_tokens' => 4000]) === 500);

    check('tokens: texto vacío', llm_estimate_tokens('') === 0);
    check('tokens: ~3.600 chars ≈ 1.100', llm_estimate_tokens(str_repeat('a', 3600)) === 1100);

    // Cabe: no se recorta.
    $fit = llm_fit_parts(['a' => ['text' => str_repeat('x', 2000), 'priority' => 1]], 500, 4096);
    check('fit: cabe sin recortar', $fit['clipped'] === false && $fit['fits'] === true && $fit['note'] === '');

    // No cabe: se recorta el bloque de menor prioridad.
    $fit = llm_fit_parts([
        'cuerpo' => ['text' => str_repeat('c', 12000), 'priority' => 1, 'min' => 200],
        'cabeza' => ['text' => str_repeat('h', 800), 'priority' => 5, 'min' => 800],
    ], 1000, 4096);
    check('fit: recorta ante exceso', $fit['clipped'] === true && $fit['fits'] === true);
    check('fit: recorta primero el cuerpo', str_contains($fit['note'], 'cuerpo') && !str_contains($fit['note'], 'cabeza'), $fit['note']);
    check('fit: la cabeza queda intacta', $fit['parts']['cabeza'] === str_repeat('h', 800));
    check('fit: el cuerpo se acorta', llm_str_len($fit['parts']['cuerpo']) < 12000);

    // Sin margen posible (min = longitud): no cabe y se dice.
    $fit = llm_fit_parts(['fijo' => ['text' => str_repeat('f', 12000), 'priority' => 1, 'min' => 12000]], 1000, 2048);
    check('fit: no cabe si no se puede recortar', $fit['fits'] === false);

    // Ventana desconocida: no se toca nada (compatibilidad).
    $fit = llm_fit_parts(['a' => ['text' => str_repeat('x', 50000), 'priority' => 1]], 1000, 0);
    check('fit: ventana 0 no recorta', $fit['clipped'] === false && $fit['fits'] === true);

    $mdShort = "# Título\n\nUn párrafo corto.";
    check('split: texto corto en un bloque', count(llm_split_markdown($mdShort, 1400)) === 1);

    $mdLong = '';
    for ($i = 0; $i < 30; $i++) {
        $mdLong .= "## Sección $i\n\n" . str_repeat('palabra ', 60) . "\n\n";
    }
    $mdLong .= "| A | B |\n|---|---|\n| 1 | 2 |\n\n```php\n\$a = 1;\n\n\$b = 2;\n```\n";
    $chunks = llm_split_markdown($mdLong, 1400);
    check('split: texto largo en varios bloques', count($chunks) >= 3, 'bloques=' . count($chunks));
    $tooBig = 0;
    foreach ($chunks as $c) {
        if (llm_str_len($c) > 1400) { $tooBig++; }
    }
    check('split: bloques acotados', $tooBig === 0, 'grandes=' . $tooBig);

    $joined = implode("\n\n", $chunks);
    check('split: no pierde el título', str_contains($joined, '## Sección 0'));
    check('split: no pierde el final', str_contains($joined, 'Final') || str_contains($joined, '$b = 2;'));
    check('split: conserva la tabla', str_contains($joined, '| A | B |'));
    $fences = 0;
    foreach ($chunks as $c) {
        $fences += substr_count($c, '```');
    }
    check('split: los bloques de código no se parten', $fences % 2 === 0, 'fences=' . $fences);

    $probeText = str_repeat('texto de prueba ', 400);
    $chunks2 = llm_split_markdown($probeText, 400);
    $reconstructed = preg_replace('/\s+/u', '', implode('', $chunks2));
    check('split: sin pérdida de contenido', $reconstructed === preg_replace('/\s+/u', '', $probeText));

    // ============================================================
    // 6 quater - Saneado del Markdown de IA y segmentos
    // ============================================================
    $wrapped = "```markdown\n## Snapshot\n\nTexto.\n\n```kql\nDeviceProcessEvents\n| where X == 1\n```\n\n## Fin\n```";
    $norm = normalize_ai_markdown($wrapped);
    check('normalize: desenvuelve el envoltorio', !str_starts_with($norm, '```markdown'));
    check('normalize: conserva el bloque interno', substr_count($norm, '```') === 2);
    check('normalize: el kql intacto', normalize_ai_markdown("```kql\nq\n```") === "```kql\nq\n```");
    check('normalize: envoltorio sin cerrar', !str_starts_with(normalize_ai_markdown("```markdown\n## A\n\ntexto\n"), '```'));

    $balanced = ai_balance_fences("## A\n\n```\ncodigo suelto\n\n## B\n\nprosa");
    check('balance: quita la apertura sin cierre', substr_count($balanced, '```') === 0);
    $okCode = "## A\n\n```kql\nq\n```\n\n## B";
    check('balance: no toca un bloque correcto', ai_balance_fences($okCode) === $okCode);

    $resid = ai_strip_residues("Aquí tienes la traducción:\n\n## T\n\nprosa\n===\nfin");
    check('residuos: quita el prefijo', !str_contains($resid, 'Aquí tienes'));
    check('residuos: === → ---', str_contains($resid, '---') && !str_contains($resid, '==='));

    $proseWrapped = ai_clean_prose("```markdown\n## T\n\nprosa traducida\n```");
    check('clean_prose: quita el envoltorio', !str_contains($proseWrapped, '```'));
    check('clean_prose: conserva el texto', str_contains($proseWrapped, 'prosa traducida'));

    $htmlWrapped = render_ai_markdown($wrapped);
    check('render_ai: el documento se pinta como Markdown', str_contains($htmlWrapped, '<h2>Snapshot</h2>'), substr($htmlWrapped, 0, 120));
    check('render_ai: el kql sigue siendo código', str_contains($htmlWrapped, 'language-kql') || str_contains($htmlWrapped, '<pre><code'));

    $segments = llm_split_markdown_segments(
        "# Titulo\n\nParrafo uno.\n\n```kql\nDeviceProcessEvents\n\n| where X == 1\n```\n\nMas prosa.",
        1400
    );
    $types = array_map(static fn($s) => $s['type'], $segments);
    check('segmentos: prosa/código/prosa', $types === ['prosa', 'codigo', 'prosa'], implode(',', $types));
    check('segmentos: el código va byte a byte', $segments[1]['text'] === "```kql\nDeviceProcessEvents\n\n| where X == 1\n```");
    $segJoin = '';
    foreach ($segments as $s) { $segJoin .= $s['text']; }
    check('segmentos: sin pérdida de contenido', preg_replace('/\s+/u', '', $segJoin) === preg_replace('/\s+/u', '', "# Titulo\n\nParrafo uno.\n\n```kql\nDeviceProcessEvents\n\n| where X == 1\n```\n\nMas prosa."));

    // --- Código en línea (KQL de los artículos de Microsoft) ---
    check('inline: línea KQL', llm_is_inline_code_line('`DeviceProcessEvents`'));
    check('inline: línea con pipe', llm_is_inline_code_line('`| where Timestamp > ago(30d)`'));
    check('inline: varios tramos', llm_is_inline_code_line('`a` + `b`'));
    check('inline: prosa con dato', !llm_is_inline_code_line('El campo `Timeout` marca el plazo'));
    check('inline: texto tras el tramo', !llm_is_inline_code_line('Consulta: `x`'));
    check('inline: valla no es inline', !llm_is_inline_code_line('```kql'));
    check('inline: línea vacía', !llm_is_inline_code_line('   '));

    check('indentado: 4 espacios', llm_is_indented_code_line('    Get-ChildItem', 'Prosa anterior'));
    check('indentado: continuación de lista', !llm_is_indented_code_line('    continuación', '- elemento'));
    check('indentado: 2 espacios no', !llm_is_indented_code_line('  x', null));

    check('code lines: inline + valla', llm_count_code_lines("`a`\n`b`\n\nprosa\n\n```kql\nq\n```") === 3);

    $mdKql = "### T\n\nConsulta:\n\n`DeviceProcessEvents`\n`| where X > 1`\n\nProsa final.";
    $segKql = llm_split_markdown_segments($mdKql, 1400);
    $typesKql = array_map(static fn($s) => $s['type'], $segKql);
    check('segmentos KQL: prosa/código/prosa', $typesKql === ['prosa', 'codigo', 'prosa'], implode(',', $typesKql));
    check('segmentos KQL: el bloque en línea va byte a byte', $segKql[1]['text'] === "`DeviceProcessEvents`\n`| where X > 1`");

    // ============================================================
    // 7 - Constantes y API pública del módulo
    // ============================================================
    check('constante LLM_503_RETRY_DELAY', defined('LLM_503_RETRY_DELAY') && is_int(LLM_503_RETRY_DELAY));
    check('Module_Llm::listModels existe', method_exists('Module_Llm', 'listModels'));
    check('Module_Llm::verifyOllama existe', method_exists('Module_Llm', 'verifyOllama'));
    check('Module_Llm::testConnection existe', method_exists('Module_Llm', 'testConnection'));
    check('Module_Llm::contextWindow existe', method_exists('Module_Llm', 'contextWindow'));

    // ============================================================
    // 8 - Razonamiento (think) y JSON de los modelos locales
    // ============================================================
    $tOpen = '<' . 'think>';
    $tClose = '<' . '/think>';
    $think = llm_strip_thinking($tOpen . "\nrazono paso a paso\n" . $tClose . "\n\n## Informe\n\nTexto final.");
    check('think: separa el razonamiento', $think['thinking'] === 'razono paso a paso', $think['thinking']);
    check('think: deja el contenido limpio', $think['content'] === "## Informe\n\nTexto final.", $think['content']);
    $thinkOpen = llm_strip_thinking($tOpen . "sin cerrar\nmás razonamiento");
    check('think: bloque sin cerrar se descarta', $thinkOpen['content'] === '' && $thinkOpen['thinking'] !== '');
    check('think: texto normal intacto', llm_strip_thinking('Solo respuesta')['content'] === 'Solo respuesta');
    check('think: sin etiquetas no inventa razonamiento', llm_strip_thinking('Solo respuesta')['thinking'] === '');

    $jsonPlain = llm_extract_json('{"a":1,"b":[1,2]}');
    check('json: objeto directo', $jsonPlain['found'] && $jsonPlain['data']['a'] === 1);
    $jsonFence = llm_extract_json("Aquí tienes:\n```json\n{\"veredicto\":\"ataque\"}\n```\nFin.");
    check('json: tolera vallas y texto', $jsonFence['found'] && $jsonFence['data']['veredicto'] === 'ataque');
    $jsonNested = llm_extract_json('bla {"a":{"b":[{"c":"}"}]}} bla');
    check('json: objeto anidado equilibrado', $jsonNested['found'] && $jsonNested['data']['a']['b'][0]['c'] === '}');
    check('json: lista', llm_extract_json('[1,2,3]')['data'] === [1, 2, 3]);
    check('json: sin JSON', !llm_extract_json('No hay datos estructurados')['found']);
    check('json: vacío', !llm_extract_json('   ')['found']);

    // ============================================================
    // 9 - Ajuste universal a la ventana del modelo
    // ============================================================
    $fitNoWindow = llm_window_fit('sys', 'user', 500, 0);
    check('ventana: sin ventana no recorta', !$fitNoWindow['clipped'] && $fitNoWindow['max_tokens'] === 500);
    check('ventana: estima el prompt', $fitNoWindow['prompt_tokens'] > 0);

    $fitOut = llm_window_fit('sys', str_repeat('x', 200), 2000, 1000);
    check('ventana: recorta la salida', $fitOut['clipped'] && $fitOut['max_tokens'] < 2000, 'max=' . $fitOut['max_tokens']);
    check('ventana: prompt + salida cabe', $fitOut['prompt_tokens'] + $fitOut['max_tokens'] <= 1000);
    check('ventana: avisa del ajuste', $fitOut['notice'] !== '');

    $fitBody = llm_window_fit('sys', str_repeat('palabra ', 2000), 800, 600);
    check('ventana: recorta el cuerpo', $fitBody['clipped'] && llm_str_len($fitBody['user']) < 8000, 'len=' . llm_str_len($fitBody['user']));
    check('ventana: marca el recorte en el texto', str_contains($fitBody['user'], 'contexto recortado'));
    check('ventana: el system no se toca', $fitBody['system'] === 'sys');

    // La salida se protege aunque el prompt sea grande: un modelo con
    // razonamiento necesita margen o gasta todo pensando y no responde.
    $fitBig = llm_window_fit('sys', str_repeat('dato ', 4000), 900, 4096);
    check('ventana: la salida no baja de 256', $fitBig['max_tokens'] >= 256, 'max=' . $fitBig['max_tokens']);
    check('ventana: protege hasta el 40% de la ventana', $fitBig['max_tokens'] <= (int)floor(4096 * 0.40) || $fitBig['max_tokens'] === 900, 'max=' . $fitBig['max_tokens']);
    $fitSmall = llm_window_fit('sys', 'user', 4000, 1024);
    check('ventana: tope de salida por ventana', $fitSmall['max_tokens'] <= 410, 'max=' . $fitSmall['max_tokens']);
    check('ventana: avisa del tope', $fitSmall['clipped'] && $fitSmall['notice'] !== '');

    // ============================================================
    // 9 bis - Detección de razonamiento y hosts cloud
    // ============================================================
    check('razonamiento: qwen3', llm_model_is_reasoning('qwen3.8-4b-q4_k_m'));
    check('razonamiento: deepseek-r1', llm_model_is_reasoning('deepseek-r1:14b'));
    check('razonamiento: gpt-oss', llm_model_is_reasoning('gpt-oss:20b'));
    check('razonamiento: lfm2.5', llm_model_is_reasoning('LFM2.5-24B-A2B'));
    check('razonamiento: llama normal no', !llm_model_is_reasoning('llama3.1:8b'));
    check('razonamiento: ministral no', !llm_model_is_reasoning('Ministral-3B-Instruct'));
    check('cloud: api.openai.com', llm_is_cloud_host('https://api.openai.com/v1'));
    check('cloud: ollama.com', llm_is_cloud_host('https://ollama.com'));
    check('cloud: localhost no', !llm_is_cloud_host('http://localhost:11434'));
    check('cloud: IP privada no', !llm_is_cloud_host('http://10.0.0.198:8080/v1'));
    check('cloud: vacío no', !llm_is_cloud_host(''));

    // ============================================================
    // 10 - Fachadas comunes (llm_run / llm_run_json / llm_run_detached)
    // ============================================================
    check('fachada: llm_run existe', function_exists('llm_run'));
    check('fachada: llm_run_json existe', function_exists('llm_run_json'));
    check('fachada: llm_run_detached existe', function_exists('llm_run_detached'));
    check('fachada: finish_response existe', function_exists('finish_response'));
    check('tareas: catálogo incluye triaje', array_key_exists('incident_triage', llm_task_catalog()));
    check('tareas: catálogo incluye equipos expuestos', array_key_exists('exposed_report', llm_task_catalog()));
    check('tareas: catálogo incluye asistente', array_key_exists('remediation_assistant', llm_task_catalog()));

    // ============================================================
    // 11 - Segmentos de código y traducciones rotas
    // ============================================================
    $inlineKql = "`DeviceNetworkEvents`\n`| where TimeGenerated > ago(7d)`";
    $wrappedKql = llm_code_segment_markdown($inlineKql);
    check('código: envuelve KQL en línea', str_starts_with($wrappedKql, '```kql'), $wrappedKql);
    check('código: conserva las líneas', substr_count($wrappedKql, "\n") >= 2);
    check('código: quita los acentos graves sueltos', !str_contains($wrappedKql, '`DeviceNetworkEvents`'));
    check('código: no rompe los guiones bajos', str_contains($wrappedKql, 'TimeGenerated'));

    $letKql = "let known_files = DeviceNetworkEvents\n| where InitiatingProcessFileName has \"curl\"";
    $wrappedLet = llm_code_segment_markdown($letKql);
    check('código: detecta KQL con let', str_starts_with($wrappedLet, '```kql'), $wrappedLet);
    check('código: conserva known_files', str_contains($wrappedLet, 'known_files'));

    $fenced = "```kql\nDeviceProcessEvents\n```";
    check('código: un bloque con valla no se toca', llm_code_segment_markdown($fenced) === $fenced);
    check('código: la prosa no se envuelve', llm_code_segment_markdown('Texto normal en español.') === 'Texto normal en español.');
    $indented = "    Get-ChildItem -Path C:\\Temp\n    Remove-Item C:\\Temp\\x";
    check('código: código indentado se envuelve', str_starts_with(llm_code_segment_markdown($indented), "```\n"), llm_code_segment_markdown($indented));

    check('traducción rota: detecta el cartel', ai_translation_is_broken("Hola\n\n[bloque 3 sin traducir]\n\nFin"));
    check('traducción rota: texto normal no', !ai_translation_is_broken("Hola\n\nMundo"));
    check('traducción rota: vacío no', !ai_translation_is_broken(''));
} catch (Throwable $e) {
    check('excepción inesperada: ' . $e->getMessage(), false, $e->getFile() . ':' . $e->getLine());
}

echo PHP_EOL . ($total - $fail) . '/' . $total . ' OK' . PHP_EOL;
exit($fail === 0 ? 0 : 1);
