<?php
/**
 * LLM falso para el E2E del triaje de Incidentes Story.
 *
 * Responde a cualquier POST con una completion OpenAI/Ollama-compatible cuyo
 * contenido es el JSON estructurado que espera el módulo. No usa red externa.
 *
 * Guarda cada petición en `sys_get_temp_dir()/entraid-fake-llm-calls.log` con
 * su tipo (`chunk`, `merge` o `single`) y el tamaño del prompt, para que el
 * E2E compruebe que un caso grande se analiza POR PARTES (varias llamadas) y
 * no en una sola.
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

$triage = [
    'resumen_ejecutivo'          => 'PowerShell ejecutó un script de descubrimiento desde el perfil del usuario.',
    'cadena_de_eventos'          => 'explorer.exe (100) inició powershell.exe (101) con -enc; después se ejecutó un script.',
    'hipotesis_principal'        => 'Actividad de reconocimiento legítima o malware inicial; falta contexto del padre.',
    'veredicto_asistido'         => 'sospechosa',
    'confianza_pct'              => 63,
    'tecnicas_attck'             => ['T1059.001', 'T1082'],
    'indicadores_benignos'       => ['Ruta de sistema de PowerShell'],
    'indicadores_maliciosos'     => ['Command line codificada (-enc)'],
    'datos_faltantes'            => ['Usuario que inició explorer.exe'],
    'acciones_recomendadas'      => ['Revisar el equipo', 'Extraer el script decodificado'],
    'clasificacion_defender_sugerida' => [
        'classification' => 'truePositive',
        'determination'  => 'SuspiciousActivity',
    ],
    'preguntas_para_el_analista' => ['¿El usuario reconoce la ejecución?'],
];

/* --- Traza de llamadas (para el E2E) --------------------------------- */

$raw = file_get_contents('php://input') ?: '';
$body = json_decode($raw, true);
$body = is_array($body) ? $body : [];
$prompt = '';
foreach ((array)($body['messages'] ?? []) as $m) {
    if (is_array($m) && (string)($m['role'] ?? '') === 'user') {
        $prompt = (string)($m['content'] ?? '');
    }
}

$kind = 'single';
if (str_contains($prompt, 'EVENTOS NORMALIZADOS')) {
    $kind = 'chunk';
} elseif (str_contains($prompt, 'ANÁLISIS PARCIALES DE LA EVIDENCIA')) {
    $kind = 'merge';
}

if (trim($prompt) !== '') {
    @file_put_contents(
        sys_get_temp_dir() . '/entraid-fake-llm-calls.log',
        json_encode([
            'kind'   => $kind,
            'len'    => strlen($prompt),
            'model'  => $body['model'] ?? null,
            'stream' => $body['stream'] ?? null,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL,
        FILE_APPEND
    );
}

$content = json_encode($triage, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

// Las PARTES devuelven un objeto parcial (como haría un modelo real): el
// esquema es más corto que el del triaje final.
if (str_contains($prompt, 'EVENTOS NORMALIZADOS')) {
    $content = (string)json_encode([
        'parte'              => '1',
        'rango_eventos'      => '1-10',
        'resumen_parcial'    => 'PowerShell ejecutó un script de descubrimiento desde el perfil del usuario.',
        'cadena_de_eventos'  => 'powershell.exe iniciado por el usuario; después ejecutó un script.',
        'hipotesis_parcial'  => 'Reconocimiento legítimo o malware inicial.',
        'veredicto_parcial'  => 'sospechosa',
        'confianza_pct'      => 60,
        'tecnicas_attck'     => ['T1059.001'],
        'indicadores_maliciosos' => ['Command line codificada (-enc)'],
        'datos_faltantes'    => ['Usuario que inició explorer.exe'],
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

// Modo «el modelo se desvía»: en la fusión devuelve solo una lista de
// técnicas (ni resumen ni veredicto). Sirve para comprobar que la app NO
// guarda eso como triaje y monta el informe de emergencia.
$esFusion = str_contains($prompt, 'ANÁLISIS PARCIALES DE LA EVIDENCIA');
if ($esFusion && str_contains($prompt, 'TRIGGER-LIST')) {
    $content = (string)json_encode(['T1021.001', 'T1059.001', 'T1003'], JSON_UNESCAPED_UNICODE);
}

echo json_encode([
    'model'      => 'e2e-fake-model',
    'created_at' => gmdate('c'),
    'message'    => ['role' => 'assistant', 'content' => $content],
    'done'       => true,
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
