<?php
/**
 * LLM falso para el E2E del triaje de Incidentes Story.
 *
 * Responde a cualquier POST con una completion OpenAI-compatible cuyo
 * contenido es el JSON estructurado que espera el módulo. No usa red externa.
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

$content = json_encode($triage, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

echo json_encode([
    'model'      => 'e2e-fake-model',
    'created_at' => gmdate('c'),
    'message'    => ['role' => 'assistant', 'content' => $content],
    'done'       => true,
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
