<?php
/**
 * LLM falso para el E2E de Equipos expuestos.
 *
 * Responde a cualquier POST con una completion estilo Ollama cuyo contenido es
 * un informe Markdown de prueba. Antes de responder inspecciona el prompt
 * recibido para que el test pueda comprobar qué se envió:
 *
 *   - "Modo detectado: compacto|detallado"  (detecta el JSON de especificación)
 *   - "CSV recibido: sí|no"                 (busca un servidor del CSV)
 *   - "KQL recibida: sí|no"                 (solo en modo detallado)
 *
 * No usa red externa.
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

$raw = (string)file_get_contents('php://input');
$decoded = json_decode($raw, true);

$prompt = '';
if (is_array($decoded) && is_array($decoded['messages'] ?? null)) {
    foreach ($decoded['messages'] as $message) {
        $prompt .= (string)($message['content'] ?? '') . "\n";
    }
}
if (trim($prompt) === '') {
    $prompt = $raw;
}

$detailed = str_contains($prompt, 'instrucciones_para_la_ia');
$hasCsv = str_contains($prompt, 'srv01.contoso.com');
$hasKql = str_contains($prompt, 'DeviceTvmSoftwareVulnerabilities');
$hasCveBlock = str_contains($prompt, 'Datos de los CVE con exploit público');
$customSpec = str_contains($prompt, 'MARCADOR-E2E');

$report = "# Informe de parcheo (prueba)\n\n"
    . "- Modo detectado: " . ($detailed ? 'detallado' : 'compacto') . "\n"
    . "- CSV recibido: " . ($hasCsv ? 'sí' : 'no') . "\n"
    . "- KQL recibida: " . ($hasKql ? 'sí' : 'no') . "\n"
    . "- Bloque de CVE: " . ($hasCveBlock ? 'sí' : 'no') . "\n"
    . "- JSON personalizado: " . ($customSpec ? 'sí' : 'no') . "\n"
    . "- Longitud del prompt: " . strlen($prompt) . "\n\n"
    . "## Resumen\n\n"
    . "Dos servidores expuestos, uno con exploit público y 64 días sin parchear.\n\n"
    . "## Tabla\n\n"
    . "| Servidor | Exposición | Exploits públicos | CVEs críticos | Días sin parchear | Primer KB a aplicar |\n"
    . "|---|---|---|---|---|---|\n"
    . "| srv01.contoso.com | High | 3 | 18 | 64 | October 2026 Security Updates |\n"
    . "| srv02.contoso.com | Medium | 0 | 1 | 1 | November 2026 Security Updates |\n\n"
    . "## Top 3 acciones\n\n"
    . "1. Parchear srv01.contoso.com con el ciclo de octubre.\n"
    . "2. Revisar srv02.contoso.com.\n"
    . "3. Verificar el ciclo mensual de parcheo.\n";

echo json_encode([
    'model'      => 'e2e-fake-report',
    'created_at' => gmdate('c'),
    'message'    => ['role' => 'assistant', 'content' => $report],
    'done'       => true,
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
