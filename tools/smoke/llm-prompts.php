<?php
/**
 * llm-prompts.php — Pruebas del registro de prompts editables.
 *
 *   php tools/smoke/llm-prompts.php
 *
 * Verifica el catálogo, los helpers (default/personalización/bloqueo/reset),
 * la integración real con CveReportAi y que ninguna llamada del código use
 * una clave inexistente. Limpia al terminar.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    echo ($ok ? 'OK   ' : 'FALLO ') . $label . (!$ok && $detail !== '' ? ' — ' . $detail : '') . PHP_EOL;
    if (!$ok) { $fail++; }
}

$created = [];

try {
    // ============================================================
    // 1 · Catálogo
    // ============================================================
    $catalog = llm_prompts_catalog();
    check('catálogo con prompts', count($catalog) >= 20, 'total=' . count($catalog));

    $emptyDefaults = [];
    $fieldsOk = true;
    foreach ($catalog as $key => $meta) {
        if (trim((string)($meta['default'] ?? '')) === '') { $emptyDefaults[] = $key; }
        foreach (['scope', 'scope_label', 'label', 'description'] as $f) {
            if (trim((string)($meta[$f] ?? '')) === '') { $fieldsOk = false; }
        }
    }
    check('todos los defaults tienen texto', $emptyDefaults === [], implode(', ', $emptyDefaults));
    check('metadatos completos', $fieldsOk);

    $locked = array_keys(array_filter($catalog, fn($m) => !empty($m['is_locked'])));
    check('hay contratos marcados', count($locked) >= 4, 'bloqueados=' . count($locked));

    // ============================================================
    // 2 · Default sin personalización
    // ============================================================
    check('sin personalización devuelve el default',
        llm_prompt('cve.report.system', 'DEFAULT-X') === 'DEFAULT-X');

    // ============================================================
    // 3 · Guardar y leer personalización
    // ============================================================
    $res = llm_prompt_save('cve.report.system', 'PROMPT PERSONALIZADO', 1);
    check('save ok', !empty($res['ok']), json_encode($res));
    $created[] = 'cve.report.system';
    check('lee la personalización',
        llm_prompt('cve.report.system', 'DEFAULT-X') === 'PROMPT PERSONALIZADO');

    // ============================================================
    // 4 · Contratos bloqueados
    // ============================================================
    $res = llm_prompt_save('cve.report.format', 'INTENTO DE CAMBIO');
    check('contrato rechazado', empty($res['ok']));
    $lockedDefault = (string)$catalog['cve.report.format']['default'];
    check('contrato sigue usando el default',
        llm_prompt('cve.report.format', $lockedDefault) === $lockedDefault);

    // ============================================================
    // 5 · Validaciones
    // ============================================================
    check('vacío rechazado', empty(llm_prompt_save('cve.report.system', '   ')['ok']));
    check('clave desconocida rechazada', empty(llm_prompt_save('no.existe', 'X')['ok']));

    // ============================================================
    // 6 · Restaurar
    // ============================================================
    $res = llm_prompt_reset('cve.report.system');
    check('reset ok', !empty($res['ok']), json_encode($res));
    $created = array_values(array_diff($created, ['cve.report.system']));
    check('tras reset vuelve el default',
        llm_prompt('cve.report.system', 'DEFAULT-X') === 'DEFAULT-X');

    // ============================================================
    // 7 · Grupos y marcadores
    // ============================================================
    $quick = llm_prompt_group('remediation.quick.');
    check('grupo remediation.quick con 5 entradas', count($quick) === 5, 'total=' . count($quick));
    check('grupo devuelve textos', trim((string)reset($quick)) !== '');

    check('sustitución de {cve_id}',
        llm_prompt('cve.item.intro', 'Analiza {cve_id}', ['{cve_id}' => 'CVE-2026-0001']) === 'Analiza CVE-2026-0001');

    // ============================================================
    // 8 · Integración real con el informe CVE
    // ============================================================
    $defaultSystem = CveReportAi::systemPrompt();
    check('systemPrompt usa el default', str_contains($defaultSystem, 'analista sénior'));

    llm_prompt_save('cve.report.system', 'SYSTEM EDITADO', 1);
    $created[] = 'cve.report.system';
    check('systemPrompt refleja la edición', CveReportAi::systemPrompt() === 'SYSTEM EDITADO');
    check('itemSystemPrompt sigue con su default', str_contains(CveReportAi::itemSystemPrompt(), 'gestión de parches'));

    $prompt = CveReportAi::itemPrompt([
        'cve_id' => 'CVE-2026-1111',
        'published_at' => '2026-10-01',
        'cvss' => 9.8,
        'severity' => 'critical',
        'vector' => 'NETWORK',
        'description' => 'Prueba',
        'epss' => 0.5,
        'kev' => 1,
        'kev_added' => '2026-10-02',
        'kev_ransomware' => 'Known',
        'kev_action' => 'Parchear',
        'github' => [],
        'exploits' => ['items' => []],
        'priority' => 'P1',
        'references' => [],
    ]);
    check('itemPrompt incluye el CVE', str_contains($prompt, 'CVE-2026-1111'));
    check('itemPrompt conserva el contrato de 6 secciones', str_contains($prompt, '6. Detección, verificación y prioridad'));

    // ============================================================
    // 9 · Sin claves huérfanas en el código
    // ============================================================
    $root = dirname(__DIR__, 2) . '/public_html';
    $orphans = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        if ($f->getExtension() !== 'php') { continue; }
        $src = file_get_contents($f->getPathname());
        if (preg_match_all("/llm_prompt\('([^']+)'/", $src, $m)) {
            foreach ($m[1] as $key) {
                if (!isset($catalog[$key])) { $orphans[] = basename($f->getPathname()) . ':' . $key; }
            }
        }
        if (preg_match_all("/llm_prompt_group\('([^']+)'/", $src, $m)) {
            foreach ($m[1] as $prefix) {
                $found = false;
                foreach (array_keys($catalog) as $key) {
                    if (str_starts_with($key, $prefix)) { $found = true; break; }
                }
                if (!$found) { $orphans[] = basename($f->getPathname()) . ':grupo ' . $prefix; }
            }
        }
    }
    check('sin claves huérfanas', $orphans === [], implode(', ', $orphans));

    // ============================================================
    // 10 · Todos los prompts del catálogo son alcanzables por la UI
    // ============================================================
    $all = llm_prompts_all();
    check('llm_prompts_all cubre el catálogo', count($all) === count($catalog));
    $missingText = [];
    foreach ($all as $key => $row) {
        if (trim((string)($row['text'] ?? '')) === '') { $missingText[] = $key; }
    }
    check('todos tienen texto efectivo', $missingText === [], implode(', ', $missingText));

    // ============================================================
    // 11 · Integración en el módulo IA (prompts capturados)
    // ============================================================
    $capture = new class extends Module_Llm {
        public array $seen = [];
        public function chat(string $systemPrompt, string $userPrompt, array $options = [], ?int $profileId = null): array
        {
            $this->seen[] = ['system' => $systemPrompt, 'user' => $userPrompt];
            return ['success' => false, 'error' => 'capture'];
        }
    };

    $capture->extractIocs('texto de prueba');
    $extractSystem = (string)($capture->seen[0]['system'] ?? '');
    check('extractIocs usa el default del catálogo',
        $extractSystem === (string)$catalog['llm.ioc.extract.system']['default'],
        'len=' . strlen($extractSystem));

    $capture->classifyIocs(0, 5);
    $classifySystem = (string)($capture->seen[1]['system'] ?? '');
    check('classifyIocs incluye el formato JSON',
        str_contains($classifySystem, 'JSON array') && str_contains($classifySystem, 'Clasifica cada IOC'));

    // Personalización visible en el módulo IA
    llm_prompt_save('llm.ioc.extract.system', 'EXTRACT EDITADO', 1);
    $created[] = 'llm.ioc.extract.system';
    $capture2 = new class extends Module_Llm {
        public array $seen = [];
        public function chat(string $systemPrompt, string $userPrompt, array $options = [], ?int $profileId = null): array
        {
            $this->seen[] = ['system' => $systemPrompt];
            return ['success' => false, 'error' => 'capture'];
        }
    };
    $capture2->extractIocs('texto');
    // Los contratos bloqueados ignoran la personalización aunque exista una fila.
    check('contrato bloqueado ignora la fila guardada',
        (string)($capture2->seen[0]['system'] ?? '') === (string)$catalog['llm.ioc.extract.system']['default']);
} finally {
    foreach ($created as $key) {
        try { llm_prompt_reset($key); } catch (Throwable $e) {}
    }
    // Limpieza de seguridad: no dejar personalizaciones de prueba.
    try { Database::query("DELETE FROM llm_prompts WHERE template IN ('PROMPT PERSONALIZADO', 'SYSTEM EDITADO', 'INTENTO DE CAMBIO')"); } catch (Throwable $e) {}
}

echo PHP_EOL . ($fail === 0 ? 'RESULTADO: OK (' . $total . ' comprobaciones)' : "RESULTADO: {$fail} de {$total} fallidas") . PHP_EOL;
exit($fail === 0 ? 0 : 1);
