<?php
/**
 * Smoke test — motor de IA por partes (includes/llm_pipeline.php).
 *
 * Sin red y sin IA real: las llamadas al modelo se inyectan con `map_call` y
 * `reduce_call`, así se prueba la orquestación (partes, reducción jerárquica,
 * fallos, división por timeout y reanudación) de forma determinista.
 *
 * Uso: php tools/smoke/llm-pipeline.php
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/public_html/config/bootstrap.php';

$fail = 0;
$total = 0;

function check(string $label, bool $ok, string $detail = ''): void
{
    global $fail, $total;
    $total++;
    if ($ok) {
        echo "OK   {$label}\n";
        return;
    }
    $fail++;
    echo "FALLA {$label}" . ($detail !== '' ? "\n     {$detail}" : '') . "\n";
}

/* =====================================================================
 * 1. Normalización de partes
 * ================================================================== */

$parts = llm_pipeline_normalize_parts(['uno', ['text' => 'dos'], ['text' => '   '], ['sin_texto' => 1]]);
check('normaliza strings y arrays', count($parts) === 2, 'total=' . count($parts));
check('conserva el campo text', (($parts[0]['text'] ?? '') === 'uno') && (($parts[1]['text'] ?? '') === 'dos'));
check('descarta partes vacías', count(llm_pipeline_normalize_parts(['', '  '])) === 0);

/* =====================================================================
 * 2. Fusión local (sin IA)
 * ================================================================== */

$merged = llm_pipeline_merge_local([
    ['veredicto_asistido' => 'sospechosa', 'confianza_pct' => 40, 'tecnicas_attck' => ['T1059']],
    ['confianza_pct' => 70, 'tecnicas_attck' => ['T1059', 'T1082'], 'datos_faltantes' => ['padre']],
], 'json');
check('local json: conserva la primera clave', (($merged['data']['veredicto_asistido'] ?? '') === 'sospechosa'));
check('local json: confianza máxima', (int)($merged['data']['confianza_pct'] ?? 0) === 70);
check('local json: listas sin duplicados', ($merged['data']['tecnicas_attck'] ?? []) === ['T1059', 'T1082']);
check('local json: une claves nuevas', ($merged['data']['datos_faltantes'] ?? []) === ['padre']);

$lista = llm_pipeline_merge_local([['a'], ['b', 'c']], 'json');
check('local json: listas de listas', ($lista['data'] ?? []) === ['a', 'b', 'c']);

$texto = llm_pipeline_merge_local(["## Parte 1\nalfa", '## Parte 2\nbeta'], 'text');
check('local text: concatena fragmentos', str_contains((string)$texto['content'], 'alfa') && str_contains((string)$texto['content'], 'beta'));

check('etiqueta numérica de parte', llm_pipeline_part_label('0') === '1');
check('etiqueta de subparte', llm_pipeline_part_label('0a') === '0a');

/* =====================================================================
 * 3. Orquestación: map + reduce jerárquico
 * ================================================================== */

$llamadasMap = 0;
$llamadasReduce = 0;
$parciales = [];

$res = llm_pipeline_run([
    'mode'  => 'json',
    'parts' => ['p1', 'p2', 'p3', 'p4'],
    'reduce_group' => 2,
    'map_call' => function (array $part, string $key, int $total) use (&$llamadasMap, &$parciales): array {
        $llamadasMap++;
        $parciales[] = $part['text'];
        return [
            'success' => true,
            'data'    => ['resumen' => 'resumen de ' . $part['text'], 'tecnicas_attck' => ['T' . strlen($part['text'])]],
            'content' => '{}',
            'model'   => 'fake-model',
        ];
    },
    'reduce_call' => function (array $chunk, int $nivel) use (&$llamadasReduce): array {
        $llamadasReduce++;
        $resumen = [];
        foreach ($chunk as $item) {
            $resumen[] = is_array($item) ? (string)($item['resumen'] ?? '') : '';
        }
        return [
            'success' => true,
            'data'    => ['resumen' => implode(' | ', $resumen), 'nivel' => $nivel],
            'content' => '{}',
        ];
    },
]);

check('4 map + 3 reduce (jerárquico)', $llamadasMap === 4 && $llamadasReduce === 3, "map={$llamadasMap} reduce={$llamadasReduce}");
check('reduce devuelve la fusión', !empty($res['success']) && str_contains((string)($res['data']['resumen'] ?? ''), 'resumen de p1'));
check('cuenta partes', (int)$res['parts'] === 4);
check('sin fallos', (int)$res['failed'] === 0);
check('modelo propagado', ($res['model'] ?? '') === 'fake-model');
check('orden de las partes', $parciales === ['p1', 'p2', 'p3', 'p4']);

/* =====================================================================
 * 4. Una parte falla: no se pierde el resto
 * ================================================================== */

$res = llm_pipeline_run([
    'mode'  => 'json',
    'parts' => ['buena', 'mala'],
    'reduce_group' => 4,
    'map_call' => static function (array $part): array {
        if (($part['text'] ?? '') === 'mala') {
            return ['success' => false, 'error' => 'HTTP 500 del proveedor'];
        }
        return ['success' => true, 'data' => ['resumen' => 'ok'], 'content' => '{}'];
    },
    'reduce_call' => static function (array $chunk): array {
        return ['success' => true, 'data' => ['resumen' => 'fusion'], 'content' => '{}'];
    },
]);

check('con una parte fallida sigue habiendo resultado', !empty($res['success']));
check('un fallo contabilizado', (int)$res['failed'] === 1);
check('aviso del fallo', count((array)$res['warnings']) >= 1);

/* =====================================================================
 * 5. Todas fallan → error
 * ================================================================== */

$res = llm_pipeline_run([
    'mode'  => 'json',
    'parts' => ['a', 'b'],
    'map_call' => static fn(): array => ['success' => false, 'error' => 'Tiempo de espera agotado con custom.'],
]);

check('si fallan todas no hay éxito', empty($res['success']));
check('se devuelve el error real', str_contains((string)$res['error'], 'Tiempo de espera agotado'));

/* =====================================================================
 * 6. Timeout en una parte: se divide en dos y se reintenta
 * ================================================================== */

$intentos = [];
$res = llm_pipeline_run([
    'mode'  => 'json',
    'parts' => [['text' => 'a|b|c|d', 'eventos' => ['a', 'b', 'c', 'd']]],
    'max_reduce_levels' => 1,
    'map_call' => function (array $part, string $key) use (&$intentos): array {
        $eventos = (array)($part['eventos'] ?? []);
        $intentos[] = $key . ':' . count($eventos);
        if (count($eventos) > 2) {
            return ['success' => false, 'error' => 'cURL error 28: Operation timed out after 120000 milliseconds'];
        }
        return ['success' => true, 'data' => ['resumen' => 'sub ' . $key], 'content' => '{}'];
    },
    'split' => static function (array $part): array {
        $eventos = array_values((array)($part['eventos'] ?? []));
        if (count($eventos) < 2) {
            return [];
        }
        $mitad = intdiv(count($eventos) + 1, 2);
        return [
            ['text' => 'sub-a', 'eventos' => array_slice($eventos, 0, $mitad)],
            ['text' => 'sub-b', 'eventos' => array_slice($eventos, $mitad)],
        ];
    },
]);

check('la parte se reintenta dividida', in_array('0a:2', $intentos, true) && in_array('0b:2', $intentos, true), implode(',', $intentos));
check('la división no pierde el resultado', !empty($res['success']) && (int)$res['failed'] === 0);
check('la división avisa', count((array)$res['warnings']) >= 1);

/* =====================================================================
 * 7. Reanudación: lo ya resuelto no se repite
 * ================================================================== */

$llamadas = [];
$res = llm_pipeline_run([
    'mode'  => 'json',
    'parts' => ['p1', 'p2'],
    'map_call' => function (array $part) use (&$llamadas): array {
        $llamadas[] = $part['text'];
        return ['success' => true, 'data' => ['resumen' => 'nuevo ' . $part['text']], 'content' => '{}'];
    },
    'load_part' => static fn(string $key): ?array => $key === '0' ? ['data' => ['resumen' => 'guardado']] : null,
    'reduce_call' => static fn(array $chunk): array => [
        'success' => true,
        'data'    => ['resumen' => implode(' | ', array_map(static fn($i) => (string)($i['resumen'] ?? ''), $chunk))],
        'content' => '{}',
    ],
]);

check('no se repite la parte ya guardada', $llamadas === ['p2'], implode(',', $llamadas));
check('la parte guardada entra en la fusión', str_contains((string)($res['data']['resumen'] ?? ''), 'guardado'));

/* =====================================================================
 * 8. Modo texto
 * ================================================================== */

$res = llm_pipeline_run([
    'mode'  => 'text',
    'parts' => ['x', 'y'],
    'map_call' => static fn(array $part): array => [
        'success' => true,
        'content' => '## ' . $part['text'],
    ],
    'reduce_call' => static function (array $chunk): array {
        return ['success' => true, 'content' => implode("\n\n", array_map('strval', $chunk))];
    },
]);

check('modo texto: éxito', !empty($res['success']));
check('modo texto: fusiona', str_contains((string)$res['content'], '## x') && str_contains((string)$res['content'], '## y'));

/* =====================================================================
 * 9. Si el reduce falla, se fusiona en local
 * ================================================================== */

$res = llm_pipeline_run([
    'mode'  => 'json',
    'parts' => ['a', 'b'],
    'map_call' => static fn(array $part): array => [
        'success' => true,
        'data'    => ['resumen' => 'r-' . $part['text'], 'tecnicas_attck' => ['T' . $part['text']]],
        'content' => '{}',
    ],
    'reduce_call' => static fn(): array => ['success' => false, 'error' => 'fallo de fusión'],
]);

check('reduce fallido no rompe el resultado', !empty($res['success']));
check('reduce fallido se une en local', str_contains((string)($res['data']['resumen'] ?? ''), 'r-a'));
check('reduce fallido se avisa', count((array)$res['warnings']) >= 1);

echo "\n";
if ($fail > 0) {
    echo "RESULTADO: {$fail} de {$total} comprobaciones fallidas\n";
    exit(1);
}
echo "RESULTADO: {$total}/{$total} OK\n";
