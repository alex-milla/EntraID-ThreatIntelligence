<?php
/**
 * llm_pipeline.php — IA por partes (map-reduce) para contextos grandes.
 *
 * Un modelo local no puede con una petición de 16k tokens de entrada y 2.500
 * de salida dentro del timeout del perfil: la corta. Este motor parte el
 * contexto en trozos, analiza cada trozo por separado (map) y fusiona los
 * resultados en una respuesta final (reduce), de forma que el tiempo total
 * puede ser largo sin que ninguna llamada suelta lo sea.
 *
 * Reglas de la casa:
 *   · La IA pasa SIEMPRE por las fachadas de helpers.php (llm_run /
 *     llm_run_json): aquí no se duplican timeouts, ventanas ni parseos.
 *   · Una parte que falla no tira el trabajo: se reintenta partiéndola en dos
 *     si el fallo es un timeout, y si no, se anota y se sigue.
 *   · El reduce es jerárquico: agrupa los parciales de N en N para que el
 *     prompt de fusión nunca desborde la ventana del modelo.
 *   · Si el reduce falla, se fusiona en local (sin IA): mejor una respuesta
 *     ensamblada que perder todo el análisis.
 *
 * Modos:
 *   · `json` — cada parte devuelve un objeto JSON; la fusión la redacta el
 *     modelo y, si no puede, se combinan las claves en local.
 *   · `text` — cada parte devuelve Markdown; la fusión la redacta el modelo y,
 *     si no puede, se concatenan los fragmentos.
 *
 * Uso mínimo:
 *   llm_pipeline_run([
 *       'mode'          => 'json',
 *       'task'          => 'incident_triage',
 *       'profile_id'    => 3,
 *       'header'        => '...contexto común...',
 *       'parts'         => [['text' => '...'], ['text' => '...']],
 *       'system_map'    => '...',
 *       'user_map'      => "CONTEXTO:\n{header}\n\nPARTE {parte_num}/{parte_total}:\n{parte}",
 *       'system_reduce' => '...',
 *       'user_reduce'   => "PARCIALES:\n{resultados}",
 *       'options'       => ['max_tokens_map' => 700, 'max_tokens_reduce' => 1500, 'think' => false],
 *   ]);
 */

declare(strict_types=1);

if (!function_exists('llm_pipeline_normalize_parts')) {
    /**
     * Normaliza las partes a arrays con `text`. Se aceptan strings y arrays
     * (los arrays permiten que el módulo guarde los datos de origen para
     * poder partir una parte por la mitad si el modelo la corta).
     *
     * @param array<int,mixed> $parts
     * @return array<int,array<string,mixed>>
     */
    function llm_pipeline_normalize_parts(array $parts): array
    {
        $out = [];
        foreach ($parts as $part) {
            if (is_array($part)) {
                if (!isset($part['text'])) {
                    $part['text'] = '';
                }
                $part['text'] = (string)$part['text'];
                if (trim($part['text']) === '') {
                    continue;
                }
                $out[] = $part;
                continue;
            }
            $text = (string)$part;
            if (trim($text) === '') {
                continue;
            }
            $out[] = ['text' => $text];
        }
        return $out;
    }
}

if (!function_exists('llm_pipeline_list_merge')) {
    /**
     * Une dos listas (técnicas, acciones, indicadores…) sin duplicar las
     * escalares. Las listas de arrays se concatenan tal cual.
     *
     * @param array<int|string,mixed> $a
     * @param array<int|string,mixed> $b
     * @return array<int|string,mixed>
     */
    function llm_pipeline_list_merge(array $a, array $b): array
    {
        $out = $a;
        foreach ($b as $value) {
            if (is_scalar($value) || $value === null) {
                $exists = false;
                foreach ($out as $current) {
                    if (is_scalar($current) && (string)$current === (string)$value) {
                        $exists = true;
                        break;
                    }
                }
                if ($exists) {
                    continue;
                }
            }
            $out[] = $value;
        }
        return array_values($out);
    }
}

if (!function_exists('llm_pipeline_part_label')) {
    /** Etiqueta legible de una parte (1, 2…) también para subdivisiones (2a, 2b). */
    function llm_pipeline_part_label(string $key): string
    {
        return ctype_digit($key) ? (string)((int)$key + 1) : $key;
    }
}

if (!function_exists('llm_pipeline_merge_local')) {
    /**
     * Fusión local de parciales, sin IA. Último recurso del reduce.
     *
     * @param array<int,mixed> $items Parciales: arrays (json) o strings (text).
     * @return array{data:mixed,content:string}
     */
    function llm_pipeline_merge_local(array $items, string $mode = 'json'): array
    {
        $items = array_values($items);

        if ($mode === 'text') {
            $text = '';
            foreach ($items as $item) {
                $chunk = is_array($item) ? (string)($item['content'] ?? '') : (string)$item;
                $chunk = trim($chunk);
                if ($chunk === '') {
                    continue;
                }
                $text .= ($text !== '' ? "\n\n" : '') . $chunk;
            }
            return ['data' => null, 'content' => $text];
        }

        $onlyLists = true;
        foreach ($items as $item) {
            if (!is_array($item) || !array_is_list($item)) {
                $onlyLists = false;
                break;
            }
        }
        if ($onlyLists) {
            $list = [];
            foreach ($items as $item) {
                $list = array_merge($list, $item);
            }
            return [
                'data'    => $list,
                'content' => (string)json_encode($list, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            ];
        }

        $merged = [];
        foreach ($items as $item) {
            if (!is_array($item)) {
                continue;
            }
            foreach ($item as $key => $value) {
                if (!array_key_exists($key, $merged)) {
                    $merged[$key] = $value;
                    continue;
                }
                $current = $merged[$key];
                if (is_array($current) && is_array($value)) {
                    $merged[$key] = llm_pipeline_list_merge($current, $value);
                } elseif (is_string($current) && is_string($value)) {
                    $value = trim($value);
                    if ($value !== '' && !str_contains($current, $value)) {
                        $merged[$key] = trim($current . "\n" . $value);
                    }
                } elseif (is_int($current) && is_int($value)) {
                    $merged[$key] = max($current, $value);
                } elseif ((is_int($current) || is_float($current)) && (is_int($value) || is_float($value))) {
                    $merged[$key] = max((float)$current, (float)$value);
                }
                // Tipos distintos: se conserva el valor del primer parcial.
            }
        }

        return [
            'data'    => $merged,
            'content' => (string)json_encode($merged, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ];
    }
}

if (!function_exists('llm_pipeline_run')) {
    /**
     * Ejecuta una tarea de IA por partes y devuelve el resultado fusionado.
     *
     * @param array{
     *   mode?:string, task?:string, profile_id?:int|null,
     *   header?:string, parts?:array,
     *   system_map?:string, user_map?:string,
     *   system_reduce?:string, user_reduce?:string,
     *   options?:array, reduce_group?:int, max_reduce_levels?:int,
     *   map_call?:callable, reduce_call?:callable, split?:callable,
     *   load_part?:callable, save_part?:callable, on_progress?:callable
     * } $spec
     * @return array{
     *   success:bool,content:string,data:mixed,parts:int,failed:int,calls:int,
     *   merged:int,clipped:bool,stopped:string,invalid_format:bool,partials:array,
     *   model:string,elapsed_ms:int,error:string,warnings:array<int,string>
     * }
     */
    function llm_pipeline_run(array $spec): array
    {
        $started = microtime(true);

        $mode  = ((string)($spec['mode'] ?? 'json')) === 'text' ? 'text' : 'json';
        $task  = (string)($spec['task'] ?? 'chat');
        $parts = llm_pipeline_normalize_parts((array)($spec['parts'] ?? []));
        $total = count($parts);

        $out = [
            'success'    => false,
            'content'    => '',
            'data'       => null,
            'parts'      => $total,
            'failed'     => 0,
            'calls'      => 0,
            'merged'     => 0,
            'clipped'    => false,
            'stopped'    => '',
            'invalid_format' => false,
            'partials'   => [],
            'model'      => '',
            'elapsed_ms' => 0,
            'error'      => '',
            'warnings'   => [],
        ];

        if ($total === 0) {
            $out['error'] = 'No hay partes que analizar.';
            return $out;
        }

        $header   = (string)($spec['header'] ?? '');
        $options  = (array)($spec['options'] ?? []);
        $maxMap   = max(64, (int)($options['max_tokens_map'] ?? ($options['max_tokens'] ?? 800)));
        $maxMerge = max(128, (int)($options['max_tokens_reduce'] ?? 1500));
        $profileId = isset($spec['profile_id']) ? (int)$spec['profile_id'] : 0;
        $deadlineSeconds = max(0.0, (float)($spec['deadline_seconds'] ?? 0));
        $minSplitChars   = max(0, (int)($spec['min_split_chars'] ?? 1200));

        $mapCall    = $spec['map_call'] ?? null;
        $reduceCall = $spec['reduce_call'] ?? null;
        $splitPart  = $spec['split'] ?? null;
        $loadPart   = $spec['load_part'] ?? null;
        $savePart   = $spec['save_part'] ?? null;
        $progress   = $spec['on_progress'] ?? null;
        $shouldStop = $spec['should_stop'] ?? null;

        /**
         * Validador de forma. En modo json, un resultado que no sea un objeto
         * (una lista de técnicas, por ejemplo) no es un análisis: se rechaza.
         */
        $validator = $spec['validator'] ?? null;
        if (!is_callable($validator)) {
            $validator = static fn(mixed $value): bool => is_array($value) && $value !== [] && !array_is_list($value);
        }
        $finalValidator = $spec['final_validator'] ?? $validator;
        if (!is_callable($finalValidator)) {
            $finalValidator = $validator;
        }

        // En modo texto el resultado es Markdown (una cadena), no un objeto:
        // el validador de forma solo tiene sentido en JSON.
        $checkPart = $mode === 'json'
            ? $validator
            : static fn(mixed $value): bool => is_string($value) && trim($value) !== '';
        $checkFinal = $mode === 'json' ? $finalValidator : $checkPart;

        /** Recordatorio que se añade al reintentar una respuesta mal formada. */
        $strictSuffix = ' Tu respuesta anterior no tenía el formato pedido. Devuelve SOLO un objeto JSON '
            . 'que empiece por { y termine en }, con las claves indicadas: nada de listas, vallas ni texto alrededor.';

        /** ¿Se agotó el tiempo global del trabajo? */
        $deadlineHit = static function () use ($started, $deadlineSeconds): bool {
            return $deadlineSeconds > 0 && (microtime(true) - $started) > $deadlineSeconds;
        };

        /** ¿El usuario pidió detener el trabajo? */
        $isCancelled = static function () use ($shouldStop): bool {
            return is_callable($shouldStop) && (bool)$shouldStop();
        };

        /** Opciones de una llamada concreta (map o reduce). */
        $callOptions = static function (int $maxTokens) use ($options, $profileId): array {
            $opts = $options;
            unset($opts['max_tokens_map'], $opts['max_tokens_reduce']);
            $opts['max_tokens'] = $maxTokens;
            if (!array_key_exists('think', $opts)) {
                $opts['think'] = false;
            }
            if ($profileId > 0) {
                $opts['profile_id'] = $profileId;
            }
            return $opts;
        };

        /** Llamada a la IA (inyectable para las pruebas). */
        $call = static function (string $system, string $user, int $maxTokens) use ($mode, $task, $callOptions): array {
            $opts = $callOptions($maxTokens);
            return $mode === 'json'
                ? llm_run_json($task, $system, $user, $opts)
                : llm_run($task, $system, $user, $opts);
        };

        /** Contenido de un parcial (array con `data` o texto). */
        $partialValue = static function (array $res, string $mode): mixed {
            if ($mode === 'json') {
                return is_array($res['data'] ?? null) ? $res['data'] : null;
            }
            $content = trim((string)($res['content'] ?? ''));
            return $content === '' ? null : $content;
        };

        /* -------------------------------------------------------------
         * 1) MAP — una llamada por parte, con reanudación y división
         * ---------------------------------------------------------- */

        $partials = [];   // clave => valor del parcial
        $order    = [];   // orden de resolución, para el reduce
        $errors   = [];   // clave => mensaje
        $resolved = [];   // partes del PLAN cerradas (con éxito o fallidas)
        $okCount  = 0;
        $failCount = 0;

        /**
         * Parte del plan a la que pertenece una clave: las subdivisiones
         * ('0a', '0b') cierran la parte original ('0'), no crean una nueva.
         */
        $slotOf = static function (string $key): string {
            return (string)preg_replace('/[a-z]+$/', '', $key);
        };

        /**
         * Publica el avance. El contador cuenta partes RESUELTAS (con éxito o
         * fallidas), no solo los aciertos: antes, un fallo dejaba la ficha
         * clavada en el último número bueno.
         */
        $report = static function (string $fase) use ($progress, &$resolved, $total, &$okCount, &$failCount): void {
            if (!is_callable($progress)) {
                return;
            }
            $progress(min(count($resolved), $total), $total, $fase, [
                'ok'     => $okCount,
                'failed' => $failCount,
            ]);
        };

        $report('Analizando la evidencia');

        $queue = [];
        foreach ($parts as $index => $part) {
            $queue[] = ['key' => (string)$index, 'part' => $part, 'depth' => 0];
        }

        // Reanudación: lo ya analizado en un intento anterior no se repite.
        if (is_callable($loadPart)) {
            $pending = [];
            foreach ($queue as $item) {
                $saved = $loadPart($item['key']);
                if (is_array($saved) && array_key_exists('data', $saved) && $saved['data'] !== null) {
                    $partials[$item['key']] = $saved['data'];
                    $order[] = $item['key'];
                    $okCount++;
                    $resolved[$slotOf($item['key'])] = true;
                    continue;
                }
                $pending[] = $item;
            }
            $queue = $pending;
        }

        // Un solo nivel de división: partir más multiplica la espera (cada
        // intento cuesta el timeout entero) sin ganar fiabilidad.
        $maxSplits = 1;
        $stopped = '';

        while ($queue !== []) {
            if ($isCancelled()) {
                $stopped = 'cancel';
                break;
            }
            if ($deadlineHit()) {
                $stopped = 'deadline';
                break;
            }

            $item = array_shift($queue);
            $partText = (string)$item['part']['text'];

            /** Una llamada de parte. `$strict` reintenta con instrucción de forma. */
            $doMap = function (bool $strict) use ($mapCall, $call, $spec, $header, $partText, $item, $total, $maxMap, $strictSuffix): array {
                if (is_callable($mapCall)) {
                    return $mapCall($item['part'], $item['key'], $total);
                }
                $vars = [
                    '{header}'      => $header,
                    '{parte}'       => $partText,
                    '{parte_num}'   => llm_pipeline_part_label($item['key']),
                    '{parte_total}' => (string)$total,
                ];
                $system = strtr((string)($spec['system_map'] ?? ''), $vars);
                if ($strict) {
                    $system .= $strictSuffix;
                }
                return $call($system, strtr((string)($spec['user_map'] ?? ''), $vars), $maxMap);
            };

            $res = $doMap(false);
            $out['calls']++;

            $value = empty($res['success']) ? null : $partialValue($res, $mode);
            $invalidShape = ($value !== null && !$checkPart($value));

            // Respuesta con forma equivocada (p. ej. solo una lista de
            // técnicas): un reintento estricto antes de darla por perdida.
            if ($invalidShape) {
                $res = $doMap(true);
                $out['calls']++;
                $value = empty($res['success']) ? null : $partialValue($res, $mode);
                if ($value !== null && !$checkPart($value)) {
                    $value = null;
                    $out['invalid_format'] = true;
                }
            }

            if ($value !== null) {
                $partials[$item['key']] = $value;
                $order[] = $item['key'];
                $okCount++;
                $resolved[$slotOf($item['key'])] = true;
                if (!empty($res['model'])) {
                    $out['model'] = (string)$res['model'];
                }
                if (!empty($res['clipped'])) {
                    $out['clipped'] = true;
                }
                if (is_callable($savePart)) {
                    $savePart($item['key'], $value, true, '', (string)($res['content'] ?? ''));
                }
                $report('Analizando la evidencia');
                continue;
            }

            $error = $invalidShape
                ? 'La parte no devolvió un objeto JSON con el análisis (formato inválido).'
                : (string)($res['error'] ?? 'La IA no devolvió contenido para esta parte.');
            if ($invalidShape) {
                $res['error_kind'] = 'invalid_format';
            }
            $errors[$item['key']] = $error;

            // Timeout o fin de contexto en una parte todavía grande: se parte
            // en dos y se reintenta. Se mira `error_kind`, que viaja desde el
            // mensaje crudo del proveedor (el traducido engañaba al detector).
            $kind = (string)($res['error_kind'] ?? '');
            $retriable = $kind === 'timeout' || $kind === 'context';
            if ($kind === '' && llm_err_is_timeout($error)) {
                $retriable = true;
            }
            $splittable = $item['depth'] < $maxSplits
                && $retriable
                && is_callable($splitPart)
                && llm_str_len($partText) >= $minSplitChars;
            if ($splittable) {
                $subParts = $splitPart($item['part']);
                if (is_array($subParts) && count($subParts) === 2) {
                    $a = llm_pipeline_normalize_parts([$subParts[0]]);
                    $b = llm_pipeline_normalize_parts([$subParts[1]]);
                    if ($a !== [] && $b !== []) {
                        $out['warnings'][] = 'La parte ' . llm_pipeline_part_label($item['key'])
                            . ($kind === 'context'
                                ? ' no cabía en el modelo: se divide en dos y se reintenta.'
                                : ' agotó el tiempo: se divide en dos y se reintenta.');
                        array_unshift(
                            $queue,
                            ['key' => $item['key'] . 'b', 'part' => $b[0], 'depth' => $item['depth'] + 1],
                            ['key' => $item['key'] . 'a', 'part' => $a[0], 'depth' => $item['depth'] + 1]
                        );
                        $report('Reintentando la parte ' . llm_pipeline_part_label($item['key'])
                            . ' por mitades (' . ($kind === 'context' ? 'no cabía' : 'se agotó el tiempo') . ')');
                        continue;
                    }
                }
            }

            $failCount++;
            $resolved[$slotOf($item['key'])] = true;
            if (is_callable($savePart)) {
                $savePart($item['key'], null, false, $error, (string)($res['content'] ?? ''));
            }
            $out['warnings'][] = 'La parte ' . llm_pipeline_part_label($item['key']) . ' no se pudo analizar: '
                . llm_str_cut($error, 220);
            $report('Analizando la evidencia');
        }

        if ($stopped !== '') {
            $out['stopped'] = $stopped;
            $out['warnings'][] = $stopped === 'cancel'
                ? 'Análisis detenido por el usuario.'
                : 'Análisis detenido al superar el tiempo máximo del trabajo.';
        }

        $out['failed'] = $failCount;

        if ($partials === []) {
            $first = (string)(reset($errors) ?: ($stopped === 'cancel'
                ? 'El análisis se detuvo antes de terminar ninguna parte.'
                : 'La IA no devolvió ningún resultado.'));
            $out['error'] = $first;
            $out['elapsed_ms'] = (int)round((microtime(true) - $started) * 1000);
            return $out;
        }

        // Los parciales se devuelven tal cual: el módulo puede montar con ellos
        // un informe de emergencia si el modelo no respetó el formato.
        foreach ($order as $key) {
            $out['partials'][] = $partials[$key];
        }

        // Detenido a medias: se ensambla en local lo que hay (sin más llamadas).
        if ($stopped !== '') {
            $items = [];
            foreach ($order as $key) {
                $items[] = $partials[$key];
            }
            $local = llm_pipeline_merge_local($items, $mode);
            $out['data'] = $mode === 'json' ? $local['data'] : null;
            $out['content'] = (string)$local['content'];
            $out['success'] = $mode === 'json' ? is_array($local['data']) : trim((string)$local['content']) !== '';
            $out['elapsed_ms'] = (int)round((microtime(true) - $started) * 1000);
            return $out;
        }

        /* -------------------------------------------------------------
         * 2) REDUCE — fusión jerárquica de los parciales
         * ---------------------------------------------------------- */

        $items = [];
        foreach ($order as $key) {
            $items[] = $partials[$key];
        }

        $groupSize  = max(2, (int)($spec['reduce_group'] ?? 4));
        $maxLevels  = max(1, (int)($spec['max_reduce_levels'] ?? 5));
        $level      = 0;

        while (count($items) > 1 && $level < $maxLevels) {
            if ($isCancelled()) {
                $stopped = 'cancel';
                break;
            }
            if ($deadlineHit()) {
                $stopped = 'deadline';
                break;
            }

            $next = [];
            foreach (array_chunk($items, $groupSize) as $chunkIndex => $chunk) {
                if (count($chunk) === 1) {
                    $next[] = $chunk[0];
                    continue;
                }

                $report('Fusionando el análisis (nivel ' . ($level + 1) . ')');

                $blocks = [];
                foreach (array_values($chunk) as $i => $value) {
                    $blocks[] = '--- ANÁLISIS PARCIAL ' . ($i + 1) . ' ---' . "\n"
                        . (is_array($value)
                            ? (string)json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)
                            : (string)$value);
                }
                $resultados = implode("\n\n", $blocks);
                $vars = ['{resultados}' => $resultados, '{header}' => $header, '{total}' => (string)$total];

                /** Una llamada de fusión. `$strict` añade la instrucción de forma. */
                $doReduce = function (bool $strict) use ($reduceCall, $call, $spec, $vars, $chunk, $level, $maxMerge, $strictSuffix): array {
                    if (is_callable($reduceCall)) {
                        return $reduceCall($chunk, $level);
                    }
                    $system = strtr((string)($spec['system_reduce'] ?? ''), $vars);
                    if ($strict) {
                        $system .= $strictSuffix;
                    }
                    return $call($system, strtr((string)($spec['user_reduce'] ?? ''), $vars), $maxMerge);
                };

                $res = $doReduce(false);
                $out['calls']++;

                $value = empty($res['success']) ? null : $partialValue($res, $mode);
                if ($value !== null && !$checkFinal($value)) {
                    // Fusión con forma equivocada: un reintento estricto.
                    $res = $doReduce(true);
                    $out['calls']++;
                    $value = empty($res['success']) ? null : $partialValue($res, $mode);
                    if ($value !== null && !$checkFinal($value)) {
                        $value = null;
                    }
                }
                if ($value !== null) {
                    if (!empty($res['model'])) {
                        $out['model'] = (string)$res['model'];
                    }
                    if (!empty($res['clipped'])) {
                        $out['clipped'] = true;
                    }
                    $next[] = $value;
                    $out['merged']++;
                    continue;
                }

                $out['invalid_format'] = true;
                $out['warnings'][] = 'La fusión del grupo ' . ($chunkIndex + 1)
                    . ' no devolvió el formato esperado (' . llm_str_cut((string)($res['error'] ?? 'sin error'), 180)
                    . '): se combinan los parciales en local.';
                $local = llm_pipeline_merge_local($chunk, $mode);
                $next[] = $mode === 'json' ? $local['data'] : $local['content'];
            }
            $items = $next;
            $level++;
        }

        if ($stopped !== '') {
            $out['stopped'] = $stopped;
            $out['warnings'][] = $stopped === 'cancel'
                ? 'Fusión interrumpida por el usuario.'
                : 'Fusión interrumpida al superar el tiempo máximo del trabajo.';
            if (count($items) > 1) {
                $local = llm_pipeline_merge_local($items, $mode);
                $items = [$mode === 'json' ? $local['data'] : $local['content']];
            }
        }

        $final = $items[0] ?? null;
        if ($mode === 'json') {
            if (!is_array($final)) {
                $local = llm_pipeline_merge_local($items, 'json');
                $final = $local['data'];
            }
            $out['data'] = $final;
            $out['content'] = (string)json_encode(
                $final,
                JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
            );
            $out['success'] = is_array($final);
            // El resultado final también debe tener la forma pedida: una lista
            // de técnicas no es un análisis.
            if ($out['success'] && !$checkFinal($final)) {
                $out['success'] = false;
                $out['invalid_format'] = true;
                $out['error'] = 'La IA no devolvió un análisis con el formato esperado.';
            }
        } else {
            $out['content'] = trim((string)$final);
            $out['success'] = $out['content'] !== '';
        }

        if (!$out['success'] && $out['error'] === '') {
            $out['error'] = 'La fusión final no produjo una respuesta válida.';
        }

        $out['elapsed_ms'] = (int)round((microtime(true) - $started) * 1000);
        if ($out['success'] && $stopped === '') {
            $report('Análisis completado');
        }

        return $out;
    }
}
