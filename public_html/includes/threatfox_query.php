<?php
/**
 * ThreatfoxQuery — Traducción de la consulta de la interfaz a la API o a SQL.
 *
 * Paridad de semántica entre las dos fuentes:
 *  · Modos: auto (detecta el tipo del indicador), recent, ioc, malware, tag,
 *    hash.
 *  · Multi-término: los términos separados por comas se combinan con AND.
 *  · El filtro de días solo aplica en modo "recent" (igual que la API).
 *  · Los filtros de campo (malware, tipo de IOC, tipo de amenaza, tag,
 *    confianza mínima, solo con referencia) se aplican en cliente cuando la
 *    fuente es la API y en SQL cuando es la base local.
 *  · Relé automático: en modo auto, si la base local no tiene el indicador y
 *    hay Auth-Key, se pregunta a la API (1 llamada, best-effort).
 *  · Orden común: confidence_level DESC, first_seen DESC.
 */

declare(strict_types=1);

final class ThreatfoxQuery
{
    public const PER_PAGE = THREATFOX_PAGE_SIZE;

    /** Modos de consulta con su etiqueta. */
    public const MODES = [
        'auto'    => 'Automático',
        'recent'  => 'Recientes',
        'ioc'     => 'IOC',
        'malware' => 'Malware',
        'tag'     => 'Tag',
        'hash'    => 'Hash',
    ];

    /** Fuentes de datos. */
    public const SOURCES = [
        'db'  => 'Base local',
        'api' => 'API en vivo',
    ];

    /** Catálogo de respaldo si la base local está vacía. */
    private const FALLBACK_IOC_TYPES = [
        'domain', 'url', 'ip:port', 'md5_hash', 'sha1_hash', 'sha256_hash', 'filename',
    ];

    private const FALLBACK_THREAT_TYPES = [
        'botnet_cc', 'payload_delivery', 'payload', 'cc_skimming', 'js.clearfake',
    ];

    /* =====================================================================
     * Normalización de la entrada
     * ================================================================== */

    /**
     * Sanea los parámetros de la interfaz (enteros acotados, enums cerrados y
     * cadenas truncadas).
     */
    public static function normalize(array $input): array
    {
        $source = (string)($input['source'] ?? 'db');
        if (!isset(self::SOURCES[$source])) {
            $source = 'db';
        }

        $mode = (string)($input['mode'] ?? 'auto');
        if (!isset(self::MODES[$mode])) {
            $mode = 'auto';
        }

        $term = self::cleanText((string)($input['search_term'] ?? ''), 300);
        $terms = [];
        foreach (explode(',', $term) as $piece) {
            $piece = trim($piece);
            if ($piece !== '') {
                $terms[] = $piece;
            }
        }

        $days = (int)($input['days'] ?? 0);
        $days = max(0, min(THREATFOX_DAYS_MAX, $days));

        $limit = (int)($input['limit'] ?? 100);
        $limit = max(1, min(1000, $limit));

        return [
            'source'      => $source,
            'mode'        => $mode,
            'term'        => $term,
            'terms'       => $terms,
            'days'        => $days,
            'exact'       => !empty($input['exact']),
            'limit'       => $limit,
            'malware'     => self::cleanText((string)($input['f_malware'] ?? ''), 120),
            'ioc_type'    => self::cleanText((string)($input['f_ioc_type'] ?? ''), 60),
            'threat_type' => self::cleanText((string)($input['f_threat'] ?? ''), 60),
            'tag'         => self::cleanText((string)($input['f_tag'] ?? ''), 80),
            'conf'        => max(0, min(100, (int)($input['f_conf'] ?? 0))),
            'ref_only'    => !empty($input['f_ref']),
        ];
    }

    private static function cleanText(string $value, int $max): string
    {
        $value = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $value) ?? '';
        $value = trim(preg_replace('/\s+/u', ' ', $value) ?? '');
        return function_exists('mb_substr') ? mb_substr($value, 0, $max) : substr($value, 0, $max);
    }

    /* =====================================================================
     * Detección del tipo de término (modo auto)
     * ================================================================== */

    /** Tipo detectado por la forma del término: md5|sha1|sha256|url|ip:port|ip|domain|text */
    public static function detectTermType(string $term): string
    {
        $term = trim($term);
        if ($term === '') {
            return 'text';
        }
        if (preg_match('/^[0-9a-f]{32}$/i', $term)) {
            return 'md5';
        }
        if (preg_match('/^[0-9a-f]{40}$/i', $term)) {
            return 'sha1';
        }
        if (preg_match('/^[0-9a-f]{64}$/i', $term)) {
            return 'sha256';
        }
        if (preg_match('#^https?://#i', $term)) {
            return 'url';
        }
        if (preg_match('/^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$/', $term)) {
            return 'ip:port';
        }
        if (filter_var($term, FILTER_VALIDATE_IP)) {
            return 'ip';
        }
        if (filter_var($term, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return 'domain';
        }
        return 'text';
    }

    /* =====================================================================
     * Ejecución
     * ================================================================== */

    /**
     * Ejecuta la consulta completa.
     *
     * @return array{rows:array,total:int,page:int,perPage:int,totalPages:int,
     *               status:string,message:string,source:string,detected:string,
     *               api_count:?int,relay:bool}
     */
    public static function run(array $f, int $page = 1): array
    {
        if ($f['source'] === 'api') {
            return self::runApi($f, $page);
        }
        return self::runDb($f, $page);
    }

    /** Filtros en la forma que espera ThreatfoxStore. */
    public static function storeFiltersFor(array $f): array
    {
        return [
            'terms'       => $f['terms'],
            /* Paridad con la API: los días solo acotan en modo "recent". */
            'days'        => $f['mode'] === 'recent' ? max(1, $f['days'] ?: THREATFOX_DAYS_MAX) : 0,
            'malware'     => $f['malware'],
            'ioc_type'    => $f['ioc_type'],
            'threat_type' => $f['threat_type'],
            'tag'         => $f['tag'],
            'conf'        => $f['conf'],
            'ref_only'    => $f['ref_only'],
        ];
    }

    private static function runDb(array $f, int $page): array
    {
        $store = new ThreatfoxStore();
        $filters = self::storeFiltersFor($f);

        $total = $store->countFiltered($filters);
        $detected = $f['mode'] === 'auto' ? self::detectTermType($f['term']) : '';

        if ($total === 0) {
            /* Relé automático: la base local no lo tiene, se pregunta a la API. */
            if ($f['mode'] === 'auto' && $f['term'] !== '' && ThreatfoxApi::hasAuthKey()) {
                $relay = self::runApi(array_merge($f, ['source' => 'api']), $page);
                if ($relay['total'] > 0) {
                    $relay['relay'] = true;
                    $relay['source'] = 'db';
                    $relay['message'] = 'No estaba en la base local; resultado de la API en vivo.';
                    $relay['detected'] = $detected;
                    return $relay;
                }
                return [
                    'rows' => [], 'total' => 0, 'page' => 1, 'perPage' => self::PER_PAGE,
                    'totalPages' => 1, 'status' => 'no_result_both',
                    'message' => 'Sin resultados en la base local ni en la API.',
                    'source' => 'db', 'detected' => $detected, 'api_count' => 0, 'relay' => true,
                ];
            }

            return [
                'rows' => [], 'total' => 0, 'page' => 1, 'perPage' => self::PER_PAGE,
                'totalPages' => 1, 'status' => 'no_result',
                'message' => $store->count() === 0
                    ? 'La base local está vacía: pulsa «Actualizar base local» o descarga el histórico completo.'
                    : 'Sin resultados para los filtros aplicados.',
                'source' => 'db', 'detected' => $detected, 'api_count' => null, 'relay' => false,
            ];
        }

        $totalPages = max(1, (int)ceil($total / self::PER_PAGE));
        $page = max(1, min($page, $totalPages));
        $rows = $store->query($filters, self::PER_PAGE, ($page - 1) * self::PER_PAGE);

        return [
            'rows'       => array_map([self::class, 'normalizeRow'], $rows),
            'total'      => $total,
            'page'       => $page,
            'perPage'    => self::PER_PAGE,
            'totalPages' => $totalPages,
            'status'     => 'ok',
            'message'    => 'Consultado en la base local.',
            'source'     => 'db',
            'detected'   => $detected,
            'api_count'  => null,
            'relay'      => false,
        ];
    }

    private static function runApi(array $f, int $page): array
    {
        $key = ThreatfoxApi::resolveAuthKey();
        if ($key === '') {
            return [
                'rows' => [], 'total' => 0, 'page' => 1, 'perPage' => self::PER_PAGE,
                'totalPages' => 1, 'status' => 'client_error',
                'message' => 'No hay Auth-Key de abuse.ch configurada: solo puedes consultar la base local.',
                'source' => 'api', 'detected' => '', 'api_count' => null, 'relay' => false,
            ];
        }

        $api = new ThreatfoxApi($key);
        $detected = '';
        $mode = $f['mode'];
        $term = $f['term'];

        switch ($mode) {
            case 'recent':
                $response = $api->getIocs(max(1, $f['days'] ?: THREATFOX_DAYS_MAX));
                break;

            case 'malware':
                if ($term === '') {
                    return self::apiBadTerm('Escribe una familia de malware (ej. win.cobaltstrike).');
                }
                $response = $api->searchMalware($term, $f['limit']);
                break;

            case 'tag':
                if ($term === '') {
                    return self::apiBadTerm('Escribe un tag (ej. Magecart).');
                }
                $response = $api->searchTag($term, $f['limit']);
                break;

            case 'hash':
                if ($term === '') {
                    return self::apiBadTerm('Escribe un hash MD5, SHA1 o SHA256.');
                }
                $response = $api->searchHash($term);
                break;

            case 'auto':
                $detected = self::detectTermType($term);
                if ($term === '') {
                    /* Sin término, "auto" equivale a los IOCs recientes. */
                    $response = $api->getIocs(max(1, $f['days'] ?: THREATFOX_DAYS_MAX));
                } elseif (in_array($detected, ['md5', 'sha1', 'sha256'], true)) {
                    $response = $api->searchHash($term);
                } else {
                    $response = $api->searchIoc($term, $f['limit'], $f['exact']);
                }
                break;

            case 'ioc':
            default:
                if ($term === '') {
                    return self::apiBadTerm('Escribe un indicador para buscar.');
                }
                $response = $api->searchIoc($term, $f['limit'], $f['exact']);
                break;
        }

        $status = (string)($response['query_status'] ?? 'unknown');
        if ($status !== ThreatfoxApi::STATUS_OK) {
            $detail = (string)($response['error'] ?? '');
            return [
                'rows' => [], 'total' => 0, 'page' => 1, 'perPage' => self::PER_PAGE,
                'totalPages' => 1,
                'status' => $status === 'no_result' ? 'no_result' : 'client_error',
                'message' => $status === 'no_result'
                    ? 'La API no tiene resultados para esa consulta.'
                    : 'La API respondió «' . $status . '»' . ($detail !== '' ? ': ' . $detail : '.'),
                'source' => 'api', 'detected' => $detected, 'api_count' => 0, 'relay' => false,
            ];
        }

        $rows = array_map([self::class, 'normalizeRow'], (array)($response['data'] ?? []));
        $apiCount = count($rows);

        /* El primer término ya alimentó la query; el resto filtra en cliente.
           En "recent" la API no acepta término, así que filtran todos. */
        $remaining = $mode === 'recent' ? $f['terms'] : array_slice($f['terms'], 1);
        $rows = self::applyClientFilters($rows, $f, $remaining);

        usort($rows, static function (array $a, array $b): int {
            $byConf = (int)($b['confidence_level'] ?? 0) <=> (int)($a['confidence_level'] ?? 0);
            return $byConf !== 0 ? $byConf : strcmp((string)($b['first_seen'] ?? ''), (string)($a['first_seen'] ?? ''));
        });

        $total = count($rows);
        if ($total === 0) {
            return [
                'rows' => [], 'total' => 0, 'page' => 1, 'perPage' => self::PER_PAGE,
                'totalPages' => 1, 'status' => 'no_result',
                'message' => $apiCount > 0
                    ? 'La API devolvió ' . $apiCount . ' IOCs, pero ninguno pasa los filtros aplicados.'
                    : 'La API no tiene resultados para esa consulta.',
                'source' => 'api', 'detected' => $detected, 'api_count' => $apiCount, 'relay' => false,
            ];
        }

        $totalPages = max(1, (int)ceil($total / self::PER_PAGE));
        $page = max(1, min($page, $totalPages));
        $slice = array_slice($rows, ($page - 1) * self::PER_PAGE, self::PER_PAGE);

        return [
            'rows'       => $slice,
            'total'      => $total,
            'page'       => $page,
            'perPage'    => self::PER_PAGE,
            'totalPages' => $totalPages,
            'status'     => 'ok',
            'message'    => 'Consultado en la API en vivo.',
            'source'     => 'api',
            'detected'   => $detected,
            'api_count'  => $apiCount,
            'relay'      => false,
        ];
    }

    private static function apiBadTerm(string $message): array
    {
        return [
            'rows' => [], 'total' => 0, 'page' => 1, 'perPage' => self::PER_PAGE,
            'totalPages' => 1, 'status' => 'client_error', 'message' => $message,
            'source' => 'api', 'detected' => '', 'api_count' => null, 'relay' => false,
        ];
    }

    /**
     * Filtros de campo aplicados en cliente (modo API): subcadena en IOC,
     * malware y tags; igualdad en tipo de IOC y de amenaza; tag como token
     * exacto; confianza mínima; solo con referencia.
     */
    private static function applyClientFilters(array $rows, array $f, array $terms): array
    {
        $out = [];
        foreach ($rows as $row) {
            foreach ($terms as $term) {
                $haystack = strtolower(
                    (string)($row['ioc'] ?? '') . ' ' . (string)($row['malware'] ?? '') . ' '
                    . (string)($row['malware_printable'] ?? '') . ' ' . (string)($row['tags'] ?? '')
                );
                if (!str_contains($haystack, strtolower($term))) {
                    continue 2;
                }
            }

            if ($f['malware'] !== '') {
                $malware = strtolower((string)($row['malware'] ?? '') . ' ' . (string)($row['malware_printable'] ?? ''));
                if (!str_contains($malware, strtolower($f['malware']))) {
                    continue;
                }
            }
            if ($f['ioc_type'] !== '' && (string)($row['ioc_type'] ?? '') !== $f['ioc_type']) {
                continue;
            }
            if ($f['threat_type'] !== '' && (string)($row['threat_type'] ?? '') !== $f['threat_type']) {
                continue;
            }
            if ($f['tag'] !== '') {
                $tags = array_map('trim', explode(',', (string)($row['tags'] ?? '')));
                if (!in_array($f['tag'], $tags, true)) {
                    continue;
                }
            }
            if ($f['conf'] > 0 && (int)($row['confidence_level'] ?? 0) < $f['conf']) {
                continue;
            }
            if ($f['ref_only'] && trim((string)($row['reference'] ?? '')) === '') {
                continue;
            }

            $out[] = $row;
        }
        return $out;
    }

    /* =====================================================================
     * Presentación
     * ================================================================== */

    /** Normaliza una fila (API o SQLite) a la forma que usa la vista. */
    public static function normalizeRow(array $row): array
    {
        $tags = $row['tags'] ?? [];
        if (is_array($tags)) {
            $tags = implode(',', array_map('strval', $tags));
        }
        $tags = trim((string)$tags);

        $row['tags'] = $tags;
        $row['tags_list'] = $tags === ''
            ? []
            : array_values(array_filter(array_map('trim', explode(',', $tags))));

        $row['reference'] = trim((string)($row['reference'] ?? ''));
        if (in_array(strtolower($row['reference']), ['none', 'null', '-'], true)) {
            $row['reference'] = '';
        }
        $row['confidence_level'] = (int)($row['confidence_level'] ?? 0);

        return $row;
    }

    /** Catálogos de los desplegables de filtro (sin red). */
    public static function catalogs(): array
    {
        try {
            $store = new ThreatfoxStore();
            $iocTypes = $store->distinct('ioc_type');
            $threatTypes = $store->distinct('threat_type');
        } catch (Throwable $e) {
            $iocTypes = [];
            $threatTypes = [];
        }

        return [
            'ioc_type'    => $iocTypes ?: self::FALLBACK_IOC_TYPES,
            'threat_type' => $threatTypes ?: self::FALLBACK_THREAT_TYPES,
        ];
    }
}
