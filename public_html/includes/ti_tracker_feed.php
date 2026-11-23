<?php
/**
 * TiTrackerFeed — Motor de feeds externos de Seguimiento TI TF (v0.4.29).
 *
 * Expone las búsquedas guardadas como listas de indicadores para herramientas
 * de Threat Intelligence externas (Microsoft Sentinel/Defender, MISP, firewalls
 * EDL...). No consulta la API de abuse.ch: solo lee la base local de
 * Seguimiento TI TF (tracked_iocs + last_results), igual que el cron.
 *
 * Los formatos se generan con los builders puros de Module_Export, así que el
 * STIX/MISP/TXT/CSV publicado es idéntico al que descarga el asistente.
 */

declare(strict_types=1);

final class TiTrackerFeed
{
    public const FORMATS = ['stix', 'misp', 'json', 'txt', 'csv'];
    public const SCOPES  = ['tracked', 'last', 'new'];
    public const TYPES   = ['all', 'ip', 'domain', 'url', 'hash', 'email'];

    /** Tope de listas combinadas en una sola petición. */
    public const MAX_LISTS = 50;

    /**
     * Ids de búsquedas permitidos por el token.
     * null = sin restricción (tokens antiguos), [] = ninguna.
     */
    public static function allowedIds(array $token): ?array
    {
        $perms = safe_json_decode((string)($token['permissions'] ?? ''), []);
        if (!is_array($perms) || ($perms['scope'] ?? null) !== 'ti_tracker') {
            return null; // Compatibilidad: un token sin ámbito TI TF ve todas las listas publicadas.
        }
        if (!empty($perms['all_lists'])) {
            return null;
        }

        $ids = [];
        foreach ((array)($perms['search_ids'] ?? []) as $value) {
            $id = (int)$value;
            if ($id > 0) {
                $ids[] = $id;
            }
        }

        return array_values(array_unique($ids));
    }

    /** ¿El token autoriza pasar el secreto por query-string? (EDLs de firewalls) */
    public static function allowQueryToken(array $token): bool
    {
        $perms = safe_json_decode((string)($token['permissions'] ?? ''), []);

        return is_array($perms) && !empty($perms['allow_query_token']);
    }

    /**
     * Resuelve las listas pedidas, siempre dentro de las autorizadas al token.
     * Acepta ids numéricos o slugs separados por comas; 'all' (o vacío) = todas.
     *
     * @param array<int,int>|null $allowedIds
     * @param array<int,array> $published
     * @return array<int,array>
     */
    public static function resolveSearches(?array $allowedIds, $listsParam, ?TiTrackerStore $store = null): array
    {
        $store = $store ?? new TiTrackerStore();
        $published = $store->listApiSearches($allowedIds);
        $byId = [];
        foreach ($published as $search) {
            $byId[(int)$search['id']] = $search;
        }

        $param = trim((string)$listsParam);
        if ($param === '' || strtolower($param) === 'all') {
            $chosen = array_values($byId);
        } else {
            $wanted = [];
            foreach (explode(',', $param) as $piece) {
                $piece = strtolower(trim($piece));
                if ($piece === '') {
                    continue;
                }
                if (ctype_digit($piece)) {
                    $wanted[] = (int)$piece;
                    continue;
                }
                foreach ($byId as $search) {
                    if (strtolower((string)($search['slug'] ?? '')) === $piece) {
                        $wanted[] = (int)$search['id'];
                    }
                }
            }
            $wanted = array_values(array_unique($wanted));
            $chosen = [];
            foreach ($wanted as $id) {
                if (isset($byId[$id])) {
                    $chosen[] = $byId[$id];
                }
            }
        }

        if (count($chosen) > self::MAX_LISTS) {
            $chosen = array_slice($chosen, 0, self::MAX_LISTS);
        }

        return $chosen;
    }

    /** Catálogo de listas publicadas para GET /api/ti-tf/lists. */
    public static function catalog(?array $allowedIds, ?TiTrackerStore $store = null): array
    {
        $store = $store ?? new TiTrackerStore();
        $items = [];
        foreach ($store->listApiSearches($allowedIds) as $search) {
            $snapshot = $store->getLastResult((int)$search['id']);
            $items[] = [
                'id'            => (int)$search['id'],
                'slug'          => (string)($search['slug'] ?? ''),
                'name'          => (string)$search['name'],
                'tracked'       => $store->trackedCount((int)$search['id']),
                'last_run_at'   => $snapshot['run_at'] ?? null,
                'last_new'      => (int)($snapshot['result']['new'] ?? 0),
                'last_rows'     => (int)($snapshot['result']['rows'] ?? 0),
                'formats'       => array_values((array)($search['formats'] ?? [])),
                'tlp'           => (string)$search['tlp'],
                'valid_days'    => (int)$search['valid_days'],
            ];
        }

        return $items;
    }

    /** Valida y normaliza el filtro temporal opcional. */
    public static function normalizeSince($value): ?string
    {
        $value = trim((string)$value);
        if ($value === '') {
            return null;
        }
        $time = strtotime($value);
        if ($time === false) {
            throw new InvalidArgumentException('El parámetro since no es una fecha válida.');
        }

        return gmdate('Y-m-d H:i:s', $time);
    }

    /**
     * Recoge y deduplica los IOCs de las listas seleccionadas.
     *
     * @param array<int,array> $searches
     * @return array{iocs:array<int,array>,lists:array<int,array>,truncated:bool}
     */
    public static function collect(
        array $searches,
        string $scope = 'tracked',
        ?string $since = null,
        string $type = 'all',
        ?TiTrackerStore $store = null
    ): array {
        $store = $store ?? new TiTrackerStore();
        if (!in_array($scope, self::SCOPES, true)) {
            throw new InvalidArgumentException('Ámbito no soportado.');
        }
        if (!in_array($type, self::TYPES, true)) {
            throw new InvalidArgumentException('Tipo de IOC no soportado.');
        }

        $iocs = [];
        $seen = [];
        $perList = [];

        foreach ($searches as $search) {
            $rows = self::rowsFor($store, (int)$search['id'], $scope, $since);
            $count = 0;
            foreach ($rows as $row) {
                $mapped = Module_Export::mapIocRow(is_array($row) ? $row : []);
                if ($mapped === null || !self::matchesType((string)$mapped['type'], $type)) {
                    continue;
                }
                $key = (string)$mapped['type'] . '|' . strtolower((string)$mapped['value']);
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $mapped['list_id']   = (int)$search['id'];
                $mapped['list_name'] = (string)$search['name'];
                $mapped['list_slug'] = (string)($search['slug'] ?? '');
                $iocs[] = $mapped;
                $count++;
            }
            $perList[] = [
                'id'    => (int)$search['id'],
                'slug'  => (string)($search['slug'] ?? ''),
                'name'  => (string)$search['name'],
                'count' => $count,
            ];
        }

        $truncated = count($iocs) > TI_TRACKER_MAX_ROWS;
        if ($truncated) {
            $iocs = array_slice($iocs, 0, TI_TRACKER_MAX_ROWS);
        }

        return ['iocs' => $iocs, 'lists' => $perList, 'truncated' => $truncated];
    }

    /** Filas de una lista según el ámbito pedido. */
    private static function rowsFor(TiTrackerStore $store, int $searchId, string $scope, ?string $since): array
    {
        if ($scope === 'tracked') {
            $rows = [];
            foreach ($store->trackedRows($searchId, $since) as $row) {
                $rows[] = [
                    'ioc'        => (string)($row['ioc'] ?? ''),
                    'ioc_id'     => (string)($row['ioc_id'] ?? ''),
                    'first_seen' => (string)($row['first_seen'] ?? ''),
                    'found_at'   => (string)($row['found_at'] ?? ''),
                ];
            }
            return $rows;
        }

        $snapshot = $store->getLastResult($searchId);
        if ($snapshot === null) {
            return [];
        }
        if ($since !== null && strtotime((string)$snapshot['run_at']) < strtotime($since)) {
            return [];
        }

        $rows = (array)$snapshot['rows'];
        if ($scope !== 'new') {
            return $rows;
        }

        $newKeys = [];
        foreach ((array)($snapshot['result']['new_iocs'] ?? []) as $value) {
            $key = strtolower(trim((string)$value));
            if ($key !== '') {
                $newKeys[$key] = true;
            }
        }
        if ($newKeys === []) {
            return [];
        }

        return array_values(array_filter($rows, static function (array $row) use ($newKeys): bool {
            return isset($newKeys[strtolower(trim((string)($row['ioc'] ?? '')))]);
        }));
    }

    private static function matchesType(string $type, string $wanted): bool
    {
        if ($wanted === 'all') {
            return true;
        }
        $groups = [
            'ip'    => ['ipv4-addr', 'ipv6-addr'],
            'domain' => ['domain-name'],
            'url'    => ['url'],
            'hash'   => ['file'],
            'email'  => ['email-addr', 'user-account'],
        ];

        return isset($groups[$wanted]) && in_array($type, $groups[$wanted], true);
    }

    /**
     * Serializa el conjunto en el formato pedido con los builders de Module_Export.
     *
     * @return array{content:string,mime:string,filename:string}
     */
    public static function render(array $iocs, string $format, array $config = []): array
    {
        if (!in_array($format, self::FORMATS, true)) {
            throw new InvalidArgumentException('Formato no soportado.');
        }

        $exporter = new Module_Export();
        $date = date('Y-m-d');
        $stixConfig = [
            'format'          => 'merged',
            'tlp'             => (string)($config['tlp'] ?? 'green'),
            'valid_days'      => (int)($config['valid_days'] ?? 365),
            'source'          => 'EntraID TI - Seguimiento TI TF',
            'indicator_type'  => 'malicious-activity',
        ];
        $mispConfig = [
            'format'       => 'merged',
            'tlp'          => (string)($config['tlp'] ?? 'green'),
            'info'         => 'EntraID TI - Seguimiento TI TF',
        ];

        return match ($format) {
            'stix' => (static function () use ($exporter, $iocs, $stixConfig, $date): array {
                $result = $exporter->buildStixResult($iocs, $stixConfig);
                return [
                    'content'  => (string)$result['content'],
                    'mime'     => 'application/json',
                    'filename' => 'ti_tf_stix_' . $date . '.json',
                ];
            })(),
            'misp' => (static function () use ($exporter, $iocs, $mispConfig, $date): array {
                $result = $exporter->buildMispResult($iocs, $mispConfig);
                return [
                    'content'  => (string)$result['content'],
                    'mime'     => 'application/json',
                    'filename' => 'ti_tf_misp_' . $date . '.json',
                ];
            })(),
            'txt' => [
                'content'  => $exporter->buildTxtContent($iocs),
                'mime'     => 'text/plain; charset=utf-8',
                'filename' => 'ti_tf_iocs_' . $date . '.txt',
            ],
            'csv' => [
                'content'  => $exporter->buildCsvContent($iocs),
                'mime'     => 'text/csv; charset=utf-8',
                'filename' => 'ti_tf_iocs_' . $date . '.csv',
            ],
            default => [
                'content'  => json_encode($iocs, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?: '[]',
                'mime'     => 'application/json',
                'filename' => 'ti_tf_iocs_' . $date . '.json',
            ],
        };
    }
}
