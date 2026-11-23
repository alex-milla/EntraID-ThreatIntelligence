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
    public const FORMATS = ['stix', 'misp', 'json', 'txt', 'csv', 'ms-sentinel'];
    public const SCOPES  = ['tracked', 'last', 'new'];
    public const TYPES   = ['all', 'ip', 'domain', 'url', 'hash', 'email'];

    /** Tope de listas combinadas en una sola petición. */
    public const MAX_LISTS = 50;

    /** UUID v4-shaped estable: id de colección TAXII derivado de la lista. */
    public static function stableUuid(string $seed): string
    {
        $hash = sha1(strtolower(trim($seed)));

        return sprintf(
            '%s-%s-4%s-8%s-%s',
            substr($hash, 0, 8),
            substr($hash, 8, 4),
            substr($hash, 13, 3),
            substr($hash, 18, 3),
            substr($hash, 20, 12)
        );
    }

    /** Id TAXII de una búsqueda (o de la colección agregada «all»). */
    public static function collectionId($searchId = null): string
    {
        return self::stableUuid($searchId === null ? 'ti-tf-all' : 'ti-tf-search-' . (int)$searchId);
    }

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

    /** Permisos decodificados de un token (array vacío si no son válidos). */
    public static function tokenPermissions($raw): array
    {
        $perms = safe_json_decode((string)$raw, []);

        return is_array($perms) ? $perms : [];
    }

    /** Construye el permiso de un token TI TF a partir del formulario. */
    public static function permissionsFromInput(array $input, array $published): array
    {
        $all = !empty($input['all_lists']);
        $ids = [];
        if (!$all) {
            $valid = [];
            foreach ($published as $search) {
                $valid[(int)$search['id']] = true;
            }
            foreach ((array)($input['search_ids'] ?? []) as $value) {
                $id = (int)$value;
                if ($id > 0 && isset($valid[$id])) {
                    $ids[] = $id;
                }
            }
        }

        return [
            'scope'             => 'ti_tracker',
            'all_lists'         => $all,
            'search_ids'        => array_values(array_unique($ids)),
            'allow_query_token' => !empty($input['allow_query_token']),
        ];
    }

    /** Resumen legible de los permisos de un token. */
    public static function describePermissions(array $perms): string
    {
        $bits = [!empty($perms['all_lists']) ? 'Todas las listas' : count((array)($perms['search_ids'] ?? [])) . ' lista(s)'];
        if (!empty($perms['allow_query_token'])) {
            $bits[] = 'token en URL permitido';
        }

        return implode(' · ', $bits);
    }

    /** Crea un token de API y devuelve el secreto en claro (solo se muestra una vez). */
    public static function createToken(int $userId, string $name, array $permissions, ?int $expiresDays = null): string
    {
        $name = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name) ?? '';
        $name = trim((string)preg_replace('/\s+/u', ' ', $name));
        $name = function_exists('mb_substr') ? mb_substr($name, 0, 80) : substr($name, 0, 80);
        if ($name === '') {
            $name = 'Token TI TF';
        }

        $raw = bin2hex(random_bytes(24));
        $expiresAt = null;
        if ($expiresDays !== null && $expiresDays > 0) {
            $expiresAt = gmdate('Y-m-d H:i:s', time() + ($expiresDays * 86400));
        }

        $st = Database::getInstance()->prepare(
            'INSERT INTO api_tokens (user_id, token_hash, name, permissions, expires_at)
             VALUES (?, ?, ?, ?, ?)'
        );
        $st->execute([
            $userId,
            hash('sha256', $raw),
            $name,
            json_encode($permissions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '[]',
            $expiresAt,
        ]);

        return $raw;
    }

    /** Tokens existentes, con sus permisos decodificados y ámbito señalado. */
    public static function listTokens(): array
    {
        $rows = Database::fetchAll(
            'SELECT id, name, permissions, expires_at, last_used_at, created_at
               FROM api_tokens ORDER BY id DESC'
        );
        foreach ($rows as &$row) {
            $perms = self::tokenPermissions((string)($row['permissions'] ?? ''));
            $row['permissions_data'] = $perms;
            $row['ti_scope'] = (string)($perms['scope'] ?? '') === 'ti_tracker';
            $row['summary'] = self::describePermissions($perms);
        }
        unset($row);

        return $rows;
    }

    public static function revokeToken(int $id): void
    {
        $st = Database::getInstance()->prepare('DELETE FROM api_tokens WHERE id = ?');
        $st->execute([$id]);
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

    /**
     * Resuelve un Collection ID TAXII de cualquier forma habitual:
     *  - "all", "default" o el UUID global → todas las listas publicadas
     *  - slug o nombre de la lista (sin distinción de mayúsculas)
     *  - id numérico o UUID TAXII de la lista
     *
     * @param array<int,array> $published
     * @return array{all:bool,searches:array<int,array>}|null
     */
    public static function resolveCollection(string $id, array $published): ?array
    {
        $key = strtolower(trim($id));
        if ($key === '') {
            return null;
        }
        if (in_array($key, ['all', 'default', 'ti_tf_all'], true) || $id === self::collectionId()) {
            return ['all' => true, 'searches' => $published];
        }

        foreach ($published as $search) {
            $searchId = (int)$search['id'];
            $slug = strtolower((string)($search['slug'] ?? ''));
            $name = strtolower((string)($search['name'] ?? ''));
            if ($key === (string)$searchId || $key === $slug || $key === $name
                || $id === self::collectionId($searchId)) {
                return ['all' => false, 'searches' => [$search]];
            }
        }

        return null;
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
                /* Momento en que la lista vio el IOC: fecha STIX y added_after TAXII. */
                $mapped['fetched_at'] = (string)(
                    $row['found_at'] ?? $row['ingested_at'] ?? $row['last_run_at'] ?? $row['first_seen'] ?? ''
                );
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
        foreach ($rows as &$row) {
            if (is_array($row)) {
                $row['found_at'] = (string)$snapshot['run_at'];
            }
        }
        unset($row);
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

    /** Objetos STIX 2.1 listos para el envelope TAXII (ids estables y fechas reales). */
    public static function taxiiObjects(array $iocs): array
    {
        $exporter = new Module_Export();

        return $exporter->buildStixIndicators($iocs, [
            'format'              => 'merged',
            'tlp'                 => 'green',
            'valid_days'          => 365,
            'source'              => 'EntraID TI - Seguimiento TI TF',
            'indicator_type'      => 'malicious-activity',
            'deterministic_ids'   => true,
            'use_ioc_timestamps'  => true,
        ]);
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
        /* TAXII: ids estables y created/modified = momento en que se vio el IOC. */
        if (!empty($config['taxii'])) {
            $stixConfig['deterministic_ids'] = true;
            $stixConfig['use_ioc_timestamps'] = true;
        }
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
            'ms-sentinel' => (static function () use ($exporter, $iocs, $stixConfig, $date): array {
                /* Payload para uploadIndicators de Microsoft Sentinel / Defender. */
                $stixConfig['deterministic_ids'] = true;
                $stixConfig['use_ioc_timestamps'] = true;
                $items = [];
                foreach ($exporter->buildStixIndicators($iocs, $stixConfig) as $ind) {
                    $items[] = [
                        'displayName'        => (string)($ind['name'] ?? ''),
                        'description'        => (string)($ind['description'] ?? ''),
                        'indicatorTypes'     => (array)($ind['indicator_types'] ?? []),
                        'pattern'            => (string)($ind['pattern'] ?? ''),
                        'patternType'        => 'stix',
                        'source'             => (string)$stixConfig['source'],
                        'confidence'         => (int)($ind['confidence'] ?? 75),
                        'severity'           => 'Informational',
                        'labels'             => (array)($ind['labels'] ?? []),
                        'validFrom'          => (string)($ind['valid_from'] ?? ''),
                        'validUntil'         => (string)($ind['valid_until'] ?? ''),
                        'tlpLevel'           => 'green',
                        'threatTypes'        => [],
                        'killChainPhases'    => [],
                        'externalReferences' => (array)($ind['external_references'] ?? []),
                    ];
                }
                return [
                    'content'  => json_encode($items, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?: '[]',
                    'mime'     => 'application/json',
                    'filename' => 'ti_tf_ms_sentinel_' . $date . '.json',
                ];
            })(),
            default => [
                'content'  => json_encode($iocs, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?: '[]',
                'mime'     => 'application/json',
                'filename' => 'ti_tf_iocs_' . $date . '.json',
            ],
        };
    }
}
