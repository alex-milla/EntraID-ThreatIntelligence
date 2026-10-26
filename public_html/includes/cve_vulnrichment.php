<?php
/**
 * CveVulnrichment — puntos SSVC publicados por CISA Vulnrichment y decisión
 * contextual (Act / Attend / Track* / Track).
 *
 * CISA publica en cada registro CVE JSON 5 (contenedor «CISA ADP
 * Vulnrichment») tres puntos de decisión SSVC: Exploitation, Automatable y
 * Technical Impact. No publica Mission & Well-Being Impact, así que la
 * decisión final se calcula con la tabla oficial CISA 2.0.3 usando el
 * contexto de criticidad de nuestro inventario.
 *
 * Diseño:
 *   · Solo se guardan los hechos de CISA (o la marca «missing»). La decisión
 *     depende del grupo/empresa y se calcula al vuelo.
 *   · Caché positiva de 30 días y negativa de 7 días.
 *   · Sin red en el listado del catálogo: la ficha y el análisis de grupo
 *     usan la caché; el cron rellena el resto.
 *   · Si CISA no ha enriquecido un CVE, se estima desde KEV, exploits y el
 *     vector CVSS, y se marca como «estimado» en la interfaz.
 */

declare(strict_types=1);

final class CveVulnrichment
{
    /** Etiquetas de las cuatro decisiones CISA. */
    public const DECISION_LABELS = [
        'track'      => 'Track',
        'track_star' => 'Track*',
        'attend'     => 'Attend',
        'act'        => 'Act',
    ];

    /**
     * Tabla oficial CISA Coordinator 2.0.3 (36 combinaciones).
     * Orden: Exploitation => Automatable => Technical Impact => [L, M, H].
     */
    private const DECISION_TABLE = [
        'none' => [
            'no' => [
                'partial' => ['track', 'track', 'track'],
                'total'   => ['track', 'track', 'track_star'],
            ],
            'yes' => [
                'partial' => ['track', 'track', 'attend'],
                'total'   => ['track', 'track', 'attend'],
            ],
        ],
        'poc' => [
            'no' => [
                'partial' => ['track', 'track', 'track_star'],
                'total'   => ['track', 'track_star', 'attend'],
            ],
            'yes' => [
                'partial' => ['track', 'track', 'attend'],
                'total'   => ['track', 'track_star', 'attend'],
            ],
        ],
        'active' => [
            'no' => [
                'partial' => ['track', 'track', 'attend'],
                'total'   => ['track', 'attend', 'act'],
            ],
            'yes' => [
                'partial' => ['attend', 'attend', 'act'],
                'total'   => ['attend', 'act', 'act'],
            ],
        ],
    ];

    // ============================================================
    // Rutas y descarga
    // ============================================================

    /**
     * Ruta relativa del registro en el repositorio de Vulnrichment.
     * Ej.: CVE-2021-44228 → 2021/44xxx/CVE-2021-44228.json
     *      CVE-2020-1472  → 2020/1xxx/CVE-2020-1472.json
     */
    public static function pathFor(string $cveId): ?string
    {
        $cveId = strtoupper(trim($cveId));
        if (!preg_match('/^CVE-(\d{4})-(\d{4,7})$/', $cveId, $m)) {
            return null;
        }
        $year = $m[1];
        $number = (int)$m[2];
        $bucket = intdiv($number, 1000) . 'xxx';
        return $year . '/' . $bucket . '/' . $cveId . '.json';
    }

    public static function urlFor(string $cveId): ?string
    {
        $path = self::pathFor($cveId);
        if ($path === null) {
            return null;
        }
        $base = defined('CVE_VULNRICHMENT_BASE')
            ? (string)CVE_VULNRICHMENT_BASE
            : 'https://raw.githubusercontent.com/cisagov/vulnrichment/develop';
        return rtrim($base, '/') . '/' . $path;
    }

    /**
     * Devuelve los puntos SSVC del CVE. Con $lazy = false solo consulta la
     * caché local (nunca hace red).
     *
     * @return array{cve_id:string,exploitation:?string,automatable:?string,technical_impact:?string,ssvc_version:?string,provider_updated_at:?string,source:string,fetched_at:?string}|null
     */
    public static function points(string $cveId, bool $lazy = true): ?array
    {
        $cveId = strtoupper(trim($cveId));
        if (self::pathFor($cveId) === null) {
            return null;
        }

        $row = self::fetchRow($cveId);
        if ($row !== null && !self::isStale($row)) {
            return $row;
        }
        if (!$lazy) {
            return $row;
        }

        $fresh = self::refresh($cveId);
        return $fresh ?? $row;
    }

    /**
     * Consulta CISA y actualiza la caché. Devuelve la fila resultante o null
     * si no se pudo consultar. Nunca lanza excepciones hacia la interfaz.
     *
     * @return array<string,mixed>|null
     */
    public static function refresh(string $cveId, bool $force = false): ?array
    {
        $cveId = strtoupper(trim($cveId));
        $url = self::urlFor($cveId);
        if ($url === null) {
            return null;
        }
        if (!$force) {
            $row = self::fetchRow($cveId);
            if ($row !== null && !self::isStale($row)) {
                return $row;
            }
        }

        $timeout = defined('CVE_VULNRICHMENT_TIMEOUT') ? max(2, (int)CVE_VULNRICHMENT_TIMEOUT) : 5;
        $res = self::httpGet($url, $timeout);

        if ((int)$res['status'] === 404) {
            self::storeMissing($cveId);
            return self::fetchRow($cveId);
        }
        if ((int)$res['status'] !== 200 || $res['error'] !== '') {
            return null;
        }

        $parsed = self::parseDocument((string)$res['body']);
        if ($parsed === null) {
            // JSON válido pero sin SSVC: CISA aún no lo ha enriquecido.
            if ($res['body'] !== '' && json_decode((string)$res['body']) !== null) {
                self::storeMissing($cveId);
                return self::fetchRow($cveId);
            }
            return null;
        }

        self::storePoints($cveId, $parsed);
        return self::fetchRow($cveId);
    }

    /**
     * Precarga en lote los CVEs que falten o estén caducados. Pensado para el
     * análisis de prioridad: una sola tanda con curl_multi y presupuesto
     * acotado. Devuelve cuántos se guardaron con datos de CISA.
     *
     * @param string[] $cveIds
     */
    public static function prefetch(array $cveIds, int $limit = 80, int $timeout = 4, int $concurrency = 8): int
    {
        $clean = [];
        foreach ($cveIds as $id) {
            $id = strtoupper(trim((string)$id));
            if (self::pathFor($id) !== null) {
                $clean[$id] = true;
            }
        }
        $ids = array_slice(array_keys($clean), 0, max(0, $limit));
        if ($ids === []) {
            return 0;
        }

        $need = [];
        foreach (array_chunk($ids, 150) as $chunk) {
            $placeholders = implode(',', array_fill(0, count($chunk), '?'));
            $rows = CveDatabase::fetchAll(
                "SELECT cve_id, source, fetched_at FROM cve_vulnrichment WHERE cve_id IN ($placeholders)",
                $chunk
            );
            $byId = [];
            foreach ($rows as $row) {
                $byId[(string)$row['cve_id']] = $row;
            }
            foreach ($chunk as $id) {
                $row = $byId[$id] ?? null;
                if ($row === null || self::isStale($row)) {
                    $need[] = $id;
                }
            }
        }
        if ($need === []) {
            return 0;
        }

        // Sin cURL (algunos PHP de hosting): secuencial con presupuesto corto.
        // No bloquea el análisis: lo que no dé tiempo se queda para el cron.
        if (!function_exists('curl_multi_init')) {
            $saved = 0;
            $deadline = microtime(true) + 8.0;
            foreach ($need as $id) {
                if (microtime(true) >= $deadline) {
                    break;
                }
                $after = self::refresh($id, true);
                if ((string)($after['source'] ?? '') === 'cisa') {
                    $saved++;
                }
            }
            return $saved;
        }

        $timeout = max(2, min(15, $timeout));
        $concurrency = max(1, min(16, $concurrency));
        $saved = 0;
        $deadline = microtime(true) + max(15, $timeout * 4);

        $mh = curl_multi_init();
        $handles = [];

        $addNext = static function () use ($mh, &$handles, &$need, $timeout): bool {
            $id = array_shift($need);
            if ($id === null) {
                return false;
            }
            $url = self::urlFor($id);
            if ($url === null) {
                return true;
            }
            $ch = self::makeHandle($url, $timeout);
            if ($ch === null) {
                return true;
            }
            curl_multi_add_handle($mh, $ch);
            $handles[(int)$ch] = ['id' => $id, 'ch' => $ch];
            return true;
        };

        for ($i = 0; $i < $concurrency; $i++) {
            if (!$addNext()) {
                break;
            }
        }

        while ($handles !== [] && microtime(true) < $deadline) {
            do {
                $status = curl_multi_exec($mh, $running);
                if ($running > 0) {
                    curl_multi_select($mh, 0.2);
                }
            } while ($status === CURLM_CALL_MULTI_PERFORM);

            while ($info = curl_multi_info_read($mh)) {
                if (($info['msg'] ?? 0) !== CURLMSG_DONE) {
                    continue;
                }
                $ch = $info['handle'];
                $key = (int)$ch;
                if (!isset($handles[$key])) {
                    continue;
                }
                $id = (string)$handles[$key]['id'];
                $code = (int)($info['result'] ?? -1);
                $http = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                $body = $code === CURLE_OK ? (string)curl_multi_getcontent($ch) : '';
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
                unset($handles[$key]);

                if ($code === CURLE_OK && $http === 200) {
                    $parsed = self::parseDocument($body);
                    if ($parsed !== null) {
                        self::storePoints($id, $parsed);
                        $saved++;
                    } else {
                        self::storeMissing($id);
                    }
                } elseif ($http === 404) {
                    self::storeMissing($id);
                }
                $addNext();
            }

            if ($handles === []) {
                break;
            }
        }

        foreach ($handles as $item) {
            curl_multi_remove_handle($mh, $item['ch']);
            curl_close($item['ch']);
        }
        curl_multi_close($mh);

        return $saved;
    }

    /**
     * Rellena por lotes los CVEs asignados a informes y los que casan con el
     * inventario. Pensado para cron.
     *
     * @return array{checked:int,updated:int,missing:int,errors:int}
     */
    public static function refreshPending(int $limit = 200, bool $force = false): array
    {
        $limit = max(1, min(2000, $limit));
        $ttl = defined('CVE_VULNRICHMENT_TTL_DAYS') ? max(1, (int)CVE_VULNRICHMENT_TTL_DAYS) : 30;
        $missingTtl = defined('CVE_VULNRICHMENT_MISSING_TTL_DAYS') ? max(1, (int)CVE_VULNRICHMENT_MISSING_TTL_DAYS) : 7;

        $where = $force
            ? '1 = 1'
            : "(v.cve_id IS NULL
                OR (v.source = 'cisa' AND v.fetched_at < datetime('now', ?))
                OR (v.source = 'missing' AND v.fetched_at < datetime('now', ?)))";
        $params = $force ? [] : ['-' . $ttl . ' days', '-' . $missingTtl . ' days'];

        $rows = CveDatabase::fetchAll(
            "SELECT candidates.cve_id
             FROM (
                 SELECT cve_id FROM cve_ai_report_items
                 UNION
                 SELECT cve_id FROM cve_watchlist_match
             ) AS candidates
             LEFT JOIN cve_vulnrichment v ON v.cve_id = candidates.cve_id
             WHERE $where
             ORDER BY (v.cve_id IS NULL) DESC, v.fetched_at ASC
             LIMIT ?",
            array_merge($params, [$limit])
        );

        $result = ['checked' => 0, 'updated' => 0, 'missing' => 0, 'errors' => 0];
        $consecutiveErrors = 0;
        foreach ($rows as $row) {
            $cveId = strtoupper((string)($row['cve_id'] ?? ''));
            if (self::pathFor($cveId) === null) {
                continue;
            }
            $result['checked']++;
            $before = self::fetchRow($cveId);
            $after = self::refresh($cveId, true);
            if ($after === null) {
                $result['errors']++;
                $consecutiveErrors++;
                // Si la red está caída, no encadenar timeouts durante minutos.
                if ($consecutiveErrors >= 3) {
                    break;
                }
                continue;
            }
            $consecutiveErrors = 0;
            if ((string)($after['source'] ?? '') === 'missing') {
                $result['missing']++;
                continue;
            }
            if ($before === null || (string)($before['source'] ?? '') !== 'cisa') {
                $result['updated']++;
            }
        }

        return $result;
    }

    // ============================================================
    // Decisión SSVC
    // ============================================================

    /**
     * Aplica la tabla CISA 2.0.3 con el contexto (MWI) indicado.
     */
    public static function decision(?array $points, ?string $mwi): ?string
    {
        if ($points === null) {
            return null;
        }
        $exploitation = self::normalizeExploitation($points['exploitation'] ?? null);
        $automatable = self::normalizeAutomatable($points['automatable'] ?? null);
        $impact = self::normalizeImpact($points['technical_impact'] ?? null);
        $mwi = self::normalizeMwi($mwi);
        if ($exploitation === null || $automatable === null || $impact === null || $mwi === null) {
            return null;
        }

        $index = ['L' => 0, 'M' => 1, 'H' => 2][$mwi];
        return self::DECISION_TABLE[$exploitation][$automatable][$impact][$index] ?? null;
    }

    /**
     * Estimación cuando CISA no ha enriquecido el CVE. Se marca como tal.
     *
     * @return array<string,mixed>|null
     */
    public static function estimate(string $cveId): ?array
    {
        $cveId = strtoupper(trim($cveId));
        if (self::pathFor($cveId) === null) {
            return null;
        }

        $row = CveDatabase::fetchOne(
            "SELECT
                (SELECT COUNT(*) FROM cve_kev WHERE cve_id = ?) AS kev,
                (SELECT COUNT(*) FROM cve_exploit WHERE cve_id = ?) AS exploits,
                (SELECT COUNT(*) FROM cve_exploit_index WHERE cve_id = ?) AS index_exploits,
                (SELECT cvss_v3_vector FROM cve_catalog WHERE cve_id = ?) AS vector,
                (SELECT cvss_v3_score FROM cve_catalog WHERE cve_id = ?) AS score",
            [$cveId, $cveId, $cveId, $cveId, $cveId]
        );
        if ($row === null) {
            return null;
        }

        $kev = (int)($row['kev'] ?? 0) > 0;
        $hasExploit = (int)($row['exploits'] ?? 0) > 0 || (int)($row['index_exploits'] ?? 0) > 0;
        $vector = trim((string)($row['vector'] ?? ''));
        $score = $row['score'] ?? null;

        if (!$kev && !$hasExploit && $vector === '' && $score === null) {
            return null;
        }

        $exploitation = $kev ? 'active' : ($hasExploit ? 'poc' : 'none');

        $automatable = 'no';
        $impact = 'partial';
        if ($vector !== '') {
            $av = self::vectorPart($vector, 'AV');
            $ac = self::vectorPart($vector, 'AC');
            $pr = self::vectorPart($vector, 'PR');
            $automatable = ($av === 'N' && $ac === 'L' && $pr === 'N') ? 'yes' : 'no';

            $c = self::vectorPart($vector, 'C');
            $i = self::vectorPart($vector, 'I');
            $a = self::vectorPart($vector, 'A');
            $impact = ($c === 'H' && $i === 'H' && $a === 'H') ? 'total' : 'partial';
        }

        return [
            'cve_id'             => $cveId,
            'exploitation'       => $exploitation,
            'automatable'        => $automatable,
            'technical_impact'   => $impact,
            'ssvc_version'       => null,
            'provider_updated_at' => null,
            'source'             => 'estimated',
            'fetched_at'         => null,
        ];
    }

    /**
     * Ficha completa para la interfaz: puntos, decisión y procedencia.
     *
     * @return array{points:?array,decision:?string,mwi:?string,estimated:bool,source:?string}
     */
    public static function forCveWithContext(string $cveId, ?string $mwi, bool $lazy = true): array
    {
        $cveId = strtoupper(trim($cveId));
        $row = self::points($cveId, $lazy);
        $estimated = false;

        if ($row === null || (string)($row['source'] ?? '') === 'missing') {
            $row = self::estimate($cveId);
            $estimated = $row !== null;
        }

        $mwi = self::normalizeMwi($mwi);
        $decision = ($row !== null && $mwi !== null) ? self::decision($row, $mwi) : null;

        return [
            'points'    => $row,
            'decision'  => $decision,
            'mwi'       => $mwi,
            'estimated' => $estimated,
            'source'    => $row['source'] ?? null,
        ];
    }

    // ============================================================
    // Contexto desde el inventario
    // ============================================================

    /**
     * MWI del grupo/empresa: máxima criticidad del software del subárbol.
     * critical/high → H · medium → M · low/info → L.
     */
    public static function mwiForGroup(int $groupId): ?string
    {
        if ($groupId <= 0) {
            return null;
        }
        $rows = CveDatabase::fetchAll(
            "WITH RECURSIVE grp(id) AS (
                SELECT id FROM software_groups WHERE id = ?
                UNION
                SELECT g.id FROM software_groups g JOIN grp ON g.parent_id = grp.id
             )
             SELECT w.criticality
             FROM software_watchlist w
             JOIN grp ON grp.id = w.group_id
             WHERE w.is_active = 1 AND w.criticality IS NOT NULL AND w.criticality <> ''",
            [$groupId]
        );
        return self::maxMwi($rows);
    }

    /**
     * MWI a partir del software inventariado que casa con el CVE.
     */
    public static function mwiForCve(string $cveId): ?string
    {
        $cveId = strtoupper(trim($cveId));
        if (self::pathFor($cveId) === null) {
            return null;
        }
        $rows = CveDatabase::fetchAll(
            "SELECT w.criticality
             FROM cve_watchlist_match m
             JOIN software_watchlist w ON w.id = m.watchlist_id
             WHERE m.cve_id = ? AND w.is_active = 1
               AND w.criticality IS NOT NULL AND w.criticality <> ''",
            [$cveId]
        );
        return self::maxMwi($rows);
    }

    public static function criticalityToMwi(?string $criticality): ?string
    {
        $value = strtolower(trim((string)$criticality));
        return match ($value) {
            'critical', 'high' => 'H',
            'medium'           => 'M',
            'low', 'info'      => 'L',
            default            => null,
        };
    }

    private static function maxMwi(array $rows): ?string
    {
        $rank = ['L' => 1, 'M' => 2, 'H' => 3];
        $best = null;
        foreach ($rows as $row) {
            $mwi = self::criticalityToMwi($row['criticality'] ?? null);
            if ($mwi !== null && ($best === null || $rank[$mwi] > $rank[$best])) {
                $best = $mwi;
            }
        }
        return $best;
    }

    // ============================================================
    // Parser
    // ============================================================

    public static function parseDocument(string $json): ?array
    {
        $data = json_decode($json, true);
        if (!is_array($data)) {
            return null;
        }
        return self::parseSsvc($data);
    }

    /**
     * Extrae los tres puntos SSVC del contenedor CISA-ADP.
     *
     * @param array<string,mixed> $record
     * @return array{exploitation:string,automatable:string,technical_impact:string,ssvc_version:?string,provider_updated_at:?string}|null
     */
    public static function parseSsvc(array $record): ?array
    {
        $adp = $record['containers']['adp'] ?? null;
        if (!is_array($adp)) {
            return null;
        }

        foreach ($adp as $container) {
            if (!is_array($container)) {
                continue;
            }
            $shortName = strtoupper((string)($container['providerMetadata']['shortName'] ?? ''));
            $title = (string)($container['title'] ?? '');
            $isCisa = $shortName === 'CISA-ADP' || stripos($title, 'CISA ADP') !== false;
            if (!$isCisa) {
                continue;
            }

            $metrics = $container['metrics'] ?? null;
            if (!is_array($metrics)) {
                continue;
            }

            foreach ($metrics as $metric) {
                if (!is_array($metric)) {
                    continue;
                }
                $other = $metric['other'] ?? null;
                if (!is_array($other) || strtolower((string)($other['type'] ?? '')) !== 'ssvc') {
                    continue;
                }
                $content = $other['content'] ?? null;
                if (!is_array($content)) {
                    continue;
                }

                $values = [];
                $options = $content['options'] ?? null;
                if (is_array($options)) {
                    // Lo habitual es una lista de mapas de una sola clave,
                    // pero también admitimos un mapa plano.
                    if (isset($options['Exploitation']) || isset($options['exploitation'])) {
                        $options = [$options];
                    }
                    foreach ($options as $option) {
                        if (is_array($option)) {
                            foreach ($option as $key => $value) {
                                $values[self::normalizeKey((string)$key)] = strtolower(trim((string)$value));
                            }
                        }
                    }
                }

                $exploitation = self::normalizeExploitation($values['exploitation'] ?? null);
                $automatable = self::normalizeAutomatable($values['automatable'] ?? null);
                $impact = self::normalizeImpact($values['technicalimpact'] ?? ($values['technical_impact'] ?? null));
                if ($exploitation === null || $automatable === null || $impact === null) {
                    continue;
                }

                return [
                    'exploitation'        => $exploitation,
                    'automatable'         => $automatable,
                    'technical_impact'    => $impact,
                    'ssvc_version'        => isset($content['version']) ? (string)$content['version'] : null,
                    'provider_updated_at' => isset($content['timestamp']) ? (string)$content['timestamp'] : null,
                ];
            }
        }

        return null;
    }

    private static function normalizeKey(string $key): string
    {
        return strtolower(preg_replace('/[^a-z0-9]/i', '', $key) ?? $key);
    }

    private static function normalizeExploitation(mixed $value): ?string
    {
        $value = strtolower(trim((string)$value));
        $map = ['none' => 'none', 'n' => 'none', 'poc' => 'poc', 'p' => 'poc', 'active' => 'active', 'a' => 'active'];
        return $map[$value] ?? null;
    }

    private static function normalizeAutomatable(mixed $value): ?string
    {
        $value = strtolower(trim((string)$value));
        $map = ['yes' => 'yes', 'y' => 'yes', 'true' => 'yes', 'no' => 'no', 'n' => 'no', 'false' => 'no'];
        return $map[$value] ?? null;
    }

    private static function normalizeImpact(mixed $value): ?string
    {
        $value = strtolower(trim((string)$value));
        $map = ['partial' => 'partial', 'p' => 'partial', 'total' => 'total', 't' => 'total'];
        return $map[$value] ?? null;
    }

    private static function normalizeMwi(?string $mwi): ?string
    {
        $value = strtoupper(trim((string)$mwi));
        return in_array($value, ['L', 'M', 'H'], true) ? $value : null;
    }

    private static function vectorPart(string $vector, string $key): string
    {
        if (preg_match('/(?:^|\/)' . preg_quote($key, '/') . ':([A-Z])/', strtoupper($vector), $m)) {
            return $m[1];
        }
        return '';
    }

    // ============================================================
    // Caché
    // ============================================================

    /** @return array<string,mixed>|null */
    private static function fetchRow(string $cveId): ?array
    {
        $row = CveDatabase::fetchOne(
            "SELECT cve_id, exploitation, automatable, technical_impact,
                    ssvc_version, provider_updated_at, source, fetched_at
             FROM cve_vulnrichment WHERE cve_id = ?",
            [$cveId]
        );
        return $row ?: null;
    }

    private static function isStale(array $row): bool
    {
        $ttl = (string)($row['source'] ?? '') === 'missing'
            ? (defined('CVE_VULNRICHMENT_MISSING_TTL_DAYS') ? max(1, (int)CVE_VULNRICHMENT_MISSING_TTL_DAYS) : 7)
            : (defined('CVE_VULNRICHMENT_TTL_DAYS') ? max(1, (int)CVE_VULNRICHMENT_TTL_DAYS) : 30);
        $ts = strtotime((string)($row['fetched_at'] ?? '') . ' UTC');
        if ($ts === false) {
            return true;
        }
        return $ts < time() - ($ttl * 86400);
    }

    private static function storePoints(string $cveId, array $points): void
    {
        CveDatabase::query(
            "INSERT OR REPLACE INTO cve_vulnrichment
                (cve_id, exploitation, automatable, technical_impact, ssvc_version,
                 provider_updated_at, source, fetched_at)
             VALUES (?, ?, ?, ?, ?, ?, 'cisa', datetime('now'))",
            [
                $cveId,
                (string)$points['exploitation'],
                (string)$points['automatable'],
                (string)$points['technical_impact'],
                $points['ssvc_version'] ?? null,
                $points['provider_updated_at'] ?? null,
            ]
        );
    }

    private static function storeMissing(string $cveId): void
    {
        CveDatabase::query(
            "INSERT OR REPLACE INTO cve_vulnrichment
                (cve_id, exploitation, automatable, technical_impact, ssvc_version,
                 provider_updated_at, source, fetched_at)
             VALUES (?, NULL, NULL, NULL, NULL, NULL, 'missing', datetime('now'))",
            [$cveId]
        );
    }

    // ============================================================
    // HTTP
    // ============================================================

    /** @return array{status:int,body:string,error:string} */
    private static function httpGet(string $url, int $timeout): array
    {
        if (function_exists('curl_init')) {
            $ch = self::makeHandle($url, $timeout);
            if ($ch === null) {
                return ['status' => 0, 'body' => '', 'error' => 'cURL no disponible'];
            }
            $body = curl_exec($ch);
            $error = (string)curl_error($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);
            return [
                'status' => $status,
                'body'   => is_string($body) ? $body : '',
                'error'  => $error,
            ];
        }

        $context = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'timeout'       => $timeout,
                'user_agent'    => 'EntraID-ThreatIntelligence/0.2.8.36',
                'ignore_errors' => true,
            ],
        ]);
        $body = @file_get_contents($url, false, $context);
        $status = 0;
        if (isset($http_response_header) && is_array($http_response_header)) {
            foreach ($http_response_header as $line) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                    $status = (int)$m[1];
                }
            }
        }
        return [
            'status' => $status,
            'body'   => is_string($body) ? $body : '',
            'error'  => $body === false ? 'No se pudo descargar el registro' : '',
        ];
    }

    /** @return CurlHandle|null */
    private static function makeHandle(string $url, int $timeout): mixed
    {
        if (!function_exists('curl_init')) {
            return null;
        }
        $ch = curl_init($url);
        if ($ch === false) {
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT        => max(2, $timeout),
            CURLOPT_USERAGENT      => 'EntraID-ThreatIntelligence/0.2.8.36',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_ENCODING       => '',
        ]);
        return $ch;
    }

    // ============================================================
    // Etiquetas para la interfaz
    // ============================================================

    public static function decisionLabel(?string $decision): string
    {
        return self::DECISION_LABELS[(string)$decision] ?? 'Sin decisión';
    }

    public static function decisionDescription(?string $decision): string
    {
        return match ((string)$decision) {
            'act'        => 'Actuar ya: requiere atención inmediata.',
            'attend'     => 'Atender antes de los plazos habituales.',
            'track_star' => 'Vigilar de cerca: puede cambiar de categoría.',
            'track'      => 'Seguimiento ordinario.',
            default      => 'Falta contexto de criticidad para decidir.',
        };
    }

    public static function exploitationLabel(?string $value): string
    {
        return match ((string)$value) {
            'active' => 'Explotación activa',
            'poc'    => 'PoC público',
            'none'   => 'Sin explotación conocida',
            default  => 'Sin datos',
        };
    }

    public static function automatableLabel(?string $value): string
    {
        return match ((string)$value) {
            'yes'   => 'Sí',
            'no'    => 'No',
            default => 'Sin datos',
        };
    }

    public static function impactLabel(?string $value): string
    {
        return match ((string)$value) {
            'total'   => 'Total',
            'partial' => 'Parcial',
            default   => 'Sin datos',
        };
    }

    public static function mwiLabel(?string $mwi): string
    {
        return match ((string)$mwi) {
            'H'     => 'Alto',
            'M'     => 'Medio',
            'L'     => 'Bajo',
            default => 'Sin contexto',
        };
    }

    public static function sourceLabel(?string $source): string
    {
        return match ((string)$source) {
            'cisa'      => 'CISA Vulnrichment',
            'estimated' => 'Estimado (sin Vulnrichment)',
            default     => 'Sin datos',
        };
    }
}
