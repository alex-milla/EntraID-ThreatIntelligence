<?php
/**
 * Módulo: Exportación
 * Exporta IOCs y datos a formatos STIX 2.1, MISP, CSV y TXT.
 * Basado en la documentación de métodos de exportación del proyecto.
 */

declare(strict_types=1);

class Module_Export extends BaseModule
{
    public function key(): string { return 'export'; }
    public function name(): string { return 'Exportación'; }
    public function description(): string { return 'Exportación a STIX, MISP, CSV y TXT'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return [];
    }

    public function isSyncable(): bool
    {
        return false;
    }

    public function sync(int $tenantId): array
    {
        return ['success' => true, 'records' => 0];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Exportar',
            'url'   => base_url('modules/export'),
            'icon'  => 'download',
            'group' => 'Análisis',
        ];
    }

    // ============================================================
    // Exportación TXT
    // ============================================================

    /**
     * Exporta IOCs a TXT (un valor por línea).
     */
    public function exportTxt(int $tenantId, array $filters = []): array
    {
        $iocs = $this->getIocsForExport($tenantId, $filters);
        $content = $this->buildTxtContent($iocs);

        return [
            'success' => true,
            'content' => $content,
            'filename' => 'iocs_' . date('Y-m-d') . '.txt',
            'mime' => 'text/plain',
            'count' => count($iocs),
        ];
    }

    // ============================================================
    // Exportación CSV
    // ============================================================

    /**
     * Exporta IOCs a CSV.
     */
    public function exportCsv(int $tenantId, array $filters = []): array
    {
        $iocs = $this->getIocsForExport($tenantId, $filters);
        $csv = $this->buildCsvContent($iocs);

        return [
            'success' => true,
            'content' => $csv,
            'filename' => 'iocs_' . date('Y-m-d') . '.csv',
            'mime' => 'text/csv',
            'count' => count($iocs),
        ];
    }

    /**
     * Escapa un campo CSV.
     */
    private function csvField(mixed $value): string
    {
        $s = (string)($value ?? '');
        if (preg_match('/[",\n\r]/', $s)) {
            return '"' . str_replace('"', '""', $s) . '"';
        }
        return $s;
    }

    // ============================================================
    // Exportación STIX 2.1
    // ============================================================

    /**
     * Genera el patrón STIX para un tipo de IOC.
     */
    public function generateStixPattern(string $type, string $value): ?string
    {
        return match ($type) {
            'ipv4-addr'             => "[ipv4-addr:value = '$value']",
            'ipv6-addr'             => "[ipv6-addr:value = '$value']",
            'domain-name'           => "[domain-name:value = '$value']",
            'url'                   => "[url:value = '$value']",
            'email-addr'            => "[email-addr:value = '$value']",
            'user-account'          => "[user-account:value = '$value']",
            'windows-registry-key'  => "[windows-registry-key:key = '$value']",
            'mac-addr'              => "[mac-addr:value = '$value']",
            'autonomous-system'     => "[autonomous-system:number = '" . str_replace('AS', '', $value) . "']",
            'file'                  => $this->fileHashPattern($value),
            default                 => null,
        };
    }

    /**
     * Determina el tipo de hash por longitud.
     */
    private function fileHashPattern(string $value): string
    {
        return match (strlen($value)) {
            32  => "[file:hashes.MD5 = '$value']",
            40  => "[file:hashes.SHA-1 = '$value']",
            64  => "[file:hashes.'SHA-256' = '$value']",
            128 => "[file:hashes.'SHA-512' = '$value']",
            default => "[file:name = '$value']",
        };
    }

    /**
     * Exporta IOCs a STIX 2.1 (bundle de indicators).
     */
    public function exportStix(int $tenantId, array $filters = [], array $config = []): array
    {
        return $this->buildStixResult($this->getIocsForExport($tenantId, $filters), $config);
    }

    // ============================================================
    // Exportación MISP
    // ============================================================

    /**
     * Mapea tipo de IOC a tipo de atributo MISP.
     */
    private function mispType(string $type, string $value): string
    {
        return match ($type) {
            'ipv4-addr', 'ipv6-addr'  => 'ip-dst',
            'domain-name'              => 'domain',
            'url'                      => 'url',
            'email-addr'               => 'email-src',
            'user-account'             => 'username',
            'windows-registry-key'     => 'regkey',
            'mac-addr'                 => 'mac-address',
            'autonomous-system'        => 'AS',
            'file'                     => $this->hashMispType($value),
            default                    => 'text',
        };
    }

    /**
     * Determina el tipo de hash MISP por longitud.
     */
    private function hashMispType(string $value): string
    {
        return match (strlen($value)) {
            32  => 'md5',
            40  => 'sha1',
            64  => 'sha256',
            128 => 'sha512',
            default => 'text',
        };
    }

    /**
     * Categoría MISP para un tipo.
     */
    private function mispCategory(string $type): string
    {
        return match ($type) {
            'ipv4-addr', 'ipv6-addr', 'domain-name', 'url', 'user-account', 'mac-addr', 'autonomous-system' => 'Network activity',
            'email-addr', 'file' => 'Payload delivery',
            'windows-registry-key' => 'Persistence mechanism',
            default => 'Other',
        };
    }

    /**
     * Exporta IOCs a formato MISP.
     */
    public function exportMisp(int $tenantId, array $filters = [], array $config = []): array
    {
        return $this->buildMispResult($this->getIocsForExport($tenantId, $filters), $config);
    }

    // ============================================================
    // Builders puros (sobre una lista explícita de IOCs)
    // ============================================================

    /** Acepta filas de BD (ioc_type/ioc_value) y del asistente (type/value). */
    private function buildRows(array $iocs): array
    {
        $rows = [];
        foreach ($iocs as $ioc) {
            if (!is_array($ioc)) { continue; }
            $rows[] = [
                'type'        => (string)($ioc['type'] ?? $ioc['ioc_type'] ?? ''),
                'value'       => (string)($ioc['value'] ?? $ioc['ioc_value'] ?? ''),
                'description' => (string)($ioc['description'] ?? ''),
                'source'      => (string)($ioc['source'] ?? ''),
                'severity'    => (string)($ioc['severity'] ?? ''),
                'fetched_at'  => (string)($ioc['fetched_at'] ?? ''),
            ];
        }
        return $rows;
    }

    public function buildTxtContent(array $iocs): string
    {
        $values = [];
        foreach ($this->buildRows($iocs) as $row) {
            if ($row['value'] !== '') { $values[] = $row['value']; }
        }
        return implode("\n", $values);
    }

    public function buildCsvContent(array $iocs): string
    {
        $rows = [['#', 'Type', 'Value', 'Description', 'Source', 'Severity', 'Fetched At']];
        foreach ($this->buildRows($iocs) as $i => $ioc) {
            $rows[] = [
                $i + 1, $ioc['type'], $ioc['value'], $ioc['description'],
                $ioc['source'], $ioc['severity'], $ioc['fetched_at'],
            ];
        }
        return implode("\n", array_map(function (array $row): string {
            return implode(',', array_map(fn($f) => $this->csvField($f), $row));
        }, $rows));
    }

    /** @return array<int,array<string,mixed>> objetos indicator STIX 2.1 */
    public function buildStixIndicators(array $iocs, array $config = []): array
    {
        $tlp = (string)($config['tlp'] ?? 'green');
        $markingRef = TLP_MARKINGS[$tlp] ?? TLP_MARKINGS['green'];
        $validDays = (int)($config['valid_days'] ?? 365);
        $confidence = (int)($config['confidence'] ?? 75);
        $labels = $config['labels'] ?? [];
        if (is_string($labels)) {
            $labels = array_values(array_filter(array_map('trim', explode(',', $labels)), 'strlen'));
        }
        $source = (string)($config['source'] ?? 'EntraID TI');
        $indicatorType = (string)($config['indicator_type'] ?? 'malicious-activity');
        $actor = trim((string)($config['threat_actor'] ?? ''));
        $lang = (string)($config['lang'] ?? 'es');

        $now = gmdate('Y-m-d\TH:i:s\Z');
        $validUntil = gmdate('Y-m-d\TH:i:s\Z', time() + ($validDays * 86400));

        $indicators = [];
        foreach ($this->buildRows($iocs) as $ioc) {
            if ($ioc['type'] === '' || $ioc['value'] === '') { continue; }
            $pattern = $this->generateStixPattern($ioc['type'], $ioc['value']);
            if (!$pattern) { continue; }

            $indicator = [
                'type'                => 'indicator',
                'id'                  => 'indicator--' . generate_uuid(),
                'spec_version'        => '2.1',
                'pattern'             => $pattern,
                'pattern_type'        => 'stix',
                'pattern_version'     => '2.1',
                'created'             => $now,
                'modified'            => $now,
                'valid_from'          => $now,
                'valid_until'         => $validUntil,
                'name'                => $source . ' - ' . $ioc['value'],
                'description'         => $ioc['description'],
                'indicator_types'     => [$indicatorType],
                'revoked'             => false,
                'labels'              => $labels,
                'confidence'          => $confidence,
                'lang'                => $lang,
                'object_marking_refs' => [$markingRef],
                'external_references' => [],
            ];
            if ($actor !== '') {
                $indicator['threat_actor_names'] = [$actor];
            }
            $indicators[] = $indicator;
        }
        return $indicators;
    }

    public function buildStixBundle(array $indicators): array
    {
        return ['type' => 'bundle', 'id' => 'bundle--' . generate_uuid(), 'objects' => $indicators];
    }

    public function buildStixResult(array $iocs, array $config = []): array
    {
        $indicators = $this->buildStixIndicators($iocs, $config);
        if (($config['format'] ?? 'merged') === 'split') {
            $byType = [];
            foreach ($indicators as $ind) {
                preg_match('/\[([a-z0-9-]+):/', (string)$ind['pattern'], $m);
                $byType[$m[1] ?? 'unknown'][] = $ind;
            }
            $files = [];
            foreach ($byType as $type => $inds) {
                $files[$type] = [
                    'content'  => json_encode($this->buildStixBundle($inds), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
                    'filename' => 'iocs_stix_' . $type . '_' . date('Y-m-d') . '.json',
                    'mime'     => 'application/json',
                ];
            }
            return ['success' => true, 'format' => 'split', 'files' => $files, 'count' => count($indicators)];
        }
        return [
            'success'  => true,
            'format'   => 'merged',
            'content'  => json_encode($this->buildStixBundle($indicators), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            'filename' => 'iocs_stix_' . date('Y-m-d') . '.json',
            'mime'     => 'application/json',
            'count'    => count($indicators),
        ];
    }

    /** @return array<string,mixed> evento MISP (contenedor Event) */
    public function buildMispEvent(array $iocs, array $config = []): array
    {
        $tlp = (string)($config['tlp'] ?? 'amber');
        $distribution = MISP_TLP_DISTRIBUTION[$tlp] ?? '1';
        $tags = array_merge(['tlp:' . $tlp], is_array($config['labels'] ?? null) ? $config['labels'] : []);
        $actor = trim((string)($config['threat_actor'] ?? ''));
        if ($actor !== '') { $tags[] = 'threat-actor:' . $actor; }
        $ipDirection = (string)($config['ip_direction'] ?? 'ip-dst');
        $info = (string)($config['info'] ?? 'EntraID TI - IOC Export');

        $attributes = [];
        foreach ($this->buildRows($iocs) as $ioc) {
            if ($ioc['type'] === '' || $ioc['value'] === '') { continue; }
            if (in_array($ioc['type'], ['ipv4-addr', 'ipv6-addr'], true)) {
                $dirs = $ipDirection === 'both' ? ['ip-src', 'ip-dst'] : [$ipDirection];
                foreach ($dirs as $dir) {
                    $attributes[] = [
                        'type' => $dir, 'category' => 'Network activity',
                        'value' => $ioc['value'], 'to_ids' => true, 'comment' => $ioc['description'],
                    ];
                }
            } else {
                $attributes[] = [
                    'type'     => $this->mispType($ioc['type'], $ioc['value']),
                    'category' => $this->mispCategory($ioc['type']),
                    'value'    => $ioc['type'] === 'autonomous-system' ? str_replace('AS', '', $ioc['value']) : $ioc['value'],
                    'to_ids'   => true,
                    'comment'  => $ioc['description'],
                ];
            }
        }

        return [
            'Event' => [
                'info'            => $info,
                'date'            => date('Y-m-d'),
                'distribution'    => $distribution,
                'threat_level_id' => '2',
                'analysis'        => '2',
                'published'       => false,
                'Attribute'       => $attributes,
                'Tag'             => array_map(fn($t) => ['name' => $t], $tags),
            ],
        ];
    }

    public function buildMispResult(array $iocs, array $config = []): array
    {
        $event = $this->buildMispEvent($iocs, $config);
        $count = count($event['Event']['Attribute'] ?? []);
        $json = static fn(array $e): string => json_encode($e, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (($config['format'] ?? 'merged') === 'split') {
            $byType = [];
            foreach ($event['Event']['Attribute'] as $attr) {
                $byType[$attr['type']][] = $attr;
            }
            $files = [];
            foreach ($byType as $type => $attrs) {
                $part = $event;
                $part['Event']['Attribute'] = $attrs;
                $files[$type] = [
                    'content'  => $json($part),
                    'filename' => 'misp_' . $type . '_' . date('Y-m-d') . '.json',
                    'mime'     => 'application/json',
                ];
            }
            return ['success' => true, 'format' => 'split', 'files' => $files, 'count' => $count];
        }
        return [
            'success'  => true,
            'format'   => 'merged',
            'content'  => $json($event),
            'filename' => 'misp_event_' . date('Y-m-d') . '.json',
            'mime'     => 'application/json',
            'count'    => $count,
        ];
    }

    // ============================================================
    // Utilidades comunes
    // ============================================================

    /**
     * Obtiene IOCs para exportar con filtros.
     */
    private function getIocsForExport(int $tenantId, array $filters): array
    {
        /* Unit42: IOCs públicos, sin tenant; el exportador ya entiende sus tipos. */
        if (($filters['source'] ?? '') === 'u42') {
            $where = ['1=1'];
            $params = [];

            if (!empty($filters['type'])) {
                $where[] = 'i.ioc_type = ?';
                $params[] = $filters['type'];
            }
            if (!empty($filters['search'])) {
                $like = '%' . $filters['search'] . '%';
                $where[] = '(i.ioc_value LIKE ? OR i.description LIKE ?)';
                array_push($params, $like, $like);
            }
            if (!empty($filters['from'])) {
                $where[] = 'date(i.first_seen) >= ?';
                $params[] = $filters['from'];
            }
            if (!empty($filters['to'])) {
                $where[] = 'date(i.first_seen) <= ?';
                $params[] = $filters['to'];
            }
            if (!empty($filters['article_id'])) {
                $where[] = 'i.article_id = ?';
                $params[] = (int)$filters['article_id'];
            }
            $sql = "SELECT i.id, i.ioc_type, i.ioc_value, i.description, i.first_seen,
                           a.title AS source, a.path AS article_path
                    FROM u42_iocs i
                    JOIN u42_articles a ON a.id = i.article_id
                    WHERE " . implode(' AND ', $where) . "
                    ORDER BY i.ioc_type, i.ioc_value";
            if (!empty($filters['limit'])) {
                $sql .= ' LIMIT ' . (int)$filters['limit'];
            }
            return Database::fetchAll($sql, $params);
        }

        $where = ['tenant_id = ?'];
        $params = [$tenantId];

        if (!empty($filters['type'])) {
            $where[] = 'ioc_type = ?';
            $params[] = $filters['type'];
        }
        if (!empty($filters['search'])) {
            $like = '%' . $filters['search'] . '%';
            $where[] = '(ioc_value LIKE ? OR description LIKE ? OR source LIKE ?)';
            array_push($params, $like, $like, $like);
        }
        if (!empty($filters['from'])) {
            $where[] = 'date(COALESCE(last_seen, first_seen, fetched_at)) >= ?';
            $params[] = $filters['from'];
        }
        if (!empty($filters['to'])) {
            $where[] = 'date(COALESCE(last_seen, first_seen, fetched_at)) <= ?';
            $params[] = $filters['to'];
        }
        if (!empty($filters['article_id'])) {
            $where[] = 'article_id = ?';
            $params[] = (int)$filters['article_id'];
        }
        $whereClause = implode(' AND ', $where);

        // Export por artículo: tal cual (son los IOCs de ese artículo).
        if (!empty($filters['article_id'])) {
            if (!empty($filters['limit'])) {
                $params[] = (int)$filters['limit'];
                return Database::fetchAll("SELECT * FROM ti_iocs WHERE $whereClause ORDER BY fetched_at DESC LIMIT ?", $params);
            }
            return Database::fetchAll("SELECT * FROM ti_iocs WHERE $whereClause ORDER BY fetched_at DESC", $params);
        }

        // Export global: sin duplicados (una fila por tipo+valor).
        $sql = "SELECT MIN(id) AS id, ioc_type, ioc_value, MAX(source) AS source, MAX(description) AS description,
                       MAX(severity) AS severity, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
                       MAX(article_id) AS article_id, MAX(profile_id) AS profile_id, MAX(fetched_at) AS fetched_at
                FROM ti_iocs WHERE $whereClause
                GROUP BY ioc_type, ioc_value
                ORDER BY fetched_at DESC";
        if (!empty($filters['limit'])) {
            $params[] = (int)$filters['limit'];
            $sql .= " LIMIT ?";
        }
        return Database::fetchAll($sql, $params);
    }

    /**
     * Tipos de IOC disponibles para filtrar.
     */
    public function getIocTypes(int $tenantId): array
    {
        return Database::fetchAll(
            "SELECT DISTINCT ioc_type FROM ti_iocs WHERE tenant_id = ? ORDER BY ioc_type",
            [$tenantId]
        );
    }

    /**
     * Cuenta IOCs por tenant.
     */
    public function countIocs(int $tenantId): int
    {
        return (int)Database::fetchOne(
            "SELECT COUNT(*) as cnt FROM ti_iocs WHERE tenant_id = ?",
            [$tenantId]
        )['cnt'];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                        'handler' => [$this, 'index']],
            ['method' => 'POST', 'pattern' => 'txt',                     'handler' => [$this, 'exportTxtEndpoint']],
            ['method' => 'POST', 'pattern' => 'csv',                     'handler' => [$this, 'exportCsvEndpoint']],
            ['method' => 'POST', 'pattern' => 'stix',                    'handler' => [$this, 'exportStixEndpoint']],
            ['method' => 'POST', 'pattern' => 'misp',                    'handler' => [$this, 'exportMispEndpoint']],
            ['method' => 'GET',  'pattern' => 'types',                   'handler' => [$this, 'getTypes']],
            ['method' => 'GET',  'pattern' => 'count',                   'handler' => [$this, 'getCount']],
            ['method' => 'GET',  'pattern' => 'download',                'handler' => [$this, 'downloadEndpoint']],
            ['method' => 'GET',  'pattern' => 'u42-articles',            'handler' => [$this, 'u42ArticlesEndpoint']],
            ['method' => 'POST', 'pattern' => 'extract',                 'handler' => [$this, 'extractEndpoint']],
            ['method' => 'POST', 'pattern' => 'generate',                'handler' => [$this, 'generateEndpoint']],
            ['method' => 'POST', 'pattern' => 'iocs/save',               'handler' => [$this, 'iocsSaveEndpoint']],
        ];
    }

    /**
     * Descarga directa (GET) para los enlaces de los artículos de Unit42.
     * format=stix|misp|txt|csv&source=u42&article_id=N
     */
    public function downloadEndpoint(array $params = []): void
    {
        $format = strtolower((string)($_GET['format'] ?? 'stix'));
        $filters = [
            'source'     => (string)($_GET['source'] ?? ''),
            'article_id' => (int)($_GET['article_id'] ?? 0),
        ];
        $tenantId = (int)($_GET['tenant'] ?? 0);
        $config = ['format' => 'merged', 'source' => 'Unit42'];

        try {
            $result = match ($format) {
                'stix' => $this->exportStix($tenantId, $filters, $config),
                'misp' => $this->exportMisp($tenantId, $filters, $config),
                'txt'  => $this->exportTxt($tenantId, $filters, $config),
                'csv'  => $this->exportCsv($tenantId, $filters, $config),
                default => null,
            };
        } catch (Throwable $e) {
            http_response_code(500);
            echo 'No se pudo exportar: ' . e($e->getMessage());
            return;
        }

        if (!is_array($result) || empty($result['content']) || (int)($result['count'] ?? 0) === 0) {
            http_response_code(404);
            echo 'No hay IOCs para exportar con esos filtros.';
            return;
        }

        $filename = (string)($result['filename'] ?? ('iocs_' . date('Y-m-d') . '.txt'));
        header('Content-Type: ' . (string)($result['mime'] ?? 'application/octet-stream'));
        header('Content-Disposition: attachment; filename="' . basename($filename) . '"');
        header('Cache-Control: no-store');
        echo $result['content'];
        exit;
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $iocCount = $selectedTenant ? $this->countIocs($selectedTenant) : 0;
        $iocTypes = $selectedTenant ? $this->getIocTypes($selectedTenant) : [];

        echo $this->page('index', [
            'module' => $this, 'tenants' => $tenants,
            'selectedTenant' => $selectedTenant,
            'iocCount' => $iocCount, 'iocTypes' => $iocTypes,
            'tlpMarkings' => TLP_MARKINGS,
            'mispDistribution' => MISP_TLP_DISTRIBUTION,
        ]);
    }

    public function exportTxtEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $result = $this->exportTxt((int)($input['tenant_id'] ?? 0), $input['filters'] ?? []);
        json_response($result);
    }

    public function exportCsvEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $result = $this->exportCsv((int)($input['tenant_id'] ?? 0), $input['filters'] ?? []);
        json_response($result);
    }

    public function exportStixEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $result = $this->exportStix(
            (int)($input['tenant_id'] ?? 0),
            $input['filters'] ?? [],
            $input['config'] ?? []
        );
        json_response($result);
    }

    public function exportMispEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $result = $this->exportMisp(
            (int)($input['tenant_id'] ?? 0),
            $input['filters'] ?? [],
            $input['config'] ?? []
        );
        json_response($result);
    }

    public function getTypes(array $params = []): void
    {
        json_response(['types' => $this->getIocTypes((int)($_GET['tenant'] ?? 0))]);
    }

    public function getCount(array $params = []): void
    {
        json_response(['count' => $this->countIocs((int)($_GET['tenant'] ?? 0))]);
    }

    // ============================================================
    // Asistente de extracción y exportación de IOCs
    // ============================================================

    private function requestInput(): array
    {
        $raw = file_get_contents('php://input');
        $input = json_decode((string)$raw, true);
        return is_array($input) ? $input : (is_array($_POST) ? $_POST : []);
    }

    /** Artículos de Unit 42 para el buscador del paso 1. */
    public function u42ArticlesEndpoint(array $params = []): void
    {
        $q = trim((string)($_GET['q'] ?? ''));
        $where = '1=1';
        $args = [];
        if ($q !== '') {
            $where = '(title LIKE ? OR path LIKE ?)';
            $like = '%' . $q . '%';
            $args = [$like, $like];
        }
        $rows = Database::fetchAll(
            "SELECT id, title, published_at, path FROM u42_articles WHERE $where
             ORDER BY published_at DESC, id DESC LIMIT 100",
            $args
        );
        json_response(['success' => true, 'articles' => $rows]);
    }

    /** Extrae IOCs de Unit 42, del catálogo del tenant o de texto pegado. */
    public function extractEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = $this->requestInput();
        $source = (string)($input['source'] ?? 'u42');
        $iocs = [];
        $articles = [];

        /* Seguimiento TI TF: búsqueda guardada (todas las filas o solo novedades). */
        if ($source === 'ti_tracker') {
            $extracted = $this->tiTrackerExtraction(
                (int)($input['search_id'] ?? 0),
                strtolower((string)($input['scope'] ?? 'all')),
                is_array($input['new_iocs'] ?? null) ? $input['new_iocs'] : []
            );
            if (!empty($extracted['error'])) {
                json_response(['success' => false, 'error' => $extracted['error']], 400);
                return;
            }
            json_response($extracted['response']);
            return;
        }

        if ($source === 'u42') {
            $ids = is_array($input['article_ids'] ?? null) ? array_values(array_filter(array_map('intval', $input['article_ids']))) : [];
            if ($ids === []) {
                json_response(['success' => false, 'error' => 'Selecciona al menos una publicación.'], 400);
                return;
            }
            foreach ($ids as $id) {
                $article = Unit42Feed::article($id);
                if ($article === null) { continue; }
                $articles[] = [
                    'id'    => (int)$article['id'],
                    'title' => (string)($article['title'] ?? $article['path'] ?? $id),
                    'path'  => (string)($article['path'] ?? ''),
                ];
                foreach (Unit42Feed::iocs($id) as $ioc) {
                    $iocs[] = [
                        'id' => (int)$ioc['id'],
                        'type' => (string)$ioc['ioc_type'],
                        'value' => (string)$ioc['ioc_value'],
                        'description' => (string)($ioc['description'] ?? ''),
                        'source' => (string)($ioc['source'] ?? 'auto'),
                    ];
                }
                // También se extracta del texto parseado: puede contener indicios
                // que la extracción de la sincronización no hubiera guardado.
                foreach (Unit42Feed::extractIocs(is_array($article['sections'] ?? null) ? $article['sections'] : []) as $ioc) {
                    $iocs[] = [
                        'id' => 0,
                        'type' => (string)$ioc['ioc_type'],
                        'value' => (string)$ioc['ioc_value'],
                        'description' => (string)($ioc['description'] ?? ''),
                        'source' => 'auto',
                    ];
                }
            }
        } elseif ($source === 'tenant') {
            $tenantId = (int)($input['tenant_id'] ?? 0);
            $filters = is_array($input['filters'] ?? null) ? $input['filters'] : [];
            foreach ($this->getIocsForExport($tenantId, $filters) as $ioc) {
                $iocs[] = [
                    'id' => (int)($ioc['id'] ?? 0),
                    'type' => (string)$ioc['ioc_type'],
                    'value' => (string)$ioc['ioc_value'],
                    'description' => (string)($ioc['description'] ?? ''),
                    'source' => 'tenant',
                ];
            }
        } elseif ($source === 'text') {
            require_once __DIR__ . '/../../includes/ioc_text_extract.php';
            $text = (string)($input['text'] ?? '');
            if (trim($text) === '') {
                json_response(['success' => false, 'error' => 'Pega el texto del que quieres extraer IOCs.'], 400);
                return;
            }
            $extracted = ioc_extract_text($text);
            json_response(['success' => true, 'iocs' => $extracted['iocs'], 'stats' => $extracted['stats'], 'source' => 'text']);
            return;
        } else {
            json_response(['success' => false, 'error' => 'Origen no válido.'], 400);
            return;
        }

        $unique = [];
        foreach ($iocs as $ioc) {
            $key = $ioc['type'] . '|' . strtolower($ioc['value']);
            if ($key === '|') { continue; }
            if (!isset($unique[$key])) { $unique[$key] = $ioc; }
            elseif ((int)$unique[$key]['id'] === 0 && (int)$ioc['id'] > 0) { $unique[$key] = $ioc; }
        }
        $list = array_values($unique);
        $byType = [];
        foreach ($list as $ioc) { $byType[$ioc['type']] = ($byType[$ioc['type']] ?? 0) + 1; }
        $categories = [
            'ip'     => ($byType['ipv4-addr'] ?? 0) + ($byType['ipv6-addr'] ?? 0),
            'domain' => $byType['domain-name'] ?? 0,
            'url'    => $byType['url'] ?? 0,
            'hash'   => $byType['file'] ?? 0,
            'email'  => ($byType['email-addr'] ?? 0) + ($byType['user-account'] ?? 0),
        ];
        $categories['other'] = max(0, count($list) - array_sum($categories));

        json_response([
            'success' => true,
            'iocs' => $list,
            'stats' => [
                'total' => count($iocs), 'unique' => count($list),
                'duplicates' => max(0, count($iocs) - count($list)),
                'by_type' => $byType, 'categories' => $categories,
            ],
            'source'   => $source,
            'articles' => $articles,
        ]);
    }

    /**
     * IOCs de una búsqueda guardada de Seguimiento TI TF, en el formato que
     * espera el asistente. scope='new' filtra por la lista de novedades que
     * envía la pantalla de resultados.
     */
    private function tiTrackerExtraction(int $searchId, string $scope, array $newIocs): array
    {
        if ($searchId <= 0) {
            return ['error' => 'Falta la búsqueda de Seguimiento TI.'];
        }
        try {
            $search = (new TiTrackerStore())->getSearch($searchId);
        } catch (Throwable $e) {
            return ['error' => 'No se pudo leer la búsqueda: ' . $e->getMessage()];
        }
        if ($search === null) {
            return ['error' => 'La búsqueda no existe.'];
        }

        try {
            $rows = TiTrackerRunner::resolveRows(TiTrackerRunner::filtersFor($search));
        } catch (Throwable $e) {
            return ['error' => $e->getMessage()];
        }

        if ($scope === 'new') {
            $keys = [];
            foreach ($newIocs as $value) {
                $key = strtolower(trim((string)$value));
                if ($key !== '') { $keys[$key] = true; }
            }
            if ($keys === []) {
                return ['error' => 'La búsqueda no tiene novedades en esta ejecución.'];
            }
            $rows = array_values(array_filter($rows, static function (array $row) use ($keys): bool {
                return isset($keys[strtolower(trim((string)($row['ioc'] ?? '')))]);
            }));
            if ($rows === []) {
                return ['error' => 'Las novedades ya no están en la consulta actual.'];
            }
        }

        $list = [];
        $seen = [];
        foreach ($rows as $row) {
            $ioc = self::mapThreatFoxIoc(is_array($row) ? $row : []);
            if ($ioc === null) { continue; }
            $key = $ioc['type'] . '|' . strtolower($ioc['value']);
            if (isset($seen[$key])) { continue; }
            $seen[$key] = true;
            $ioc['id'] = 0;
            $list[] = $ioc;
        }
        if ($list === []) {
            return ['error' => 'No se encontraron IOCs exportables en esa búsqueda.'];
        }

        $byType = [];
        foreach ($list as $ioc) { $byType[$ioc['type']] = ($byType[$ioc['type']] ?? 0) + 1; }
        $categories = [
            'ip'     => ($byType['ipv4-addr'] ?? 0) + ($byType['ipv6-addr'] ?? 0),
            'domain' => $byType['domain-name'] ?? 0,
            'url'    => $byType['url'] ?? 0,
            'hash'   => $byType['file'] ?? 0,
            'email'  => ($byType['email-addr'] ?? 0) + ($byType['user-account'] ?? 0),
        ];
        $categories['other'] = max(0, count($list) - array_sum($categories));

        return ['response' => [
            'success' => true,
            'iocs'    => $list,
            'stats'   => [
                'total' => count($rows), 'unique' => count($list),
                'duplicates' => max(0, count($rows) - count($list)),
                'by_type' => $byType, 'categories' => $categories,
            ],
            'source' => 'ti_tracker',
            'search' => [
                'id'          => (int)$search['id'],
                'name'        => (string)$search['name'],
                'source_name' => (string)$search['source_name'],
                'threat_actor' => (string)$search['threat_actor'],
                'extra_tags'  => (string)$search['extra_tags'],
                'tlp'         => (string)$search['tlp'],
                'valid_days'  => (int)$search['valid_days'],
                'scope'       => $scope,
            ],
        ]];
    }

    /** Fila de ThreatFox → IOC del asistente (tipos válidos en sus desplegables). */
    private static function mapThreatFoxIoc(array $row): ?array
    {
        $value = trim((string)($row['ioc'] ?? ''));
        if ($value === '') { return null; }

        $type = strtolower(trim((string)($row['ioc_type'] ?? '')));
        $description = trim((string)($row['malware_printable'] ?? ''));
        if ($description === '') { $description = trim((string)($row['malware'] ?? '')); }
        if (($row['tags'] ?? '') !== '') {
            $description = $description !== ''
                ? $description . ' — ' . (string)$row['tags']
                : (string)$row['tags'];
        }
        $reference = trim((string)($row['reference'] ?? ''));
        if ($reference !== '' && filter_var($reference, FILTER_VALIDATE_URL)) {
            $description = $description !== '' ? $description . ' — ' . $reference : $reference;
        }

        // ip:port: el asistente no tiene patrón network-traffic, se exporta la IP
        // y el puerto viaja en la descripción.
        if (preg_match('/^((?:\d{1,3}\.){3}\d{1,3}|[a-f0-9:]+):(\d{1,5})$/i', $value, $m)) {
            $ipType = str_contains($m[1], ':') ? 'ipv6-addr' : 'ipv4-addr';
            return [
                'type' => $ipType, 'value' => $m[1],
                'description' => ($description !== '' ? $description . ' · ' : '') . 'puerto ' . (int)$m[2],
                'source' => 'ti_tracker',
            ];
        }

        $mapped = null;
        if (filter_var($value, FILTER_VALIDATE_IP)) {
            $mapped = str_contains($value, ':') ? 'ipv6-addr' : 'ipv4-addr';
        } elseif (filter_var($value, FILTER_VALIDATE_URL)) {
            $mapped = 'url';
        } elseif (filter_var($value, FILTER_VALIDATE_EMAIL)) {
            $mapped = 'email-addr';
        } elseif (preg_match('/^[a-f0-9]{32}$/i', $value)
            || preg_match('/^[a-f0-9]{40}$/i', $value)
            || preg_match('/^[a-f0-9]{64}$/i', $value)
            || preg_match('/^[a-f0-9]{128}$/i', $value)) {
            $mapped = 'file';
        } elseif (in_array($type, ['domain', 'hostname', 'dns'], true)
            || preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i', $value)) {
            $mapped = 'domain-name';
        } elseif ($type === 'url') {
            $mapped = 'url';
        } elseif (str_contains($type, 'hash')) {
            $mapped = 'file';
        }

        if ($mapped === null) { return null; }
        return [
            'type' => $mapped, 'value' => $value,
            'description' => $description, 'source' => 'ti_tracker',
        ];
    }

    /**
     * Fachada pública del mapeador para la API de Seguimiento TI TF (v0.4.29).
     * Reutiliza exactamente la misma normalización que el asistente.
     */
    public static function mapIocRow(array $row): ?array
    {
        return self::mapThreatFoxIoc($row);
    }

    /** Genera los ficheros sin descargarlos: el navegador decide cuáler bajar. */
    public function generateEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = $this->requestInput();
        $format = strtolower((string)($input['format'] ?? 'stix'));
        $iocs = is_array($input['iocs'] ?? null) ? $input['iocs'] : [];
        $config = is_array($input['config'] ?? null) ? $input['config'] : [];
        $searchId = (int)($input['search_id'] ?? 0);

        if ($iocs === []) {
            json_response(['success' => false, 'error' => 'No hay IOCs para exportar.'], 400);
            return;
        }

        switch ($format) {
            case 'stix':
                $result = $this->buildStixResult($iocs, $config);
                break;
            case 'misp':
                $result = $this->buildMispResult($iocs, $config);
                break;
            case 'csv':
                $result = [
                    'success' => true, 'format' => 'csv', 'count' => count($iocs),
                    'files' => ['all' => [
                        'content' => $this->buildCsvContent($iocs),
                        'filename' => 'iocs_' . date('Y-m-d') . '.csv',
                        'mime' => 'text/csv',
                    ]],
                ];
                break;
            case 'txt':
                $result = [
                    'success' => true, 'format' => 'txt', 'count' => count($iocs),
                    'files' => ['all' => [
                        'content' => $this->buildTxtContent($iocs),
                        'filename' => 'iocs_' . date('Y-m-d') . '.txt',
                        'mime' => 'text/plain',
                    ]],
                ];
                break;
            default:
                json_response(['success' => false, 'error' => 'Formato no válido.'], 400);
                return;
        }

        // Trazabilidad: si la exportación viene de Seguimiento TI, se registra
        // en el historial de la búsqueda igual que el endpoint antiguo.
        if ($searchId > 0 && !empty($result['success'])) {
            try {
                $filename = (string)($result['filename'] ?? '');
                if ($filename === '' && is_array($result['files'] ?? null)) {
                    foreach ($result['files'] as $file) {
                        $filename = (string)($file['filename'] ?? '');
                        if ($filename !== '') { break; }
                    }
                }
                (new TiTrackerStore())->logExport(
                    $searchId, $format, (int)($result['count'] ?? 0), $filename
                );
            } catch (Throwable $e) {
                // La auditoría no debe impedir la descarga.
            }
        }

        json_response($result);
    }

    /** Guarda correcciones de tipo/descripción sobre los IOCs de Unit 42. */
    public function iocsSaveEndpoint(array $params = []): void
    {
        Csrf::validateOrFail();
        $input = $this->requestInput();
        $articleId = (int)($input['article_id'] ?? 0);
        $changes = is_array($input['changes'] ?? null) ? $input['changes'] : [];
        if ($articleId <= 0) {
            json_response(['success' => false, 'error' => 'Falta el artículo.'], 400);
            return;
        }

        $saved = 0;
        foreach ($changes as $ch) {
            if (!is_array($ch)) { continue; }
            $type = trim((string)($ch['type'] ?? ''));
            $value = trim((string)($ch['value'] ?? ''));
            $description = trim((string)($ch['description'] ?? ''));
            if ($type === '' || $value === '') { continue; }
            $id = (int)($ch['id'] ?? 0);

            if ($id > 0) {
                Database::query(
                    "DELETE FROM u42_iocs WHERE article_id = ? AND ioc_type = ? AND ioc_value = ? AND id <> ?",
                    [$articleId, $type, $value, $id]
                );
                Database::query(
                    "UPDATE u42_iocs SET ioc_type = ?, ioc_value = ?, description = ?, edited = 1 WHERE id = ? AND article_id = ?",
                    [$type, $value, $description, $id, $articleId]
                );
            } else {
                Database::query(
                    "INSERT OR IGNORE INTO u42_iocs (article_id, ioc_type, ioc_value, description, source, edited, first_seen)
                     VALUES (?, ?, ?, ?, 'manual', 1, datetime('now'))",
                    [$articleId, $type, $value, $description]
                );
            }
            $saved++;
        }
        json_response(['success' => true, 'saved' => $saved]);
    }
}
