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
        $content = implode("\n", array_column($iocs, 'ioc_value'));

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

        $headers = ['#', 'Type', 'Value', 'Description', 'Source', 'Severity', 'Fetched At'];
        $rows = [$headers];

        foreach ($iocs as $i => $ioc) {
            $rows[] = [
                $i + 1,
                $ioc['ioc_type'],
                $ioc['ioc_value'],
                $ioc['description'] ?? '',
                $ioc['source'] ?? '',
                $ioc['severity'] ?? '',
                $ioc['fetched_at'] ?? '',
            ];
        }

        $csv = implode("\n", array_map(function ($row) {
            return implode(',', array_map(fn($f) => $this->csvField($f), $row));
        }, $rows));

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
        $iocs = $this->getIocsForExport($tenantId, $filters);

        $tlp = $config['tlp'] ?? 'green';
        $markingRef = TLP_MARKINGS[$tlp] ?? TLP_MARKINGS['green'];
        $validDays = (int)($config['valid_days'] ?? 365);
        $confidence = (int)($config['confidence'] ?? 75);
        $labels = $config['labels'] ?? [];
        $format = $config['format'] ?? 'merged'; // 'merged' o 'split'

        $now = gmdate('Y-m-d\TH:i:s\Z');
        $validUntil = gmdate('Y-m-d\TH:i:s\Z', time() + ($validDays * 86400));

        $indicators = [];
        foreach ($iocs as $ioc) {
            $pattern = $this->generateStixPattern($ioc['ioc_type'], $ioc['ioc_value']);
            if (!$pattern) continue;

            $indicators[] = [
                'type'                 => 'indicator',
                'id'                   => 'indicator--' . generate_uuid(),
                'spec_version'         => '2.1',
                'pattern'              => $pattern,
                'pattern_type'         => 'stix',
                'pattern_version'      => '2.1',
                'created'              => $now,
                'modified'             => $now,
                'valid_from'           => $now,
                'valid_until'          => $validUntil,
                'name'                 => ($config['source'] ?? 'EntraID TI') . ' - ' . $ioc['ioc_value'],
                'description'          => $ioc['description'] ?? '',
                'indicator_types'      => ['malicious-activity'],
                'revoked'              => false,
                'labels'               => $labels,
                'confidence'           => $confidence,
                'lang'                 => 'es',
                'object_marking_refs'  => [$markingRef],
                'external_references'  => [],
            ];
        }

        if ($format === 'split') {
            // Agrupar por tipo
            $byType = [];
            foreach ($indicators as $ind) {
                preg_match('/\[([a-z0-9-]+):/', $ind['pattern'], $m);
                $type = $m[1] ?? 'unknown';
                $byType[$type][] = $ind;
            }

            $files = [];
            foreach ($byType as $type => $inds) {
                $bundle = [
                    'type'    => 'bundle',
                    'id'      => 'bundle--' . generate_uuid(),
                    'objects' => $inds,
                ];
                $files[$type] = [
                    'content'  => json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
                    'filename' => 'iocs_stix_' . $type . '_' . date('Y-m-d') . '.json',
                    'mime'     => 'application/json',
                ];
            }

            return ['success' => true, 'format' => 'split', 'files' => $files, 'count' => count($indicators)];
        }

        // Merged: un único bundle
        $bundle = [
            'type'    => 'bundle',
            'id'      => 'bundle--' . generate_uuid(),
            'objects' => $indicators,
        ];

        return [
            'success' => true,
            'format' => 'merged',
            'content' => json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            'filename' => 'iocs_stix_' . date('Y-m-d') . '.json',
            'mime' => 'application/json',
            'count' => count($indicators),
        ];
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
        $iocs = $this->getIocsForExport($tenantId, $filters);

        $tlp = $config['tlp'] ?? 'amber';
        $distribution = MISP_TLP_DISTRIBUTION[$tlp] ?? '1';
        $tags = array_merge(['tlp:' . $tlp], $config['labels'] ?? []);
        $format = $config['format'] ?? 'merged';
        $ipDirection = $config['ip_direction'] ?? 'ip-dst';
        $info = $config['info'] ?? 'EntraID TI - IOC Export';

        $attributes = [];
        foreach ($iocs as $ioc) {
            $type = $this->mispType($ioc['ioc_type'], $ioc['ioc_value']);
            $category = $this->mispCategory($ioc['ioc_type']);

            // IPs pueden tener dirección configurable
            if (in_array($ioc['ioc_type'], ['ipv4-addr', 'ipv6-addr'], true)) {
                $dirs = $ipDirection === 'both' ? ['ip-src', 'ip-dst'] : [$ipDirection];
                foreach ($dirs as $dir) {
                    $attributes[] = [
                        'type'     => $dir,
                        'category' => 'Network activity',
                        'value'    => $ioc['ioc_value'],
                        'to_ids'   => true,
                        'comment'  => $ioc['description'] ?? '',
                    ];
                }
            } else {
                $attributes[] = [
                    'type'     => $type,
                    'category' => $category,
                    'value'    => $ioc['ioc_type'] === 'autonomous-system' ? str_replace('AS', '', $ioc['ioc_value']) : $ioc['ioc_value'],
                    'to_ids'   => true,
                    'comment'  => $ioc['description'] ?? '',
                ];
            }
        }

        $buildEvent = function (array $attrs) use ($info, $distribution, $tags): array {
            return [
                'Event' => [
                    'info'           => $info,
                    'date'           => date('Y-m-d'),
                    'distribution'   => $distribution,
                    'threat_level_id'=> '2',
                    'analysis'       => '2',
                    'published'      => false,
                    'Attribute'      => $attrs,
                    'Tag'            => array_map(fn($t) => ['name' => $t], $tags),
                ],
            ];
        };

        if ($format === 'split') {
            $byType = [];
            foreach ($attributes as $attr) {
                $byType[$attr['type']][] = $attr;
            }

            $files = [];
            foreach ($byType as $type => $attrs) {
                $event = $buildEvent($attrs);
                $files[$type] = [
                    'content'  => json_encode($event, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
                    'filename' => 'misp_' . $type . '_' . date('Y-m-d') . '.json',
                    'mime'     => 'application/json',
                ];
            }

            return ['success' => true, 'format' => 'split', 'files' => $files, 'count' => count($attributes)];
        }

        $event = $buildEvent($attributes);

        return [
            'success' => true,
            'format' => 'merged',
            'content' => json_encode($event, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            'filename' => 'misp_event_' . date('Y-m-d') . '.json',
            'mime' => 'application/json',
            'count' => count($attributes),
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
        $where = ['tenant_id = ?'];
        $params = [$tenantId];

        if (!empty($filters['type'])) {
            $where[] = 'ioc_type = ?';
            $params[] = $filters['type'];
        }
        if (!empty($filters['search'])) {
            $where[] = 'ioc_value LIKE ?';
            $params[] = '%' . $filters['search'] . '%';
        }
        if (!empty($filters['limit'])) {
            $params[] = (int)$filters['limit'];
            return Database::fetchAll(
                "SELECT * FROM ti_iocs WHERE " . implode(' AND ', $where) . " ORDER BY fetched_at DESC LIMIT ?",
                $params
            );
        }

        return Database::fetchAll(
            "SELECT * FROM ti_iocs WHERE " . implode(' AND ', $where) . " ORDER BY fetched_at DESC",
            $params
        );
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
        ];
    }

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $iocCount = $selectedTenant ? $this->countIocs($selectedTenant) : 0;
        $iocTypes = $selectedTenant ? $this->getIocTypes($selectedTenant) : [];

        echo $this->render('index', [
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
}
