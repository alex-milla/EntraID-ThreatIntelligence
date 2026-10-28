<?php
declare(strict_types=1);

/**
 * ThreatfoxExport — Exportadores de los IOCs filtrados de ThreatFox.
 *
 * Origen del método: proyecto "IOC Extractor & Classifier"
 * (public_html/export.php + utils.php), portado sin dependencias y ampliado
 * con el bundle STIX 2.1 completo y la exportación MISP:
 *
 *  - STIX 2.1: cada IOC → objeto indicator con el patrón detectado por la
 *    forma del valor (detectIOCType + generateSTIXPattern), TLP vía
 *    object_marking_refs con los IDs estándar, labels = [tipo legible, tags],
 *    confidence, threat_actor_names opcional, indicator_types configurable y
 *    valid_until a N días. Salida como bundle STIX 2.1 con su
 *    marking-definition, en un único fichero (merged) o uno por tipo de
 *    patrón (split).
 *  - MISP core: Event + Attribute[] + Tag[], distribution ligada al TLP,
 *    atributos según el tipo de IOC y dirección IP configurable.
 *  - CSV (BOM UTF-8, separador ';'), JSON y TXT.
 *
 * Adaptación a la fuente: las filas de ThreatFox (ioc, ioc_type, malware,
 * tags, confidence_level, reference…) se convierten a la forma de IOC del
 * extractor ({value, type, description}); ip:port usa el patrón
 * network-traffic, que el método original no cubre.
 */
final class ThreatfoxExport
{
    /** IDs estándar de TLP 1.0 (marking-definitions conocidos), como en config.php. */
    private const TLP_MARKINGS = [
        'white' => 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
        'green' => 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
        'amber' => 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
        'red'   => 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    ];

    /** Valores por defecto del método original (config.php). */
    private const DEFAULT_SOURCE_NAME = 'abuse.ch ThreatFox';
    private const DEFAULT_INDICATOR_TYPE = 'malicious-activity';
    private const DEFAULT_CONFIDENCE = 75;

    /** Distribución MISP asociada a cada nivel TLP (evita fugas de información). */
    private const MISP_TLP_DISTRIBUTION = [
        'white' => '3', // All communities
        'green' => '2', // Connected communities
        'amber' => '1', // This community only
        'red'   => '0', // Your organisation only
    ];

    /** Vocabulario STIX 2.1 de indicator_types, con etiqueta en español. */
    public const INDICATOR_TYPES = [
        'malicious-activity' => 'Actividad Maliciosa',
        'anomalous-activity' => 'Actividad Anómala',
        'attribution'        => 'Atribución',
        'benign'             => 'Benigna',
        'compromised'        => 'Comprometida',
        'unknown'            => 'Desconocida',
    ];

    /** Niveles TLP con su descripción para la leyenda de la interfaz. */
    public const TLP_LEVELS = [
        'white' => ['label' => 'BLANCO', 'help' => 'difusión sin restricción (público)', 'dot' => 'bg-neutral'],
        'green' => ['label' => 'VERDE', 'help' => 'compartir con la comunidad, no público', 'dot' => 'bg-success'],
        'amber' => ['label' => 'ÁMBAR', 'help' => 'organización y clientes; no público', 'dot' => 'bg-warning'],
        'red'   => ['label' => 'ROJO', 'help' => 'solo destinatarios nombrados, sin reenvío', 'dot' => 'bg-danger'],
    ];

    private string $tlpLevel;
    private int $validDays;
    private string $sourceName;

    /** Metadatos configurables desde la pantalla de exportación (paso 4 del extractor). */
    private string $indicatorType = self::DEFAULT_INDICATOR_TYPE;
    private string $threatActor = '';
    /** @var string[] */
    private array $extraLabels = [];
    private ?int $confOverride = null;
    /** Dirección IP para los atributos MISP: ip-src | ip-dst | both. */
    private string $ipDirection = 'ip-dst';

    /**
     * @param array{sourceName?:string, threatActor?:string, tags?:string, indicatorType?:string, confidence?:int|null, ip_direction?:string} $config
     */
    public function __construct(string $tlp = 'amber', int $validDays = 90, array $config = [])
    {
        $this->tlpLevel = isset(self::TLP_MARKINGS[$tlp]) ? $tlp : 'green';
        $this->validDays = max(1, $validDays);
        $this->sourceName = trim((string) ($config['sourceName'] ?? '')) ?: self::DEFAULT_SOURCE_NAME;
        $this->threatActor = trim((string) ($config['threatActor'] ?? ''));
        $this->extraLabels = array_values(array_filter(array_map('trim', explode(',', (string) ($config['tags'] ?? '')))));
        $type = strtolower(trim((string) ($config['indicatorType'] ?? '')));
        if (in_array($type, ['malicious-activity', 'anomalous-activity', 'attribution', 'compromised', 'benign', 'unknown'], true)) {
            $this->indicatorType = $type;
        }
        $conf = $config['confidence'] ?? null;
        $this->confOverride = ($conf === null || $conf === '') ? null : max(0, min(100, (int) $conf));

        $direction = strtolower(trim((string) ($config['ip_direction'] ?? 'ip-dst')));
        if (in_array($direction, ['ip-src', 'ip-dst', 'both'], true)) {
            $this->ipDirection = $direction;
        }
    }

    public function tlp(): string
    {
        return $this->tlpLevel;
    }

    /* ---------------------------------------------------------------------
     * Utilidades portadas de utils.php (proyecto IOC Extractor & Classifier)
     * ------------------------------------------------------------------ */

    /** UUID v4 (generateUUID de utils.php). */
    private static function generateUUID(): string
    {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    private static function isValidMD5(string $hash): bool
    {
        return (bool) preg_match('/^[0-9a-f]{32}$/i', $hash);
    }

    private static function isValidSHA1(string $hash): bool
    {
        return (bool) preg_match('/^[0-9a-f]{40}$/i', $hash);
    }

    private static function isValidSHA256(string $hash): bool
    {
        return (bool) preg_match('/^[0-9a-f]{64}$/i', $hash);
    }

    private static function isValidSHA512(string $hash): bool
    {
        return (bool) preg_match('/^[0-9a-f]{128}$/i', $hash);
    }

    /** MD5/SHA1/SHA256/SHA512 según la longitud de un hash hex, o null. */
    private static function getHashAlgorithmLabel(string $value): ?string
    {
        if (!preg_match('/^[0-9a-f]+$/i', $value)) {
            return null;
        }
        switch (strlen($value)) {
            case 32:  return 'MD5';
            case 40:  return 'SHA1';
            case 64:  return 'SHA256';
            case 128: return 'SHA512';
            default:  return null;
        }
    }

    /** Detección del tipo de IOC por la forma del valor (detectIOCType de utils.php). */
    public static function detectIOCType(string $value): string
    {
        $value = trim($value);

        // Windows Registry Key
        if (preg_match('/^(HKLM|HKCU|HKCR|HKU|HKCC|HK\\w+)/i', $value)) {
            return 'windows-registry-key';
        }
        // Email address
        if (preg_match('/^[^\s@]+@[^\s@]+\.[^\s@]+$/', $value)) {
            return 'email-addr';
        }
        // IPv6 address
        if (preg_match('/^([0-9a-fA-F:]+:)+[0-9a-fA-F]+$/', $value)) {
            return 'ipv6-addr';
        }
        // IPv4 address (with optional CIDR)
        if (preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$/', $value)) {
            return 'ipv4-addr';
        }
        // Process / binary name (before domain: "cmd.exe" also looks like a domain)
        if (preg_match('/^[\w\-.]+\.exe$/i', $value)) {
            return 'file-name';
        }
        // Domain name
        if (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/', $value)) {
            return 'domain-name';
        }
        // URL
        if (preg_match('/^(https?|ftp):\/\/[^\s]+/i', $value)) {
            return 'url';
        }
        // Hashes (longest first to avoid false positives)
        if (self::isValidSHA512($value) || self::isValidSHA256($value)
            || self::isValidSHA1($value) || self::isValidMD5($value)) {
            return 'file';
        }
        // User account (Windows format)
        if (preg_match('/^(DOMAIN\\\\[A-Za-z0-9_]+|[A-Za-z0-9_]+@[A-Za-z0-9_.]+)$/', $value)) {
            return 'user-account';
        }
        // MAC address
        if (preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $value)) {
            return 'mac-addr';
        }
        // ASN (Autonomous System Number)
        if (preg_match('/^AS[0-9]+$/i', $value) || (preg_match('/^[0-9]+$/', $value) && strlen($value) <= 10)) {
            return 'autonomous-system';
        }
        // File path (Windows or Unix)
        if (preg_match('/^[A-Za-z]:\\\\[^\s]*$/', $value) || preg_match('/^\/[^\s]*$/', $value)) {
            return 'file-path';
        }
        // Chrome Extension ID (32 hex characters, a-p range)
        if (preg_match('/^[a-p]{32}$/i', $value)) {
            return 'chrome-extension-id';
        }
        return 'unknown';
    }

    /** Nombre legible del tipo (getHumanReadableType de utils.php). */
    public static function getHumanReadableType(string $type, ?string $value = null): string
    {
        $types = [
            'ipv4-addr'            => 'IPv4',
            'ipv6-addr'            => 'IPv6',
            'domain-name'          => 'Dominio',
            'url'                  => 'URL',
            'file'                 => 'Hash de Archivo',
            'file-name'            => 'Proceso / Binario',
            'file-path'            => 'Ruta de Archivo',
            'email-addr'           => 'Correo Electrónico',
            'user-account'         => 'Cuenta de Usuario',
            'windows-registry-key' => 'Clave de Registro',
            'mac-addr'             => 'Dirección MAC',
            'autonomous-system'    => 'Sistema Autónomo (ASN)',
            'chrome-extension-id'  => 'ID de Extensión Chrome',
            'network-traffic'      => 'IP:Puerto',
            'unknown'              => 'Desconocido',
        ];

        if ($type === 'file' && $value !== null) {
            $algo = self::getHashAlgorithmLabel($value);
            if ($algo !== null) {
                return $algo;
            }
        }

        return $types[$type] ?? $type;
    }

    /** Patrón STIX por tipo (generateSTIXPattern de utils.php). */
    public static function generateSTIXPattern(string $type, string $value): ?string
    {
        switch ($type) {
            case 'ipv4-addr':
                return "[ipv4-addr:value = '$value']";
            case 'ipv6-addr':
                return "[ipv6-addr:value = '$value']";
            case 'domain-name':
                return "[domain-name:value = '$value']";
            case 'url':
                return "[url:value = '$value']";
            case 'file':
                if (self::isValidMD5($value)) {
                    return "[file:hashes.MD5 = '$value']";
                } elseif (self::isValidSHA1($value)) {
                    return "[file:hashes.'SHA-1' = '$value']";
                } elseif (self::isValidSHA256($value)) {
                    return "[file:hashes.'SHA-256' = '$value']";
                } elseif (self::isValidSHA512($value)) {
                    return "[file:hashes.'SHA-512' = '$value']";
                }
                return "[file:hashes.MD5 = '$value']"; // Default
            case 'file-name':
                return "[file:name = '$value']";
            case 'email-addr':
                return "[email-addr:value = '$value']";
            case 'user-account':
                return "[user-account:value = '$value']";
            case 'windows-registry-key':
                return "[windows-registry-key:key = '$value']";
            case 'mac-addr':
                return "[mac-addr:value = '$value']";
            case 'autonomous-system':
                return "[autonomous-system:number = '$value']";
            case 'chrome-extension-id':
                return "[x-chrome-extension:extension_id = '$value']";
            default:
                return null;
        }
    }

    /** Extrae el tipo de objeto del patrón (extractStixType de utils.php). */
    public static function extractStixType(array $stix): string
    {
        if (!isset($stix['pattern'])) {
            return 'unknown';
        }
        $pattern = $stix['pattern'];

        if (strpos($pattern, 'ipv4-addr') !== false) return 'ipv4-addr';
        if (strpos($pattern, 'ipv6-addr') !== false) return 'ipv6-addr';
        if (strpos($pattern, 'domain-name') !== false) return 'domain-name';
        if (strpos($pattern, 'network-traffic') !== false) return 'network-traffic';
        if (strpos($pattern, 'url') !== false) return 'url';
        if (strpos($pattern, 'file:name') !== false) return 'file-name';
        if (strpos($pattern, 'file') !== false) return 'file';
        if (strpos($pattern, 'email-addr') !== false) return 'email-addr';
        if (strpos($pattern, 'user-account') !== false) return 'user-account';
        if (strpos($pattern, 'windows-registry-key') !== false) return 'windows-registry-key';
        if (strpos($pattern, 'mac-addr') !== false) return 'mac-addr';
        if (strpos($pattern, 'autonomous-system') !== false) return 'autonomous-system';
        if (strpos($pattern, 'x-chrome-extension') !== false) return 'chrome-extension-id';

        return 'unknown';
    }

    /* ---------------------------------------------------------------------
     * Método de exportación: generateSTIX (export.php del proyecto original)
     * ------------------------------------------------------------------ */

    /** Fila de la BD/API ThreatFox → IOC en la forma del extractor original. */
    private static function toExtractorIoc(array $row): array
    {
        $value = trim((string) ($row['ioc'] ?? ''));
        $iocType = strtolower((string) ($row['ioc_type'] ?? ''));

        /* Mapa del tipo ThreatFox → tipo del extractor; si no está claro,
           se detecta por la forma del valor, igual que hace generateSTIX
           cuando el IOC no trae tipo. */
        $typeMap = [
            'domain'      => 'domain-name',
            'url'         => 'url',
            'filename'    => 'file-name',
            'md5_hash'    => 'file',
            'sha1_hash'   => 'file',
            'sha256_hash' => 'file',
            'ip:port'     => 'network-traffic',
        ];
        $type = $typeMap[$iocType] ?? self::detectIOCType($value);
        if ($type === 'unknown') {
            $type = self::detectIOCType($value);
        }

        $reference = trim((string) ($row['reference'] ?? ''));
        /* ThreatFox usa "None"/"null" cuando no hay referencia. */
        if (in_array(strtolower($reference), ['none', 'null', '-'], true)) {
            $reference = '';
        }
        $malwarePrintable = trim((string) ($row['malware_printable'] ?? ''));
        $malware = $malwarePrintable !== '' ? $malwarePrintable : trim((string) ($row['malware'] ?? ''));
        $description = $malware;
        if ($reference !== '') {
            $description = $description !== '' ? $description . ' — ' . $reference : $reference;
        }

        return [
            'value'       => $value,
            'type'        => $type,
            'description' => $description,
            'tags'        => (string) ($row['tags'] ?? ''),
            'confidence'  => (int) ($row['confidence_level'] ?? 0),
            'reference'   => $reference,
        ];
    }

    /** IOC en forma del extractor → objeto indicator STIX 2.1 (generateSTIX). */
    public function indicator(array $ioc): ?array
    {
        if (empty($ioc['value'])) {
            return null;
        }

        $value = (string) $ioc['value'];
        $type = ((string) ($ioc['type'] ?? '')) !== '' ? (string) $ioc['type'] : self::detectIOCType($value);

        if ($type === 'network-traffic') {
            /* ip:port de ThreatFox: el método original no lo cubre; se genera
               el patrón network-traffic equivalente. */
            if (!preg_match('/^((?:\d{1,3}\.){3}\d{1,3}|[a-f0-9:]+):(\d{1,5})$/i', $value, $m)) {
                return null;
            }
            $pattern = "[network-traffic:dst_ref.value = '" . $m[1] . "', network-traffic:dst_port = " . (int) $m[2] . ']';
        } else {
            $pattern = self::generateSTIXPattern($type, $value);
        }
        if (!$pattern) {
            return null;
        }

        $humanType = self::getHumanReadableType($type, $value);
        $rowTags = !empty($ioc['tags'])
            ? array_values(array_filter(array_map('trim', explode(',', (string) $ioc['tags']))))
            : [];
        /* Etiquetas = tipo legible + etiquetas de la pantalla de exportación + tags del IOC. */
        $tagsArray = array_values(array_unique([...$this->extraLabels, ...$rowTags]));

        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $validUntil = $now->add(new DateInterval('P' . $this->validDays . 'D'));

        $description = !empty($ioc['description'])
            ? trim((string) $ioc['description'])
            : 'IOC (' . $humanType . ') from ' . $this->sourceName;

        $indicator = [
            'type'                => 'indicator',
            'id'                  => 'indicator--' . self::generateUUID(),
            'spec_version'        => '2.1',
            'pattern'             => $pattern,
            'pattern_type'        => 'stix',
            'pattern_version'     => '2.1',
            'created'             => $now->format('Y-m-d\TH:i:s\Z'),
            'modified'            => $now->format('Y-m-d\TH:i:s\Z'),
            'valid_from'          => $now->format('Y-m-d\TH:i:s\Z'),
            'valid_until'         => $validUntil->format('Y-m-d\TH:i:s\Z'),
            'name'                => $this->sourceName . ' - ' . $value,
            'description'         => $description,
            'indicator_types'     => [$this->indicatorType],
            'revoked'             => false,
            'labels'              => [$humanType, ...$tagsArray],
            'confidence'          => $this->confOverride ?? (int) ($ioc['confidence'] ?? self::DEFAULT_CONFIDENCE),
            'lang'                => 'en',
            'object_marking_refs' => [self::TLP_MARKINGS[$this->tlpLevel] ?? self::TLP_MARKINGS['green']],
            'external_references' => [],
            'granular_markings'   => [],
            'extensions'          => new \stdClass(),
        ];

        /* Referencia externa: ThreatFox pertenece a abuse.ch; si la fila trae
           URL de referencia se usa como url de la referencia. */
        $reference = trim((string) ($ioc['reference'] ?? ''));
        if ($reference !== '' && filter_var($reference, FILTER_VALIDATE_URL)) {
            $indicator['external_references'] = [
                [
                    'source_name' => $this->sourceName,
                    'url'         => $reference,
                    'external_id' => $this->sourceName . '-' . substr(md5($value), 0, 8),
                ],
            ];
        }

        /* Actor de amenaza indicado en la pantalla de exportación. */
        if ($this->threatActor !== '') {
            $indicator['threat_actor_names'] = [$this->threatActor];
        }

        return $indicator;
    }

    /**
     * Exporta los IOCs como bundles STIX 2.1 completos (con marking-definition).
     *
     * @return array{bundle:string,converted:int,skipped:int,byType:array<string,string>}
     */
    public function export(array $iocs): array
    {
        $stixObjects = [];
        $skipped = 0;

        foreach ($iocs as $row) {
            $ind = $this->indicator(is_array($row) ? self::toExtractorIoc($row) : []);
            if ($ind === null) {
                $skipped++;
                continue;
            }
            $stixObjects[] = $ind;
        }

        /* Split: un bundle por tipo de objeto del patrón. */
        $byType = [];
        $grouped = [];
        foreach ($stixObjects as $stix) {
            $grouped[self::extractStixType($stix)][] = $stix;
        }
        foreach ($grouped as $type => $indicators) {
            $byType[$type] = $this->encodeBundle($indicators);
        }

        return [
            'bundle'    => $this->encodeBundle($stixObjects),
            'converted' => count($stixObjects),
            'skipped'   => $skipped,
            'byType'    => $byType,
        ];
    }

    /** Bundle STIX 2.1 con la marking-definition del TLP como primer objeto. */
    private function encodeBundle(array $indicators): string
    {
        $bundle = [
            'type'    => 'bundle',
            'id'      => 'bundle--' . self::generateUUID(),
            'objects' => array_merge([$this->markingDefinition()], $indicators),
        ];
        return (string)json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /** Objeto marking-definition del TLP elegido. */
    public function markingDefinition(): array
    {
        $level = $this->tlpLevel;
        $names = ['white' => 'TLP:WHITE', 'green' => 'TLP:GREEN', 'amber' => 'TLP:AMBER', 'red' => 'TLP:RED'];
        $created = ['white' => '2017-01-20T00:00:00.000Z'];

        return [
            'type'                => 'marking-definition',
            'spec_version'        => '2.1',
            'id'                  => self::TLP_MARKINGS[$level] ?? self::TLP_MARKINGS['green'],
            'created'             => $created[$level] ?? '2021-10-19T00:00:00.000Z',
            'definition_type'     => 'tlp',
            'name'                => $names[$level] ?? 'TLP:GREEN',
            'definition'          => ['tlp' => strtoupper($level)],
        ];
    }

    /* ---------------------------------------------------------------------
     * Formatos de fichero
     * ------------------------------------------------------------------ */

    /**
     * Genera los ficheros de una exportación.
     *
     * @param array<int,array> $rows  filas de ThreatFox
     * @param string $format  csv | json | txt | stix | misp
     * @param bool $split     un fichero por tipo (stix/misp)
     * @return array{files:array<int,array{filename:string,content:string,mime:string}>,count:int,skipped:int}
     */
    public function files(array $rows, string $format, bool $split = false): array
    {
        $stamp = gmdate('Ymd_His');
        $out = ['files' => [], 'count' => 0, 'skipped' => 0];

        switch ($format) {
            case 'csv':
                $out['files'][] = [
                    'filename' => 'threatfox_iocs_' . $stamp . '.csv',
                    'content'  => $this->csv($rows),
                    'mime'     => 'text/csv; charset=utf-8',
                ];
                $out['count'] = count($rows);
                break;

            case 'json':
                $out['files'][] = [
                    'filename' => 'threatfox_iocs_' . $stamp . '.json',
                    'content'  => $this->json($rows),
                    'mime'     => 'application/json; charset=utf-8',
                ];
                $out['count'] = count($rows);
                break;

            case 'txt':
                $out['files'][] = [
                    'filename' => 'threatfox_iocs_' . $stamp . '.txt',
                    'content'  => $this->txt($rows),
                    'mime'     => 'text/plain; charset=utf-8',
                ];
                $out['count'] = count($rows);
                break;

            case 'misp':
                $groups = $this->mispGroups($rows);
                $out['skipped'] = $groups['skipped'];
                if ($split && count($groups['byType']) > 1) {
                    foreach ($groups['byType'] as $type => $attributes) {
                        $out['files'][] = [
                            'filename' => 'misp_' . $type . '_' . $stamp . '.json',
                            'content'  => $this->mispEvent($attributes),
                            'mime'     => 'application/json; charset=utf-8',
                        ];
                    }
                } else {
                    $all = [];
                    foreach ($groups['byType'] as $attributes) {
                        $all = array_merge($all, $attributes);
                    }
                    $out['files'][] = [
                        'filename' => 'misp_event_' . $stamp . '.json',
                        'content'  => $this->mispEvent($all),
                        'mime'     => 'application/json; charset=utf-8',
                    ];
                }
                $out['count'] = count($rows) - $groups['skipped'];
                break;

            case 'stix':
            default:
                $result = $this->export($rows);
                $out['skipped'] = $result['skipped'];
                if ($split && count($result['byType']) > 1) {
                    foreach ($result['byType'] as $type => $content) {
                        $out['files'][] = [
                            'filename' => 'iocs_stix_' . $type . '_' . $stamp . '.json',
                            'content'  => $content,
                            'mime'     => 'application/json; charset=utf-8',
                        ];
                    }
                } else {
                    $out['files'][] = [
                        'filename' => 'iocs_stix_' . $stamp . '.json',
                        'content'  => $result['bundle'],
                        'mime'     => 'application/json; charset=utf-8',
                    ];
                }
                $out['count'] = $result['converted'];
                break;
        }

        return $out;
    }

    /** CSV con BOM UTF-8, separador ';' y columnas fijas (listas unidas con '|'). */
    public function csv(array $rows): string
    {
        $columns = [
            'id', 'ioc', 'ioc_type', 'threat_type', 'malware', 'malware_printable',
            'confidence_level', 'first_seen', 'last_seen', 'reference', 'reporter', 'tags',
        ];

        $buffer = fopen('php://temp', 'r+');
        if ($buffer === false) {
            return '';
        }
        fwrite($buffer, "\xEF\xBB\xBF");
        fputcsv($buffer, $columns, ';', '"', '\\');
        foreach ($rows as $row) {
            $line = [];
            foreach ($columns as $column) {
                $value = (string)($row[$column] ?? '');
                if ($column === 'tags') {
                    $value = implode('|', array_filter(array_map('trim', explode(',', $value))));
                }
                $line[] = $value;
            }
            fputcsv($buffer, $line, ';', '"', '\\');
        }
        rewind($buffer);
        $csv = (string)stream_get_contents($buffer);
        fclose($buffer);

        return $csv;
    }

    /** JSON con el conjunto filtrado completo. */
    public function json(array $rows): string
    {
        return (string)json_encode([
            'query_status' => 'ok',
            'count'        => count($rows),
            'data'         => array_values($rows),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /** TXT con un indicador por línea. */
    public function txt(array $rows): string
    {
        $lines = [];
        foreach ($rows as $row) {
            $value = trim((string)($row['ioc'] ?? ''));
            if ($value !== '') {
                $lines[] = $value;
            }
        }
        return implode("\n", $lines);
    }

    /* ---------------------------------------------------------------------
     * MISP core
     * ------------------------------------------------------------------ */

    /**
     * Agrupa los atributos MISP por tipo (para split/merged).
     *
     * @return array{byType:array<string,array<int,array>>,skipped:int}
     */
    private function mispGroups(array $rows): array
    {
        $byType = [];
        $skipped = 0;

        foreach ($rows as $row) {
            if (!is_array($row)) {
                $skipped++;
                continue;
            }
            $attributes = $this->mispAttributesFor($row);
            if ($attributes === []) {
                $skipped++;
                continue;
            }
            foreach ($attributes as $attribute) {
                $byType[$attribute['type']][] = $attribute;
            }
        }

        return ['byType' => $byType, 'skipped' => $skipped];
    }

    /**
     * Fila de ThreatFox → atributos MISP ({type, category, value, to_ids, comment}).
     *
     * @return array<int,array{type:string,category:string,value:string,to_ids:bool,comment:string}>
     */
    private function mispAttributesFor(array $row): array
    {
        $value = trim((string)($row['ioc'] ?? ''));
        if ($value === '') {
            return [];
        }

        $iocType = strtolower((string)($row['ioc_type'] ?? ''));
        $comment = trim((string)($row['malware_printable'] ?? ''));
        if ($comment === '') {
            $comment = trim((string)($row['malware'] ?? ''));
        }
        $reference = trim((string)($row['reference'] ?? ''));
        if ($reference !== '' && filter_var($reference, FILTER_VALIDATE_URL)) {
            $comment = $comment !== '' ? $comment . ' — ' . $reference : $reference;
        }

        $network = 'Network activity';
        $payload = 'Payload delivery';
        $base = ['category' => $network, 'value' => $value, 'to_ids' => true, 'comment' => $comment];

        switch ($iocType) {
            case 'ip:port':
                /* ThreatFox publica "ip:puerto": MISP admite el par en un
                   atributo ip-src|ip-dst (la dirección se mantiene con puerto). */
                $directions = $this->ipDirection === 'both' ? ['ip-src', 'ip-dst'] : [$this->ipDirection];
                $out = [];
                foreach ($directions as $direction) {
                    $out[] = ['type' => $direction] + $base;
                }
                return $out;

            case 'md5_hash':
                return [['type' => 'md5', 'category' => $payload] + $base];
            case 'sha1_hash':
                return [['type' => 'sha1', 'category' => $payload] + $base];
            case 'sha256_hash':
                return [['type' => 'sha256', 'category' => $payload] + $base];
            case 'filename':
                return [['type' => 'filename', 'category' => $payload] + $base];
            case 'url':
                return [['type' => 'url'] + $base];
            case 'domain':
            case 'hostname':
                return [['type' => 'domain'] + $base];
            default:
                /* Tipo no mapeado: si es un hash por longitud, se usa esa
                   categoría; si no, se descarta (se cuenta como skipped). */
                $hashType = self::mispHashType($value);
                if ($hashType !== '') {
                    return [['type' => $hashType, 'category' => $payload] + $base];
                }
                return [];
        }
    }

    /** md5 | sha1 | sha256 | sha512 según la longitud del hash, o '' si no lo es. */
    private static function mispHashType(string $value): string
    {
        if (!preg_match('/^[0-9a-f]+$/i', $value)) {
            return '';
        }
        return match (strlen($value)) {
            32 => 'md5',
            40 => 'sha1',
            64 => 'sha256',
            128 => 'sha512',
            default => '',
        };
    }

    /** Evento MISP core con los atributos y las etiquetas del TLP. */
    private function mispEvent(array $attributes): string
    {
        $tags = [];
        foreach (array_merge(['tlp:' . $this->tlpLevel], $this->extraLabels) as $label) {
            $label = trim((string)$label);
            if ($label !== '') {
                $tags[] = ['name' => $label];
            }
        }

        $info = $this->sourceName;
        if ($this->threatActor !== '') {
            $info .= ' - ' . $this->threatActor;
        }
        $info .= ' - IOC Export';

        $event = [
            'Event' => [
                'info'            => $info,
                'date'            => gmdate('Y-m-d'),
                'distribution'    => self::MISP_TLP_DISTRIBUTION[$this->tlpLevel] ?? '1',
                'threat_level_id' => '2',
                'analysis'        => '2',
                'published'       => false,
                'Attribute'       => array_values($attributes),
                'Tag'             => $tags,
            ],
        ];

        return (string)json_encode($event, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

