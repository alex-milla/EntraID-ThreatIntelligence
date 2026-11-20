<?php
/**
 * Extracción genérica de IOCs desde texto libre.
 *
 * Portado y simplificado de `IOC-Extractor-Clasificator/public_html/utils.php`
 * (`extractIOCs`, `refangText`, `buildIOCDescriptions`). Vanilla PHP, sin
 * dependencias, apto para hosting compartido.
 */

declare(strict_types=1);

if (!function_exists('ioc_refang_text')) {
    function ioc_refang_text(string $text): string
    {
        $text = str_ireplace(
            ['[.]', '(.)', '[dot]', '{dot}', '[:]', '[//]', 'hxxp://', 'hxxps://', 'fxp://'],
            ['.', '.', '.', '.', ':', '//', 'http://', 'https://', 'ftp://'],
            $text
        );
        return preg_replace('/\\\\[.]/u', '.', $text) ?? $text;
    }
}

if (!function_exists('ioc_benign_domains')) {
    /** Dominios que casi nunca son IOCs y ensuciarían el resultado. */
    function ioc_benign_domains(): array
    {
        return [
            'microsoft.com', 'windows.com', 'office.com', 'office365.com', 'live.com',
            'outlook.com', 'github.com', 'google.com', 'gmail.com', 'cloudflare.com',
            'apple.com', 'amazon.com', 'python.org', 'jquery.com', 'w3.org', 'schema.org',
            'iana.org', 'icann.org', 'example.com', 'localhost',
        ];
    }
}

if (!function_exists('ioc_is_acceptable_domain')) {
    function ioc_is_acceptable_domain(string $domain): bool
    {
        $domain = strtolower($domain);
        if (filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            return false;
        }
        foreach (ioc_benign_domains() as $benign) {
            if ($domain === $benign || str_ends_with($domain, '.' . $benign)) {
                return false;
            }
        }
        // Extensiones de fichero frecuentes: "payload.exe" no es un dominio.
        if (preg_match('/\.(?:exe|dll|pdf|zip|dat|png|jpe?g|gif|js|py|log|docx?|xlsx?|csv|xml|html?|ini|ps1)\b/i', $domain)) {
            return false;
        }
        return true;
    }
}

if (!function_exists('ioc_is_public_ipv4')) {
    function ioc_is_public_ipv4(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }
}

if (!function_exists('ioc_extract_text')) {
    /**
     * @return array{iocs:array<int,array{type:string,value:string,description:string}>,stats:array<string,mixed>}
     */
    function ioc_extract_text(string $text): array
    {
        $text = ioc_refang_text($text);

        $patterns = [
            'url'      => '~(?:https?|ftp)://[^\s<>"\'`]+~i',
            'email'    => '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/',
            'sha512'   => '/\b[a-f0-9]{128}\b/i',
            'sha256'   => '/\b[a-f0-9]{64}\b/i',
            'sha1'     => '/\b[a-f0-9]{40}\b/i',
            'md5'      => '/\b[a-f0-9]{32}\b/i',
            'ipv4'     => '/(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/',
            'ipv6'     => '/\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/i',
            'registry' => '/\bHK(?:LM|CU|CR|U|CC)\\[^\s"\']+/i',
            'file'     => '/\b[\w\-.]+\.(?:exe|dll|ps1|bat|js|vbs|sh|docx?|xlsx?|pdf|zip|rar|7z|jar|apk)\b/i',
            'mac'      => '/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/i',
            'asn'      => '/\bAS\d{1,10}\b/i',
            'domain'   => '/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/i',
        ];
        $typeMap = [
            'url' => 'url', 'email' => 'email-addr',
            'sha512' => 'file', 'sha256' => 'file', 'sha1' => 'file', 'md5' => 'file',
            'ipv4' => 'ipv4-addr', 'ipv6' => 'ipv6-addr', 'domain' => 'domain-name',
            'registry' => 'windows-registry-key', 'file' => 'file',
            'mac' => 'mac-addr', 'asn' => 'autonomous-system',
        ];

        $raw = [];
        foreach ($patterns as $key => $pattern) {
            if (!preg_match_all($pattern, $text, $matches, PREG_OFFSET_CAPTURE)) {
                continue;
            }
            foreach ($matches[0] as $row) {
                $value = trim(rtrim((string)$row[0], ".,;:!?)}]'\""));
                $offset = (int)$row[1];
                if ($value === '') {
                    continue;
                }
                if ($key === 'domain' && !ioc_is_acceptable_domain($value)) {
                    continue;
                }
                if ($key === 'ipv4' && !ioc_is_public_ipv4($value)) {
                    continue;
                }
                if ($key === 'ipv4' && preg_match('/(?:version|v?\.?\b)\s*$/i', substr($text, max(0, $offset - 12), 12))) {
                    continue; // 1.2.3.4 tras "version"
                }
                $raw[] = ['value' => $value, 'type' => $typeMap[$key], 'offset' => $offset];
            }
        }

        usort($raw, static fn(array $a, array $b): int => $a['offset'] <=> $b['offset']);
        $descriptions = ioc_build_descriptions($text, $raw);

        $found = [];
        foreach ($raw as $m) {
            $key = $m['type'] . '|' . strtolower($m['value']);
            if (isset($found[$key])) {
                continue;
            }
            $found[$key] = [
                'type'        => $m['type'],
                'value'       => $m['value'],
                'description' => $descriptions[strtolower($m['value'])] ?? '',
            ];
        }
        $iocs = array_values($found);

        $byType = [];
        foreach ($iocs as $ioc) {
            $byType[$ioc['type']] = ($byType[$ioc['type']] ?? 0) + 1;
        }
        $categories = [
            'ip'     => ($byType['ipv4-addr'] ?? 0) + ($byType['ipv6-addr'] ?? 0),
            'domain' => $byType['domain-name'] ?? 0,
            'url'    => $byType['url'] ?? 0,
            'hash'   => $byType['file'] ?? 0,
            'email'  => ($byType['email-addr'] ?? 0) + ($byType['user-account'] ?? 0),
        ];
        $categories['other'] = max(0, count($iocs) - array_sum($categories));

        return [
            'iocs'  => $iocs,
            'stats' => [
                'total'      => count($raw),
                'unique'     => count($iocs),
                'duplicates' => max(0, count($raw) - count($iocs)),
                'by_type'    => $byType,
                'categories' => $categories,
            ],
        ];
    }
}

if (!function_exists('ioc_build_descriptions')) {
    /** Contexto de la frase/fila donde aparece cada IOC. */
    function ioc_build_descriptions(string $text, array $matches): array
    {
        $map = [];
        $offset = 0;
        foreach (preg_split('/\r\n|\r|\n/', $text) ?: [] as $line) {
            $line = trim($line);
            if ($line === '') {
                $offset += 1;
                continue;
            }
            foreach ($matches as $m) {
                if ($m['offset'] < $offset || $m['offset'] > $offset + strlen($line)) {
                    continue;
                }
                $desc = $line;
                if (preg_match('/^.{0,40}?\b(?:IOC|indicador|dominio|ip|hash|url)\b\s*[:=–-]\s*(.+)$/i', $line, $mm)) {
                    $desc = $mm[1];
                }
                $key = strtolower($m['value']);
                if (!isset($map[$key]) || strlen($desc) < strlen($map[$key])) {
                    $map[$key] = function_exists('mb_substr') ? mb_substr($desc, 0, 300) : substr($desc, 0, 300);
                }
            }
            $offset += strlen($line) + 1;
        }
        return $map;
    }
}
