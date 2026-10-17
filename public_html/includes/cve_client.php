<?php
/**
 * CveClient — cliente HTTP para las fuentes públicas de CVEs.
 * Fase 1: prueba de conectividad de NVD, CISA KEV y EPSS.
 * La descarga masiva se implementará en la Fase 2.
 */

declare(strict_types=1);

class CveClient
{
    private string $nvdUrl;
    private string $nvdKey;
    private string $kevUrl;
    private string $epssUrl;
    private int $timeout;

    public function __construct(array $config = [])
    {
        $this->nvdUrl = (string)($config['nvd_url'] ?? CVE_NVD_URL);
        $this->nvdKey = (string)($config['nvd_api_key'] ?? '');
        $this->kevUrl = (string)($config['kev_url'] ?? CVE_KEV_URL);
        $this->epssUrl = (string)($config['epss_url'] ?? CVE_EPSS_CSV_URL);
        $this->timeout = (int)($config['timeout'] ?? 45);
    }

    /**
     * Configuración efectiva: settings de la BD con fallback a constantes.
     */
    public static function config(): array
    {
        return [
            'nvd_url'         => (string)setting_get('cve_nvd_url', CVE_NVD_URL),
            'nvd_api_key'     => (string)setting_get('cve_nvd_api_key', CVE_NVD_API_KEY),
            'nvd_page_size'   => (int)setting_get('cve_nvd_page_size', CVE_NVD_PAGE_SIZE),
            'scope'           => (string)setting_get('cve_scope', 'full'),
            'recent_years'    => (int)setting_get('cve_recent_years', 3),
            'min_cvss'        => (float)setting_get('cve_min_cvss', 0),
            'kev_url'         => (string)setting_get('cve_kev_url', CVE_KEV_URL),
            'epss_url'        => (string)setting_get('cve_epss_url', CVE_EPSS_CSV_URL),
            'auto_sync'       => (int)setting_get('cve_auto_sync', 1),
            'interval_hours'  => (int)setting_get('cve_interval_hours', 24),
        ];
    }

    public static function fromSettings(): self
    {
        return new self(self::config());
    }

    /**
     * Comprueba las tres fuentes sin lanzar excepciones.
     */
    public function testAll(): array
    {
        $sources = [
            'nvd'  => $this->testNvd(),
            'kev'  => $this->testKev(),
            'epss' => $this->testEpss(),
        ];

        $ok = true;
        foreach ($sources as $source) {
            if (empty($source['ok'])) {
                $ok = false;
            }
        }

        return [
            'success'   => $ok,
            'sources'   => $sources,
            'tested_at' => date('c'),
        ];
    }

    private function testNvd(): array
    {
        try {
            if (!self::isSafeUrl($this->nvdUrl)) {
                return $this->result(false, 0, 'URL de NVD no válida (se requiere HTTPS público).');
            }

            $sep = str_contains($this->nvdUrl, '?') ? '&' : '?';
            $url = $this->nvdUrl . $sep . 'resultsPerPage=1&noRejected';
            $headers = ['Accept: application/json'];
            if ($this->nvdKey !== '') {
                $headers[] = 'apiKey: ' . $this->nvdKey;
            }

            $res = $this->httpGet($url, $headers, $this->timeout, false);
            if ($res['http'] === 200) {
                $data = json_decode($res['body'], true);
                if (!is_array($data)) {
                    return $this->result(false, 200, 'NVD respondió 200 pero el JSON no es válido.');
                }
                $total = (int)($data['totalResults'] ?? 0);
                return $this->result(true, 200, 'OK — ' . number_format($total) . ' CVEs en NVD.', [
                    'total' => $total,
                ]);
            }

            $message = 'HTTP ' . $res['http'];
            if ($res['http'] === 403 || $res['http'] === 401) {
                $message .= ' — API key inválida o sin permisos.';
            } elseif ($res['http'] === 429) {
                $message .= ' — rate limit alcanzado. Configura una API key de NVD.';
            } elseif ($res['http'] === 404) {
                $message .= ' — endpoint de NVD no encontrado.';
            }
            return $this->result(false, $res['http'], $message);
        } catch (Throwable $e) {
            return $this->result(false, 0, 'No se pudo conectar con NVD: ' . $e->getMessage());
        }
    }

    private function testKev(): array
    {
        try {
            if (!self::isSafeUrl($this->kevUrl)) {
                return $this->result(false, 0, 'URL de KEV no válida (se requiere HTTPS público).');
            }

            $res = $this->httpGet($this->kevUrl, ['Accept: application/json'], $this->timeout, true);
            if ($res['http'] !== 200) {
                return $this->result(false, $res['http'], 'HTTP ' . $res['http'] . ' al descargar CISA KEV.');
            }

            $data = json_decode($res['body'], true);
            if (!is_array($data)) {
                return $this->result(false, 200, 'CISA KEV no devolvió un JSON válido.');
            }

            $count = (int)($data['count'] ?? count($data['vulnerabilities'] ?? []));
            $version = (string)($data['catalogVersion'] ?? '');
            $released = (string)($data['dateReleased'] ?? '');
            $message = 'OK — ' . number_format($count) . ' CVEs';
            if ($version !== '') {
                $message .= ' (catálogo ' . $version . ')';
            }
            if ($released !== '') {
                $message .= ', publicado ' . $released;
            }

            return $this->result(true, 200, $message . '.', [
                'count'    => $count,
                'version'  => $version,
                'released' => $released,
            ]);
        } catch (Throwable $e) {
            return $this->result(false, 0, 'No se pudo conectar con CISA KEV: ' . $e->getMessage());
        }
    }

    private function testEpss(): array
    {
        try {
            if (!self::isSafeUrl($this->epssUrl)) {
                return $this->result(false, 0, 'URL de EPSS no válida (se requiere HTTPS público).');
            }

            // HEAD con seguimiento de redirecciones; si el servidor no lo soporta,
            // se hace un GET parcial para confirmar que el CSV es accesible.
            $res = $this->httpGet($this->epssUrl, ['Accept: */*'], 20, true, true);
            if ($res['http'] >= 400 || $res['http'] === 0) {
                $res = $this->httpGet($this->epssUrl, ['Accept: */*'], 30, true, false);
            }
            if ($res['http'] !== 200) {
                return $this->result(false, $res['http'], 'HTTP ' . $res['http'] . ' al descargar EPSS.');
            }

            $length = (int)($res['headers']['content-length'] ?? 0);
            $lastModified = (string)($res['headers']['last-modified'] ?? '');
            $message = 'OK — CSV accesible';
            if ($length > 0) {
                $message .= ' (' . number_format($length / 1048576, 2) . ' MB)';
            }
            if ($lastModified !== '') {
                $message .= ', modificado ' . $lastModified;
            }
            return $this->result(true, 200, $message . '.', [
                'size'          => $length,
                'last_modified' => $lastModified,
            ]);
        } catch (Throwable $e) {
            return $this->result(false, 0, 'No se pudo conectar con EPSS: ' . $e->getMessage());
        }
    }

    private function result(bool $ok, int $http, string $message, array $extra = []): array
    {
        return array_merge([
            'ok'      => $ok,
            'http'    => $http,
            'message' => $message,
        ], $extra);
    }

    /**
     * GET/HEAD con cURL. Devuelve status, body y cabeceras normalizadas.
     */
    private function httpGet(string $url, array $headers = [], int $timeout = 45, bool $follow = true, bool $noBody = false): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('La extensión cURL de PHP no está disponible.');
        }

        $ch = curl_init($url);
        $responseHeaders = [];
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => 'GET',
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_FOLLOWLOCATION => $follow,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'EntraID-TI-CVE/1.0',
            CURLOPT_ENCODING       => '',
            CURLOPT_NOBODY         => $noBody,
            CURLOPT_HEADERFUNCTION => function ($ch, string $header) use (&$responseHeaders): int {
                $length = strlen($header);
                $parts = explode(':', $header, 2);
                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return $length;
            },
        ];
        curl_setopt_array($ch, $opts);

        $body = curl_exec($ch);
        $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            throw new RuntimeException($error !== '' ? $error : 'Error de conexión cURL');
        }

        return [
            'http'    => $http,
            'body'    => (string)$body,
            'headers' => $responseHeaders,
            'error'   => $error !== '' ? $error : null,
        ];
    }

    /**
     * Evita SSRF: solo HTTPS público (sin localhost ni rangos privados/reservados).
     */
    public static function isSafeUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https') {
            return false;
        }
        $host = strtolower(trim((string)($parts['host'] ?? '')));
        if ($host === '' || $host === 'localhost') {
            return false;
        }
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return filter_var(
                $host,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            ) !== false;
        }
        return true;
    }
}
