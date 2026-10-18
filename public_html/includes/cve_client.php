<?php
/**
 * CveClient — cliente HTTP para las fuentes públicas de CVEs.
 * Prueba NVD, CPE, CISA KEV (con mirror) y EPSS; también descarga páginas NVD.
 */

declare(strict_types=1);

class CveClient
{
    private string $nvdUrl;
    private string $cpeUrl;
    private string $nvdKey;
    private string $kevUrl;
    private string $kevFallbackUrl;
    private string $epssUrl;
    private int $timeout;
    private int $rateWindow;
    private int $rateMax;
    private int $maxRetries;
    private int $lastNvdAttempts = 0;

    /** Marcas de tiempo (microtime) de las últimas peticiones a NVD. */
    private array $nvdRequestTimes = [];
    private bool $throttlePrimed = false;

    public function __construct(array $config = [])
    {
        $this->nvdUrl = (string)($config['nvd_url'] ?? CVE_NVD_URL);
        $this->cpeUrl = (string)($config['cpe_url'] ?? CVE_CPE_URL);
        $this->nvdKey = (string)($config['nvd_api_key'] ?? '');
        $this->kevUrl = (string)($config['kev_url'] ?? CVE_KEV_URL);
        $this->kevFallbackUrl = (string)($config['kev_fallback_url'] ?? CVE_KEV_FALLBACK_URL);
        $this->epssUrl = (string)($config['epss_url'] ?? CVE_EPSS_CSV_URL);
        $this->timeout = (int)($config['timeout'] ?? 45);
        $this->rateWindow = max(1, (int)($config['rate_window'] ?? CVE_NVD_RATE_WINDOW));
        $this->rateMax = max(0, (int)($config['rate_max'] ?? CVE_NVD_RATE_MAX));
        $this->maxRetries = max(1, (int)($config['max_retries'] ?? CVE_SYNC_MAX_RETRIES));
    }

    /**
     * Configuración efectiva: settings de la BD con fallback a constantes.
     */
    public static function config(): array
    {
        return [
            'nvd_url'         => (string)setting_get('cve_nvd_url', CVE_NVD_URL),
            'cpe_url'         => (string)setting_get('cve_cpe_url', CVE_CPE_URL),
            'nvd_api_key'     => (string)setting_get('cve_nvd_api_key', CVE_NVD_API_KEY),
            'nvd_page_size'   => (int)setting_get('cve_nvd_page_size', CVE_NVD_PAGE_SIZE),
            'scope'           => (string)setting_get('cve_scope', 'full'),
            'recent_years'    => (int)setting_get('cve_recent_years', 3),
            'min_cvss'        => (float)setting_get('cve_min_cvss', 0),
            'kev_url'         => (string)setting_get('cve_kev_url', CVE_KEV_URL),
            'kev_fallback_url'=> (string)setting_get('cve_kev_fallback_url', CVE_KEV_FALLBACK_URL),
            'epss_url'        => (string)setting_get('cve_epss_url', CVE_EPSS_CSV_URL),
            'auto_sync'       => (int)setting_get('cve_auto_sync', 1),
            'interval_hours'  => (int)setting_get('cve_interval_hours', 24),
            'rate_window'     => (int)CVE_NVD_RATE_WINDOW,
            'rate_max'        => (int)CVE_NVD_RATE_MAX,
            'max_retries'     => (int)CVE_SYNC_MAX_RETRIES,
        ];
    }

    public static function fromSettings(): self
    {
        return new self(self::config());
    }

    public function hasApiKey(): bool
    {
        return $this->nvdKey !== '';
    }

    /**
     * Peticiones permitidas por ventana según las normas de NVD API 2.0:
     * 5/30 s sin API key y 50/30 s con API key (o el override configurado).
     */
    public function effectiveRateLimit(): int
    {
        return $this->rateMax > 0 ? $this->rateMax : ($this->hasApiKey() ? 50 : 5);
    }

    public function rateWindowSeconds(): int
    {
        return $this->rateWindow;
    }

    /**
     * Espera lo necesario para no superar el límite de NVD en una ventana
     * deslizante (no un sleep fijo por petición). La primera petición de cada
     * proceso deja pasar el hueco mínimo entre peticiones para no encadenar
     * ventanas entre peticiones HTTP distintas (descarga continua web).
     */
    private function throttleNvd(bool $prime = false): void
    {
        $limit = max(1, $this->effectiveRateLimit());
        $window = $this->rateWindow;

        if (!$this->throttlePrimed) {
            $this->throttlePrimed = true;
            if ($prime) {
                $gap = $window / $limit;
                if ($gap > 0) {
                    usleep((int)($gap * 1000000));
                }
            }
        }

        $filter = static function (array $times, float $now) use ($window): array {
            return array_values(array_filter(
                $times,
                static fn(float $t): bool => ($now - $t) < $window
            ));
        };

        $now = microtime(true);
        $this->nvdRequestTimes = $filter($this->nvdRequestTimes, $now);

        while (count($this->nvdRequestTimes) >= $limit) {
            $oldest = min($this->nvdRequestTimes);
            $wait = $window - ($now - $oldest);
            if ($wait <= 0) {
                break;
            }
            usleep((int)(($wait + 0.05) * 1000000));
            $now = microtime(true);
            $this->nvdRequestTimes = $filter($this->nvdRequestTimes, $now);
        }

        $this->nvdRequestTimes[] = microtime(true);
    }

    /**
     * GET a NVD con reintentos y backoff. Respeta Retry-After en 429/503 y
     * limpia la ventana de rate limit cuando NVD pide esperar.
     */
    private function nvdGetWithRetries(string $url, array $headers, int $timeout = 120): array
    {
        $attempts = max(1, $this->maxRetries);
        $res = ['http' => 0, 'body' => '', 'headers' => [], 'error' => null];
        $slept = 0;

        for ($attempt = 1; $attempt <= $attempts; $attempt++) {
            $this->lastNvdAttempts = $attempt;
            $this->throttleNvd(true);
            try {
                $res = $this->httpGet($url, $headers, $timeout, false);
            } catch (Throwable $e) {
                $res = [
                    'http'    => 0,
                    'body'    => '',
                    'headers' => [],
                    'error'   => $e->getMessage(),
                ];
            }

            $message = (string)($res['error'] ?? '');
            $permanent = $res['http'] === 0
                && (str_contains($message, 'extensión cURL') || str_contains($message, 'URL de NVD no válida'));

            $retryable = !$permanent && ($res['http'] === 429 || $res['http'] === 0 || $res['http'] >= 500);
            if (!$retryable || $attempt === $attempts) {
                break;
            }

            $retryAfter = (int)($res['headers']['retry-after'] ?? 0);
            if ($res['http'] === 429) {
                // La IP del hosting puede compartir cuota: reiniciamos la ventana.
                $this->nvdRequestTimes = [];
            }

            // Tope global de espera para no agotar el tiempo de la petición web.
            $remainingBudget = 45 - $slept;
            if ($remainingBudget <= 0) {
                break;
            }
            $backoff = $retryAfter > 0 ? $retryAfter : (10 * $attempt);
            $backoff = max(5, min(45, $backoff, $remainingBudget));
            sleep($backoff);
            $slept += $backoff;
        }

        return $res;
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

        foreach ($sources as $key => $source) {
            if (empty($source['status'])) {
                $sources[$key]['status'] = !empty($source['ok']) ? 'ok' : 'error';
            }
        }

        // NVD y EPSS son el núcleo. KEV puede quedar en warning si el
        // mirror funciona o si CISA bloquea la IP del hosting.
        $coreOk = !empty($sources['nvd']['ok']) && !empty($sources['epss']['ok']);
        $allOk = $coreOk && !empty($sources['kev']['ok']);

        return [
            'success'   => $coreOk,
            'all_ok'    => $allOk,
            'sources'   => $sources,
            'tested_at' => date('c'),
        ];
    }

    /**
     * Descarga una página de NVD API 2.0.
     *
     * @param int $startIndex Inicio (0-based)
     * @param int $pageSize Tamaño (máx. 2000)
     * @param string|null $pubStart Fecha ISO de publicación desde
     * @param string|null $pubEnd Fecha ISO de publicación hasta
     * @return array{total:int,vulnerabilities:array,timestamp:?string}
     */
    public function nvdPage(
        int $startIndex,
        int $pageSize,
        ?string $pubStart = null,
        ?string $pubEnd = null,
        ?string $lastModStart = null,
        ?string $lastModEnd = null,
        ?string $virtualMatchString = null
    ): array
    {
        if (!self::isSafeUrl($this->nvdUrl)) {
            throw new RuntimeException('URL de NVD no válida (se requiere HTTPS público).');
        }

        $pageSize = max(1, min(2000, $pageSize));
        $params = [
            'resultsPerPage' => $pageSize,
            'startIndex'     => max(0, $startIndex),
        ];
        if ($pubStart !== null && $pubEnd !== null) {
            $params['pubStartDate'] = $pubStart;
            $params['pubEndDate'] = $pubEnd;
        }
        if ($lastModStart !== null && $lastModEnd !== null) {
            $params['lastModStartDate'] = $lastModStart;
            $params['lastModEndDate'] = $lastModEnd;
        }
        if ($virtualMatchString !== null && $virtualMatchString !== '') {
            $params['virtualMatchString'] = $virtualMatchString;
        }

        $sep = str_contains($this->nvdUrl, '?') ? '&' : '?';
        $url = $this->nvdUrl . $sep . http_build_query($params) . '&noRejected';
        $headers = ['Accept: application/json'];
        if ($this->nvdKey !== '') {
            $headers[] = 'apiKey: ' . $this->nvdKey;
        }

        $res = $this->nvdGetWithRetries($url, $headers, 120);
        if ($res['http'] !== 200) {
            $attemptsUsed = max(1, $this->lastNvdAttempts);
            if ($res['http'] === 0) {
                $detail = trim((string)($res['error'] ?? ''));
                throw new RuntimeException(
                    'No se pudo conectar con NVD tras ' . $attemptsUsed . ' intento(s): '
                    . ($detail !== '' ? $detail : 'error de red')
                );
            }
            $detail = trim(strip_tags(substr((string)$res['body'], 0, 500)));
            $message = 'NVD respondió HTTP ' . $res['http'] . ' tras ' . $attemptsUsed . ' intento(s)';
            if ($res['http'] === 403 || $res['http'] === 401) {
                $message .= ' (API key inválida o sin permisos)';
            } elseif ($res['http'] === 429) {
                $message .= ' (rate limit; configura una API key de NVD)';
            }
            if ($detail !== '') {
                $message .= ': ' . $detail;
            }
            throw new RuntimeException($message);
        }

        $data = json_decode((string)$res['body'], true);
        if (!is_array($data)) {
            throw new RuntimeException('NVD devolvió un JSON no válido.');
        }

        return [
            'total'           => (int)($data['totalResults'] ?? 0),
            'vulnerabilities' => is_array($data['vulnerabilities'] ?? null) ? $data['vulnerabilities'] : [],
            'timestamp'       => isset($data['timestamp']) ? (string)$data['timestamp'] : null,
        ];
    }

    /**
     * Busca CPE en NVD por palabra clave y deduplica a la CPE base
     * (cpe:2.3:part:vendor:product, sin versión).
     */
    public function searchCpes(string $query, int $limit = 20): array
    {
        $query = trim($query);
        if ($query === '') {
            return [];
        }
        if (!self::isSafeUrl($this->cpeUrl)) {
            throw new RuntimeException('URL del buscador CPE no válida.');
        }

        $params = [
            'keywordSearch'  => $query,
            'resultsPerPage' => max(10, min(100, $limit * 3)),
        ];
        $sep = str_contains($this->cpeUrl, '?') ? '&' : '?';
        $url = $this->cpeUrl . $sep . http_build_query($params);
        $headers = ['Accept: application/json'];
        if ($this->nvdKey !== '') {
            $headers[] = 'apiKey: ' . $this->nvdKey;
        }

        $this->throttleNvd();
        $res = $this->httpGet($url, $headers, 45, false);
        if ($res['http'] !== 200) {
            throw new RuntimeException('NVD CPE respondió HTTP ' . $res['http'] . '.');
        }
        $data = json_decode((string)$res['body'], true);
        if (!is_array($data) || !is_array($data['products'] ?? null)) {
            return [];
        }

        $out = [];
        foreach ($data['products'] as $product) {
            $cpe = $product['cpe'] ?? null;
            if (!is_array($cpe) || !empty($cpe['deprecated'])) {
                continue;
            }
            $name = (string)($cpe['cpeName'] ?? '');
            if (!str_starts_with($name, 'cpe:2.3:')) {
                continue;
            }
            $parts = explode(':', $name);
            if (count($parts) < 5) {
                continue;
            }
            $base = implode(':', array_slice($parts, 0, 5));
            if (isset($out[$base])) {
                continue;
            }
            $title = ucwords(str_replace(['_', '-'], ' ', $parts[3] . ' ' . $parts[4]));
            foreach (($cpe['titles'] ?? []) as $t) {
                if (is_array($t) && ($t['lang'] ?? '') === 'es' && !preg_match('/\d/', (string)($t['title'] ?? ''))) {
                    $title = (string)$t['title'];
                    break;
                }
            }
            $out[$base] = [
                'cpe'     => $base,
                'title'   => $title,
                'vendor'  => $parts[3],
                'product' => $parts[4],
            ];
            if (count($out) >= $limit) {
                break;
            }
        }

        return array_values($out);
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
        $primary = $this->tryKevUrl($this->kevUrl);
        if (!empty($primary['ok'])) {
            return $this->result(true, 200, 'OK — ' . (string)$primary['message'], [
                'status'         => 'ok',
                'source'         => 'cisa',
                'fallback_used'  => false,
                'primary_http'   => 200,
                'count'          => $primary['count'],
                'version'        => $primary['version'],
                'released'       => $primary['released'],
            ]);
        }

        if (
            $this->kevFallbackUrl !== ''
            && $this->kevFallbackUrl !== $this->kevUrl
            && self::isSafeUrl($this->kevFallbackUrl)
        ) {
            $fallback = $this->tryKevUrl($this->kevFallbackUrl);
            if (!empty($fallback['ok'])) {
                $message = 'CISA directo HTTP ' . ($primary['http'] ?: '—')
                    . '; mirror GitHub OK — ' . $fallback['message'];
                return $this->result(true, 200, $message, [
                    'status'         => 'warning',
                    'source'         => 'github',
                    'fallback_used'  => true,
                    'primary_http'   => (int)$primary['http'],
                    'count'          => $fallback['count'],
                    'version'        => $fallback['version'],
                    'released'       => $fallback['released'],
                ]);
            }

            $message = 'CISA directo HTTP ' . ($primary['http'] ?: '—')
                . ' y mirror GitHub HTTP ' . ($fallback['http'] ?: '—') . '. '
                . $primary['message'] . ' / ' . $fallback['message'];
            return $this->result(false, 0, $message, [
                'status'         => 'error',
                'source'         => 'none',
                'fallback_used'  => true,
                'primary_http'   => (int)$primary['http'],
                'fallback_http'  => (int)$fallback['http'],
            ]);
        }

        return $this->result(false, (int)$primary['http'], (string)$primary['message'], [
            'status'        => 'error',
            'source'        => 'cisa',
            'fallback_used' => false,
            'primary_http'  => (int)$primary['http'],
        ]);
    }

    /**
     * Intenta descargar y validar un catálogo KEV desde una URL.
     */
    private function tryKevUrl(string $url): array
    {
        try {
            if (!self::isSafeUrl($url)) {
                return ['ok' => false, 'http' => 0, 'message' => 'URL de KEV no válida (se requiere HTTPS público).'];
            }

            $res = $this->httpGet($url, ['Accept: application/json'], $this->timeout, true);
            if ($res['http'] !== 200) {
                return ['ok' => false, 'http' => (int)$res['http'], 'message' => 'HTTP ' . $res['http']];
            }

            $data = json_decode($res['body'], true);
            if (!is_array($data) || !is_array($data['vulnerabilities'] ?? null)) {
                return ['ok' => false, 'http' => 200, 'message' => 'KEV no devolvió un JSON válido.'];
            }

            $count = (int)($data['count'] ?? count($data['vulnerabilities']));
            $version = (string)($data['catalogVersion'] ?? '');
            $released = (string)($data['dateReleased'] ?? '');
            $message = number_format($count) . ' CVEs';
            if ($version !== '') {
                $message .= ' (catálogo ' . $version . ')';
            }
            if ($released !== '') {
                $message .= ', publicado ' . $released;
            }

            return [
                'ok'       => true,
                'http'     => 200,
                'message'  => $message,
                'count'    => $count,
                'version'  => $version,
                'released' => $released,
                'data'     => $data,
            ];
        } catch (Throwable $e) {
            return ['ok' => false, 'http' => 0, 'message' => $e->getMessage()];
        }
    }

    /**
     * Devuelve el catálogo KEV desde CISA o el mirror oficial.
     * Lanza excepción si ninguna fuente responde.
     */
    public function fetchKevCatalog(): array
    {
        $primary = $this->tryKevUrl($this->kevUrl);
        if (!empty($primary['ok']) && is_array($primary['data'] ?? null)) {
            return [
                'source'   => 'cisa',
                'data'     => $primary['data'],
                'count'    => (int)$primary['count'],
                'version'  => (string)$primary['version'],
                'released' => (string)$primary['released'],
            ];
        }

        if (
            $this->kevFallbackUrl !== ''
            && $this->kevFallbackUrl !== $this->kevUrl
            && self::isSafeUrl($this->kevFallbackUrl)
        ) {
            $fallback = $this->tryKevUrl($this->kevFallbackUrl);
            if (!empty($fallback['ok']) && is_array($fallback['data'] ?? null)) {
                return [
                    'source'   => 'github',
                    'data'     => $fallback['data'],
                    'count'    => (int)$fallback['count'],
                    'version'  => (string)$fallback['version'],
                    'released' => (string)$fallback['released'],
                ];
            }
            throw new RuntimeException(
                'No se pudo obtener KEV. CISA: ' . $primary['message']
                . ' / GitHub: ' . $fallback['message']
            );
        }

        throw new RuntimeException('No se pudo obtener KEV: ' . $primary['message']);
    }

    /**
     * Descarga el CSV GZ diario de EPSS.
     */
    public function downloadEpssCsv(): string
    {
        if (!self::isSafeUrl($this->epssUrl)) {
            throw new RuntimeException('URL de EPSS no válida.');
        }
        $res = $this->httpGet($this->epssUrl, ['Accept: */*'], 120, true);
        if ($res['http'] !== 200) {
            throw new RuntimeException('EPSS respondió HTTP ' . $res['http'] . '.');
        }
        if ($res['body'] === '') {
            throw new RuntimeException('EPSS devolvió un cuerpo vacío.');
        }
        return (string)$res['body'];
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
