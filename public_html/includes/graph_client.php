<?php
/**
 * GraphClient — Cliente HTTP para Microsoft Graph y Defender for Endpoint.
 * Gestiona tokens con caché, reintentos ante throttling (429) y dos audiences.
 */

declare(strict_types=1);

class GraphClient
{
    private array $tokenCache = [];
    private string $tenantId;
    private string $clientId;
    private string $clientSecret;

    public function __construct(string $tenantId, string $clientId, string $clientSecret)
    {
        $this->tenantId = $tenantId;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    // ============================================================
    // Autenticación — client credentials flow
    // ============================================================

    /**
     * Obtiene un token de acceso para el scope indicado.
     * Usa caché en memoria y en disco (storage/cache).
     */
    public function getToken(string $scope = GRAPH_SCOPE): string
    {
        $cacheKey = md5($this->tenantId . '|' . $this->clientId . '|' . $scope);

        // Caché en memoria (por request)
        if (isset($this->tokenCache[$cacheKey])) {
            $cached = $this->tokenCache[$cacheKey];
            if (time() < $cached['expires_at']) {
                return $cached['token'];
            }
        }

        // Caché en disco (entre requests)
        $cacheFile = CACHE_PATH . '/token_' . $cacheKey . '.json';
        if (file_exists($cacheFile)) {
            $data = json_decode(file_get_contents($cacheFile), true);
            if ($data && time() < $data['expires_at']) {
                $this->tokenCache[$cacheKey] = $data;
                return $data['token'];
            }
        }

        // Solicitar nuevo token
        $tokenUrl = GRAPH_AUTHORITY_BASE . $this->tenantId . GRAPH_TOKEN_PATH;

        $body = http_build_query([
            'grant_type'    => 'client_credentials',
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'scope'         => $scope,
        ]);

        $response = $this->httpRequest($tokenUrl, 'POST', $body, [
            'Content-Type: application/x-www-form-urlencoded',
        ]);

        if (!isset($response['access_token'])) {
            $error = $response['error_description'] ?? $response['error'] ?? 'Error desconocido';
            throw new RuntimeException("Error obteniendo token: $error");
        }

        $cached = [
            'token'      => $response['access_token'],
            'expires_at' => time() + (int)($response['expires_in'] ?? 3600) - 300, // -5 min margen
        ];

        $this->tokenCache[$cacheKey] = $cached;
        file_put_contents($cacheFile, json_encode($cached), LOCK_EX);

        return $cached['token'];
    }

    // ============================================================
    // Llamadas a Graph API
    // ============================================================

    /**
     * Llamada GET a Microsoft Graph.
     */
    public function graphGet(string $path, array $queryParams = []): array
    {
        $url = GRAPH_BASE_URL . ltrim($path, '/');
        if (!empty($queryParams)) {
            $url .= '?' . http_build_query($queryParams);
        }
        return $this->graphRequest($url);
    }

    /**
     * Llamada POST a Microsoft Graph.
     */
    public function graphPost(string $path, array $body = []): array
    {
        $url = GRAPH_BASE_URL . ltrim($path, '/');
        return $this->graphRequest($url, 'POST', json_encode($body));
    }

    /**
     * Llamada genérica a Microsoft Graph con reintentos.
     */
    public function graphRequest(string $url, string $method = 'GET', ?string $body = null, int $retries = 3): array
    {
        $token = $this->getToken(GRAPH_SCOPE);

        $headers = [
            'Authorization: Bearer ' . $token,
            'Content-Type: application/json',
            'Accept: application/json',
        ];

        $response = $this->httpRequest($url, $method, $body, $headers, $retries);
        return $response;
    }

    // ============================================================
    // Llamadas a Defender for Endpoint API
    // ============================================================

    /**
     * Llamada GET a Defender for Endpoint (audience diferente).
     */
    public function mdeGet(string $path, array $queryParams = []): array
    {
        $url = MDE_BASE_URL . ltrim($path, '/');
        if (!empty($queryParams)) {
            $url .= '?' . http_build_query($queryParams);
        }
        return $this->mdeRequest($url);
    }

    /**
     * Llamada genérica a Defender for Endpoint con reintentos.
     */
    public function mdeRequest(string $url, string $method = 'GET', ?string $body = null, int $retries = 3): array
    {
        $token = $this->getToken(MDE_SCOPE);

        $headers = [
            'Authorization: Bearer ' . $token,
            'Content-Type: application/json',
            'Accept: application/json',
        ];

        return $this->httpRequest($url, $method, $body, $headers, $retries);
    }

    // ============================================================
    // HTTP genérico con reintentos ante throttling
    // ============================================================

    /**
     * Ejecuta una petición HTTP usando cURL.
     */
    private function httpRequest(string $url, string $method = 'GET', ?string $body = null, array $headers = [], int $retries = 3): array
    {
        $ch = curl_init($url);

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => 60,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT      => 'EntraID-TI-Platform/1.0',
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $responseBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($responseBody === false) {
            throw new RuntimeException("Error cURL: $error");
        }

        // Manejar throttling (429)
        if ($httpCode === 429 && $retries > 1) {
            // No tenemos acceso a los headers aquí, esperar tiempo prudencial
            sleep(10);
            return $this->httpRequest($url, $method, $body, $headers, $retries - 1);
        }

        // Manejar errores 5xx con reintento
        if ($httpCode >= 500 && $retries > 1) {
            sleep(5);
            return $this->httpRequest($url, $method, $body, $headers, $retries - 1);
        }

        $decoded = json_decode($responseBody, true);

        if ($httpCode >= 400) {
            $errorMsg = $decoded['error']['message'] ?? $decoded['message'] ?? $responseBody;
            $errorCode = $decoded['error']['code'] ?? $decoded['code'] ?? "HTTP_$httpCode";
            throw new RuntimeException("API Error [$errorCode] ($httpCode): $errorMsg — URL: $url");
        }

        return $decoded ?? ['raw' => $responseBody];
    }

    // ============================================================
    // Paginación automática
    // ============================================================

    /**
     * Obtiene todas las páginas de una colección de Graph.
     * Sigue @odata.nextLink automáticamente.
     */
    public function graphGetAll(string $path, array $queryParams = [], int $maxPages = 100): array
    {
        $allValues = [];
        $url = GRAPH_BASE_URL . ltrim($path, '/');
        if (!empty($queryParams)) {
            $url .= '?' . http_build_query($queryParams);
        }

        $pageCount = 0;
        while ($url && $pageCount < $maxPages) {
            $response = $this->graphRequest($url);
            $values = $response['value'] ?? [];
            $allValues = array_merge($allValues, $values);

            // Graph devuelve nextLink absoluto
            $url = $response['@odata.nextLink'] ?? null;
            $pageCount++;
        }

        return $allValues;
    }

    /**
     * Obtiene todas las páginas de una colección de MDE.
     */
    public function mdeGetAll(string $path, array $queryParams = [], int $maxPages = 100): array
    {
        $allValues = [];
        $url = MDE_BASE_URL . ltrim($path, '/');
        if (!empty($queryParams)) {
            $url .= '?' . http_build_query($queryParams);
        }

        $pageCount = 0;
        while ($url && $pageCount < $maxPages) {
            $response = $this->mdeRequest($url);
            $values = $response['value'] ?? [];
            $allValues = array_merge($allValues, $values);
            $url = $response['@odata.nextLink'] ?? null;
            $pageCount++;
        }

        return $allValues;
    }

    // ============================================================
    // Test de conexión
    // ============================================================

    /**
     * Verifica que las credenciales funcionan obteniendo info del tenant.
     */
    public function testConnection(): array
    {
        try {
            $token = $this->getToken();
            return [
                'success' => true,
                'message' => 'Conexión exitosa. Token obtenido correctamente.',
                'token_preview' => substr($token, 0, 20) . '...',
            ];
        } catch (Throwable $e) {
            return [
                'success' => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Ejecuta una llamada de diagnóstico SIN lanzar excepción.
     * Sirve para comprobar permisos reales (403 = falta permiso/consentimiento).
     * Devuelve ['ok' => bool, 'http' => int, 'message' => string, 'count' => ?int].
     */
    public function probe(string $method, string $path, array $queryParams = [], bool $defender = false): array
    {
        try {
            if ($defender) {
                $url = MDE_BASE_URL . ltrim($path, '/');
                if (!empty($queryParams)) {
                    $url .= '?' . http_build_query($queryParams);
                }
                $response = $this->mdeRequest($url, strtoupper($method));
            } else {
                $url = GRAPH_BASE_URL . ltrim($path, '/');
                if (!empty($queryParams)) {
                    $url .= '?' . http_build_query($queryParams);
                }
                $response = $this->graphRequest($url, strtoupper($method));
            }

            $count = (isset($response['value']) && is_array($response['value'])) ? count($response['value']) : null;
            return ['ok' => true, 'http' => 200, 'message' => 'OK', 'count' => $count];
        } catch (Throwable $e) {
            $msg = $e->getMessage();
            $http = 0;
            if (preg_match('/\((\d{3})\)/', $msg, $m)) {
                $http = (int)$m[1];
            }
            return ['ok' => false, 'http' => $http, 'message' => $msg];
        }
    }
}
