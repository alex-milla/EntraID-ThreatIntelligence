<?php
/**
 * ThreatfoxApi — Cliente de la API v1 de ThreatFox (abuse.ch).
 *
 * Documentación: https://threatfox.abuse.ch/api/
 *
 * Reglas de la fuente:
 *  · Endpoint único POST https://threatfox-api.abuse.ch/api/v1/
 *  · Cabecera obligatoria "Auth-Key" (gratuita en https://auth.abuse.ch/)
 *  · Cuerpo y respuesta JSON con "query_status" y "data"
 *  · Uso bajo fair use: la ingesta diaria (get_iocs, 1-7 días) es la única
 *    llamada recurrente; el resto de consultas son manuales.
 *
 * La clase nunca lanza excepciones hacia la vista: normaliza cualquier error
 * de red o de JSON a un estado propio ("client_error").
 */

declare(strict_types=1);

final class ThreatfoxApi
{
    /** Estados conocidos de la API. */
    public const STATUS_OK = 'ok';

    /** Tiempo total por petición y tiempo de conexión (segundos). */
    private const TIMEOUT = 60;
    private const CONNECT_TIMEOUT = 15;

    /** Intentos por petición y backoff base (microsegundos). */
    private const RETRIES = 3;
    private const RETRY_DELAY_US = 500000;

    private string $authKey;

    public function __construct(string $authKey)
    {
        $this->authKey = trim($authKey);
    }

    /**
     * Resuelve la Auth-Key: variable de entorno/.env primero y, si no hay,
     * el ajuste cifrado guardado desde la interfaz del módulo.
     */
    public static function resolveAuthKey(): string
    {
        $fromEnv = trim((string)THREATFOX_AUTH_KEY);
        if ($fromEnv !== '') {
            return $fromEnv;
        }
        try {
            return trim((string)setting_get('threatfox_auth_key', ''));
        } catch (Throwable $e) {
            return '';
        }
    }

    /** Indica si hay alguna clave configurada (para avisos de la UI). */
    public static function hasAuthKey(): bool
    {
        return self::resolveAuthKey() !== '';
    }

    /** ¿La clave viene del entorno? (entonces la UI la muestra en solo lectura). */
    public static function authKeyFromEnv(): bool
    {
        return trim((string)THREATFOX_AUTH_KEY) !== '';
    }

    private function apiUrl(): string
    {
        $override = getenv('THREATFOX_API_URL');
        if ($override !== false && $override !== '') {
            return (string)$override;
        }
        return (string)THREATFOX_API_URL;
    }

    /**
     * Ejecuta una consulta contra la API.
     * Siempre devuelve un array con al menos "query_status" y "data".
     */
    public function call(array $payload): array
    {
        if ($this->authKey === '') {
            return $this->error('Falta la Auth-Key de abuse.ch.');
        }

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $lastError = 'Error de red desconocido';

        // 1) cURL (con reintentos). Se pide compresión solo como cabecera HTTP:
        //    así no dependemos de CURLOPT_ENCODING, que algunos hostings rechazan.
        if (function_exists('curl_init')) {
            for ($attempt = 0; $attempt < self::RETRIES; $attempt++) {
                $ch = curl_init($this->apiUrl());
                if ($ch === false) {
                    $lastError = 'No se pudo inicializar cURL.';
                    break;
                }

                // Array original: es lo que ya funcionaba en hosting compartido.
                curl_setopt_array($ch, [
                    CURLOPT_POST           => true,
                    CURLOPT_POSTFIELDS     => $json,
                    CURLOPT_HTTPHEADER     => $this->headers(),
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
                    CURLOPT_TIMEOUT        => self::TIMEOUT,
                    CURLOPT_SSL_VERIFYPEER => true,
                ]);
                $this->applyOptionalCurlOptions($ch, $attempt);

                $body = curl_exec($ch);
                $errno = (int)curl_errno($ch);
                $error = (string)curl_error($ch);
                $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                curl_close($ch);

                if ($body === false) {
                    $lastError = 'Error de red (curl ' . $errno . '): ' . $error;
                    // Un corte de transferencia (curl 18) no se arregla
                    // repitiendo la misma petición: se va al fallback de stream.
                    $partial = defined('CURLE_PARTIAL_FILE') ? CURLE_PARTIAL_FILE : 18;
                    if ($errno === $partial) {
                        break;
                    }
                } elseif ($status === 429 || $status >= 500) {
                    $lastError = 'La API respondió HTTP ' . $status;
                } else {
                    $data = json_decode($this->decodeBody((string)$body), true);
                    if (is_array($data)) {
                        $data['data'] = is_array($data['data'] ?? null) ? $data['data'] : [];
                        $data['query_status'] = (string)($data['query_status'] ?? 'unknown');
                        return $data;
                    }
                    $lastError = 'Respuesta no válida de la API (HTTP ' . $status . ').';
                }

                if ($attempt + 1 < self::RETRIES) {
                    usleep(self::RETRY_DELAY_US * ($attempt + 1));
                }
            }
        } else {
            $lastError = 'La extensión curl de PHP no está disponible en este servidor.';
        }

        // 2) Fallback con el wrapper HTTP de PHP (HTTP/1.1 directo, sin libcurl).
        $stream = $this->callViaStream($json);
        if ($stream !== null) {
            return $stream;
        }

        return $this->error($lastError);
    }

    /** IOCs recientes por first_seen (máximo 7 días). */
    public function getIocs(int $days = 1): array
    {
        return $this->call([
            'query' => 'get_iocs',
            'days'  => max(1, min(THREATFOX_DAYS_MAX, $days)),
        ]);
    }

    /** Búsqueda de IOC (wildcard o exacta). */
    public function searchIoc(string $term, int $limit = 100, bool $exact = false): array
    {
        return $this->call([
            'query'        => 'search_ioc',
            'search_term'  => $term,
            'exact_match'  => $exact,
            'limit'        => $this->clampLimit($limit),
        ]);
    }

    /** IOCs de una familia de malware. */
    public function searchMalware(string $malware, int $limit = 100): array
    {
        return $this->call([
            'query'   => 'malwareinfo',
            'malware' => $malware,
            'limit'   => $this->clampLimit($limit),
        ]);
    }

    /** IOCs con una etiqueta. */
    public function searchTag(string $tag, int $limit = 100): array
    {
        return $this->call([
            'query' => 'taginfo',
            'tag'   => $tag,
            'limit' => $this->clampLimit($limit),
        ]);
    }

    /** IOCs ligados a un hash MD5/SHA1/SHA256. */
    public function searchHash(string $hash): array
    {
        $hash = preg_replace('/\s+/', '', $hash) ?? '';
        if ($hash === '') {
            return $this->error('Hash vacío.');
        }
        return $this->call(['query' => 'search_hash', 'hash' => $hash]);
    }

    /** Catálogo de tipos de IOC y de amenaza soportados. */
    public function types(): array
    {
        return $this->call(['query' => 'types']);
    }

    /**
     * Catálogo de tipos con caché en disco (24 h por defecto).
     * Devuelve ['ioc_type' => [...], 'threat_type' => [...]].
     */
    public function typesCached(): array
    {
        $cachePath = STORAGE_PATH . '/threatfox-types.json';
        $ttl = THREATFOX_TYPES_TTL_HOURS * 3600;

        if (is_file($cachePath) && (time() - (int)@filemtime($cachePath)) < $ttl) {
            $cached = safe_json_decode((string)@file_get_contents($cachePath), null);
            if (is_array($cached)) {
                return [
                    'ioc_type'    => array_values((array)($cached['ioc_type'] ?? [])),
                    'threat_type' => array_values((array)($cached['threat_type'] ?? [])),
                ];
            }
        }

        $res = $this->types();
        $out = ['ioc_type' => [], 'threat_type' => []];
        if (($res['query_status'] ?? '') === self::STATUS_OK) {
            foreach ((array)($res['data'] ?? []) as $row) {
                if (!is_array($row)) {
                    continue;
                }
                if (!empty($row['ioc_type'])) {
                    $out['ioc_type'][] = (string)$row['ioc_type'];
                }
                if (!empty($row['threat_type'])) {
                    $out['threat_type'][] = (string)$row['threat_type'];
                }
            }
            $out['ioc_type'] = array_values(array_unique($out['ioc_type']));
            $out['threat_type'] = array_values(array_unique($out['threat_type']));
            sort($out['ioc_type']);
            sort($out['threat_type']);

            if (is_dir(dirname($cachePath))) {
                @file_put_contents($cachePath, json_encode($out, JSON_UNESCAPED_SLASHES));
            }
        }

        return $out;
    }

    /** Descarga el export completo (~6 meses) y devuelve la ruta del ZIP temporal. */
    public function downloadFullExport(string $targetZip): bool
    {
        if (!function_exists('curl_init')) {
            return false;
        }

        $override = getenv('THREATFOX_EXPORT_URL');
        $base = ($override !== false && $override !== '') ? (string)$override : (string)THREATFOX_EXPORT_URL;
        if ($base === '') {
            $base = 'https://threatfox-api.abuse.ch/v2/files/exports/'
                . rawurlencode($this->authKey) . '/full.csv.zip';
        }

        for ($attempt = 0; $attempt < self::RETRIES; $attempt++) {
            $ch = curl_init($base);
            if ($ch === false) {
                return false;
            }
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
                CURLOPT_TIMEOUT        => THREATFOX_EXPORT_TIMEOUT,
                CURLOPT_SSL_VERIFYPEER => true,
            ]);
            $this->applyOptionalCurlOptions($ch, $attempt);

            $body = curl_exec($ch);
            $http = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);

            if ($body !== false && $http === 200) {
                return @file_put_contents($targetZip, $body) !== false;
            }
            if (($body === false || $http === 429 || $http >= 500) && $attempt + 1 < self::RETRIES) {
                usleep(self::RETRY_DELAY_US * ($attempt + 1));
                continue;
            }
            return false;
        }

        return false;
    }

    /** Cabeceras comunes. Se pide gzip para reducir el payload de get_iocs. */
    private function headers(): array
    {
        return [
            'Auth-Key: ' . $this->authKey,
            'Content-Type: application/json',
            'User-Agent: EntraID-ThreatIntelligence/ThreatFox',
            'Accept-Encoding: gzip, deflate',
            'Connection: close',
        ];
    }

    /** Decodifica gzip/zlib si el servidor comprimió la respuesta. */
    private function decodeBody(string $body): string
    {
        if (strlen($body) >= 2 && ord($body[0]) === 0x1f && ord($body[1]) === 0x8b) {
            $decoded = @gzdecode($body);
            return $decoded === false ? $body : $decoded;
        }
        if (strlen($body) >= 2 && ord($body[0]) === 0x78
            && in_array(ord($body[1]), [0x01, 0x9c, 0xda], true)) {
            $decoded = @gzuncompress($body);
            return $decoded === false ? $body : $decoded;
        }
        return $body;
    }

    /**
     * Segunda vía de transporte: el wrapper HTTP de PHP con HTTP/1.1 directo.
     * No usa libcurl, así que esquiva los problemas de HTTP/2 y de extensiones
     * recortadas en hosting compartido (mismo patrón que Unit42Feed).
     */
    private function callViaStream(string $json): ?array
    {
        $context = stream_context_create([
            'http' => [
                'method'           => 'POST',
                'header'           => implode("\r\n", $this->headers()) . "\r\n",
                'content'          => $json,
                'timeout'          => self::TIMEOUT,
                'protocol_version' => 1.1,
                'ignore_errors'    => true,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        $body = @file_get_contents($this->apiUrl(), false, $context);
        if ($body === false) {
            return null;
        }

        $status = 0;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', (string)$line, $matches)) {
                $status = (int)$matches[1];
            }
        }
        if ($status === 0 || $status === 429 || $status >= 500) {
            return null;
        }

        $data = json_decode($this->decodeBody((string)$body), true);
        if (!is_array($data)) {
            return null;
        }
        $data['data'] = is_array($data['data'] ?? null) ? $data['data'] : [];
        $data['query_status'] = (string)($data['query_status'] ?? 'unknown');
        return $data;
    }

    /**
     * Opciones avanzadas, best-effort. Se aplican FUERA de curl_setopt_array():
     * en hostings compartidos con libcurl antigua o recortada, curl_setopt_array()
     * valida el array completo y falla con "must contain only valid cURL options".
     * Si una constante no existe o la libcurl no la acepta, simplemente se omite.
     */
    private function applyOptionalCurlOptions($ch, int $attempt): void
    {
        if (defined('CURL_HTTP_VERSION_1_1')) {
            $this->setOptionalCurlOption($ch, 'CURLOPT_HTTP_VERSION', constant('CURL_HTTP_VERSION_1_1'));
        }
        if ($attempt > 0) {
            $this->setOptionalCurlOption($ch, 'CURLOPT_FRESH_CONNECT', true);
            $this->setOptionalCurlOption($ch, 'CURLOPT_FORBID_REUSE', true);
        }
    }

    /** Aplica una opción solo si la constante existe y la libcurl la acepta. */
    private function setOptionalCurlOption($ch, string $name, $value): bool
    {
        if (!defined($name)) {
            return false;
        }
        try {
            return @curl_setopt($ch, constant($name), $value) === true;
        } catch (Throwable $e) {
            return false;
        }
    }

    private function clampLimit(int $limit): int
    {
        return max(1, min(1000, $limit));
    }

    private function error(string $message): array
    {
        return [
            'query_status' => 'client_error',
            'error'        => $message,
            'data'         => [],
        ];
    }
}
