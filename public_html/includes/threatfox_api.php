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

    /** Peticiones que superan este tiempo se abandonan (segundos). */
    private const TIMEOUT = 30;

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
        if (!function_exists('curl_init')) {
            return $this->error('La extensión curl de PHP no está disponible en este servidor.');
        }

        $ch = curl_init($this->apiUrl());
        if ($ch === false) {
            return $this->error('No se pudo inicializar cURL.');
        }

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_SLASHES),
            CURLOPT_HTTPHEADER     => [
                'Auth-Key: ' . $this->authKey,
                'Content-Type: application/json',
                'User-Agent: EntraID-ThreatIntelligence/ThreatFox',
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
            CURLOPT_TIMEOUT        => self::TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        $body = curl_exec($ch);
        if ($body === false) {
            $err = curl_error($ch);
            curl_close($ch);
            return $this->error('Error de red: ' . $err);
        }

        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        $data = json_decode((string)$body, true);
        if (!is_array($data)) {
            return $this->error('Respuesta no válida de la API (HTTP ' . $status . ').');
        }

        $data['data'] = is_array($data['data'] ?? null) ? $data['data'] : [];
        $data['query_status'] = (string)($data['query_status'] ?? 'unknown');
        return $data;
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

        $ch = curl_init($base);
        if ($ch === false) {
            return false;
        }        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
            CURLOPT_TIMEOUT        => THREATFOX_EXPORT_TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $body = curl_exec($ch);
        $http = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($body === false || $http !== 200) {
            return false;
        }
        return @file_put_contents($targetZip, $body) !== false;
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
