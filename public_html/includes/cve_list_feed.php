<?php
/**
 * CveListFeed — descarga de la CVE List V5 (CVE.org) desde las releases de
 * CVEProject/cvelistV5 en GitHub.
 *
 * Fuente primaria del catálogo: cada registro es un CVE JSON 5.1 (contenedor
 * del fabricante + ADP de CISA) y se procesa con CveSync::parseCveOrgRecord().
 *
 * - Delta diario: `<fecha>_delta_CVEs_at_1000Z.zip` (~0,4 MB, CVEs nuevos o
 *   modificados del día). Un JSON por CVE.
 * - Snapshot completo: `<fecha>_all_CVEs_at_midnight.zip` (~630 MB), para una
 *   carga inicial sin depender de NVD.
 *
 * El ZIP se lee con ZipArchive si existe; si no, con un lector propio (la
 * release usa deflate y el directorio central trae los tamaños correctos).
 */

declare(strict_types=1);

if (!class_exists('CveZipReader')) {
    final class CveZipReader
    {
        /**
         * Entradas del ZIP (nombre => contenido). Solo ficheros de texto/JSON.
         *
         * @return array<string,string>
         */
        public static function entries(string $path): array
        {
            if (!is_file($path)) {
                return [];
            }
            if (class_exists('ZipArchive')) {
                $zip = new ZipArchive();
                if ($zip->open($path) === true) {
                    $out = [];
                    for ($i = 0; $i < $zip->numFiles; $i++) {
                        $name = $zip->getNameIndex($i);
                        if (!is_string($name) || $name === '' || str_ends_with($name, '/')) {
                            continue;
                        }
                        $content = $zip->getFromIndex($i);
                        if (is_string($content)) {
                            $out[$name] = $content;
                        }
                    }
                    $zip->close();
                    if ($out !== []) {
                        return $out;
                    }
                }
            }
            return self::entriesManual($path);
        }

        /**
         * Lector propio: recorre el directorio central (PK\x01\x02), que
         * siempre trae los tamaños reales, y lee cada entrada local.
         *
         * @return array<string,string>
         */
        public static function entriesManual(string $path): array
        {
            $data = @file_get_contents($path);
            if ($data === false || $data === '') {
                return [];
            }
            $len = strlen($data);
            $eocd = strrpos($data, "PK\x05\x06");
            if ($eocd === false || $eocd + 22 > $len) {
                return [];
            }
            $cdCount = unpack('v', substr($data, $eocd + 10, 2))[1];
            $cdOffset = unpack('V', substr($data, $eocd + 16, 4))[1];
            if ($cdCount <= 0 || $cdOffset <= 0 || $cdOffset >= $len) {
                return [];
            }

            $out = [];
            $pos = $cdOffset;
            for ($i = 0; $i < $cdCount; $i++) {
                if ($pos + 46 > $len || substr($data, $pos, 4) !== "PK\x01\x02") {
                    break;
                }
                $method = unpack('v', substr($data, $pos + 10, 2))[1];
                $csize  = unpack('V', substr($data, $pos + 20, 4))[1];
                $nlen   = unpack('v', substr($data, $pos + 28, 2))[1];
                $elen   = unpack('v', substr($data, $pos + 30, 2))[1];
                $clen   = unpack('v', substr($data, $pos + 32, 2))[1];
                $lho    = unpack('V', substr($data, $pos + 42, 4))[1];
                $name   = substr($data, $pos + 46, $nlen);
                $pos   += 46 + $nlen + $elen + $clen;

                if ($name === '' || str_ends_with($name, '/') || $lho + 30 > $len) {
                    continue;
                }
                if (substr($data, $lho, 4) !== "PK\x03\x04") {
                    continue;
                }
                $lNlen = unpack('v', substr($data, $lho + 26, 2))[1];
                $lElen = unpack('v', substr($data, $lho + 28, 2))[1];
                $start = $lho + 30 + $lNlen + $lElen;
                if ($start + $csize > $len) {
                    continue;
                }
                $raw = substr($data, $start, $csize);
                if ($method === 0) {
                    $out[$name] = $raw;
                } elseif ($method === 8) {
                    $inflated = @gzinflate($raw);
                    if (is_string($inflated)) {
                        $out[$name] = $inflated;
                    }
                }
            }
            return $out;
        }
    }
}

if (!class_exists('CveListFeed')) {
    final class CveListFeed
    {
        private const RELEASES_API = 'https://api.github.com/repos/CVEProject/cvelistV5/releases/latest';
        private const RELEASE_API  = 'https://api.github.com/repos/CVEProject/cvelistV5/releases/tags/';

        public static function storageDir(): string
        {
            $dbPath = defined('CVE_DB_PATH') ? (string)CVE_DB_PATH : (STORAGE_PATH . '/cve.sqlite');
            $dir = rtrim(dirname($dbPath), '/\\') . DIRECTORY_SEPARATOR . 'cve-list';
            if (!is_dir($dir)) {
                @mkdir($dir, 0750, true);
            }
            return $dir;
        }

        /**
         * Última release de cvelistV5 con sus assets.
         *
         * @return array{tag:string,published:string,delta_url:string,delta_name:string,snapshot_url:string,snapshot_name:string}|null
         */
        public static function latestRelease(int $timeout = 25): ?array
        {
            $json = self::httpGetJson(self::RELEASES_API, $timeout);
            if ($json === null) {
                return null;
            }
            $tag = (string)($json['tag_name'] ?? '');
            $assets = is_array($json['assets'] ?? null) ? $json['assets'] : [];
            $deltaUrl = '';
            $deltaName = '';
            $snapUrl = '';
            $snapName = '';
            foreach ($assets as $asset) {
                if (!is_array($asset)) {
                    continue;
                }
                $name = (string)($asset['name'] ?? '');
                $url = (string)($asset['browser_download_url'] ?? '');
                if ($name === '' || $url === '') {
                    continue;
                }
                if (str_contains($name, '_delta_') && str_ends_with($name, '.zip')) {
                    $deltaUrl = $url;
                    $deltaName = $name;
                } elseif (str_contains($name, '_all_CVEs_') && str_ends_with($name, '.zip')) {
                    $snapUrl = $url;
                    $snapName = $name;
                }
            }
            if ($tag === '' || $deltaUrl === '') {
                return null;
            }
            return [
                'tag'          => $tag,
                'published'    => (string)($json['published_at'] ?? ''),
                'delta_url'    => $deltaUrl,
                'delta_name'   => $deltaName,
                'snapshot_url' => $snapUrl,
                'snapshot_name' => $snapName,
            ];
        }

        /**
         * Descarga el delta diario. Reutiliza el fichero si ya está completo.
         *
         * @return array{ok:bool,path?:string,release?:string,bytes?:int,skipped?:bool,error?:string}
         */
        public static function downloadDelta(int $timeout = 60): array
        {
            $release = self::latestRelease();
            if ($release === null) {
                return ['ok' => false, 'error' => 'No se pudo consultar la última release de CVE List V5 (GitHub).'];
            }
            $dest = self::storageDir() . DIRECTORY_SEPARATOR . $release['delta_name'];
            if (is_file($dest) && filesize($dest) > 0) {
                return [
                    'ok'      => true,
                    'path'    => $dest,
                    'release' => $release['tag'],
                    'bytes'   => (int)filesize($dest),
                    'skipped' => true,
                ];
            }
            $dl = self::download($release['delta_url'], $dest, $timeout);
            if (empty($dl['ok'])) {
                return ['ok' => false, 'error' => (string)($dl['error'] ?? 'No se pudo descargar el delta.')];
            }
            return [
                'ok'      => true,
                'path'    => $dest,
                'release' => $release['tag'],
                'bytes'   => (int)($dl['bytes'] ?? 0),
                'skipped' => false,
            ];
        }

        /**
         * Descarga el snapshot completo (~630 MB). Pensado para CLI.
         *
         * @return array{ok:bool,path?:string,release?:string,bytes?:int,error?:string}
         */
        public static function downloadSnapshot(int $timeout = 1800): array
        {
            $release = self::latestRelease();
            if ($release === null || $release['snapshot_url'] === '') {
                return ['ok' => false, 'error' => 'La release no incluye snapshot completo.'];
            }
            $dest = self::storageDir() . DIRECTORY_SEPARATOR . $release['snapshot_name'];
            $dl = self::download($release['snapshot_url'], $dest, $timeout);
            if (empty($dl['ok'])) {
                return ['ok' => false, 'error' => (string)($dl['error'] ?? 'No se pudo descargar el snapshot.')];
            }
            return [
                'ok'      => true,
                'path'    => $dest,
                'release' => $release['tag'],
                'bytes'   => (int)($dl['bytes'] ?? 0),
            ];
        }

        /**
         * Registros CVE JSON 5.1 de un ZIP de la release.
         *
         * @return array<int,array<string,mixed>>
         */
        public static function recordsFromZip(string $path, int $limit = 0): array
        {
            $entries = CveZipReader::entries($path);
            $records = [];
            foreach ($entries as $name => $content) {
                if (!str_ends_with(strtolower((string)$name), '.json')) {
                    continue;
                }
                $decoded = json_decode((string)$content, true);
                if (is_array($decoded) && isset($decoded['cveMetadata'])) {
                    $records[] = $decoded;
                    if ($limit > 0 && count($records) >= $limit) {
                        break;
                    }
                }
            }
            return $records;
        }

        /**
         * GET binario con reanudación por HTTP Range y fichero .part.
         *
         * @return array{ok:bool,bytes?:int,error?:string}
         */
        public static function download(string $url, string $dest, int $timeout = 120): array
        {
            $part = $dest . '.part';
            $offset = is_file($part) ? (int)filesize($part) : 0;

            if (!function_exists('curl_init')) {
                $body = @file_get_contents($url, false, stream_context_create([
                    'http' => ['timeout' => $timeout, 'follow_location' => 1],
                    'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
                ]));
                if ($body === false) {
                    return ['ok' => false, 'error' => 'No se pudo descargar (sin cURL).'];
                }
                if (@file_put_contents($dest, $body) === false) {
                    return ['ok' => false, 'error' => 'No se pudo guardar el fichero.'];
                }
                return ['ok' => true, 'bytes' => strlen($body)];
            }

            $fh = @fopen($part, $offset > 0 ? 'ab' : 'wb');
            if ($fh === false) {
                return ['ok' => false, 'error' => 'No se pudo abrir el fichero temporal.'];
            }
            $ch = curl_init($url);
            $headers = ['Accept: application/octet-stream'];
            if ($offset > 0) {
                $headers[] = 'Range: bytes=' . $offset . '-';
            }
            curl_setopt_array($ch, [
                CURLOPT_FILE           => $fh,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 5,
                CURLOPT_TIMEOUT        => $timeout,
                CURLOPT_CONNECTTIMEOUT => 20,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_USERAGENT      => 'EntraID-TI-CVE/1.0',
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            $ok = curl_exec($ch);
            $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = curl_error($ch);
            curl_close($ch);
            fclose($fh);

            if ($ok === false) {
                return ['ok' => false, 'error' => $err !== '' ? $err : 'Error de descarga.'];
            }
            if ($http !== 200 && $http !== 206) {
                @unlink($part);
                return ['ok' => false, 'error' => 'HTTP ' . $http . ' al descargar la release.'];
            }
            if (!@rename($part, $dest)) {
                return ['ok' => false, 'error' => 'No se pudo mover el fichero descargado.'];
            }
            return ['ok' => true, 'bytes' => (int)filesize($dest)];
        }

        /** @return array<string,mixed>|null */
        private static function httpGetJson(string $url, int $timeout): ?array
        {
            if (function_exists('curl_init')) {
                $ch = curl_init($url);
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT        => $timeout,
                    CURLOPT_CONNECTTIMEOUT => 15,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_HTTPHEADER     => ['Accept: application/vnd.github+json'],
                    CURLOPT_USERAGENT      => 'EntraID-TI-CVE/1.0',
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                ]);
                $body = curl_exec($ch);
                $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                if ($body === false || $http !== 200) {
                    return null;
                }
                $json = json_decode((string)$body, true);
                return is_array($json) ? $json : null;
            }

            $ctx = stream_context_create([
                'http' => [
                    'method'        => 'GET',
                    'header'        => "Accept: application/vnd.github+json\r\nUser-Agent: EntraID-TI-CVE/1.0\r\n",
                    'timeout'       => $timeout,
                    'ignore_errors' => true,
                ],
                'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
            ]);
            $body = @file_get_contents($url, false, $ctx);
            if ($body === false) {
                return null;
            }
            $json = json_decode($body, true);
            return is_array($json) ? $json : null;
        }
    }
}
