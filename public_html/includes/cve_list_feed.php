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
         * Nombres de las entradas del ZIP (solo el directorio central, sin
         * leer contenido). Útil para detectar el ZIP anidado del snapshot.
         *
         * @return string[]
         */
        public static function listNames(string $path): array
        {
            if (!is_file($path)) {
                return [];
            }
            if (class_exists('ZipArchive')) {
                $zip = new ZipArchive();
                if ($zip->open($path) === true) {
                    $names = [];
                    for ($i = 0; $i < $zip->numFiles; $i++) {
                        $name = $zip->getNameIndex($i);
                        if (is_string($name) && $name !== '' && !str_ends_with($name, '/')) {
                            $names[] = $name;
                        }
                    }
                    $zip->close();
                    if ($names !== []) {
                        return $names;
                    }
                }
            }

            $fh = @fopen($path, 'rb');
            if ($fh === false) {
                return [];
            }
            $names = [];
            $cd = self::centralDirectory($fh);
            if ($cd !== null) {
                fseek($fh, $cd['offset']);
                for ($i = 0; $i < $cd['count']; $i++) {
                    $h = fread($fh, 46);
                    if (strlen($h) !== 46 || substr($h, 0, 4) !== "PK\x01\x02") {
                        break;
                    }
                    $nlen = unpack('v', substr($h, 28, 2))[1];
                    $elen = unpack('v', substr($h, 30, 2))[1];
                    $clen = unpack('v', substr($h, 32, 2))[1];
                    $name = $nlen > 0 ? (string)fread($fh, $nlen) : '';
                    if ($elen + $clen > 0) {
                        fseek($fh, $elen + $clen, SEEK_CUR);
                    }
                    if ($name !== '' && !str_ends_with($name, '/')) {
                        $names[] = $name;
                    }
                }
            }
            fclose($fh);
            return $names;
        }

        /**
         * Recorre las entradas una a una (memoria acotada). Para ficheros
         * grandes: solo se carga en memoria el contenido de cada entrada.
         *
         * @return Generator<string,string>
         */
        public static function streamEntries(string $path): Generator
        {
            if (!is_file($path)) {
                return;
            }
            $fh = @fopen($path, 'rb');
            if ($fh === false) {
                return;
            }
            $cd = self::centralDirectory($fh);
            if ($cd === null) {
                fclose($fh);
                return;
            }

            $cdOffset = $cd['offset'];
            for ($i = 0; $i < $cd['count']; $i++) {
                fseek($fh, $cdOffset);
                $h = fread($fh, 46);
                if (strlen($h) !== 46 || substr($h, 0, 4) !== "PK\x01\x02") {
                    break;
                }
                $method = unpack('v', substr($h, 10, 2))[1];
                $csize  = unpack('V', substr($h, 20, 4))[1];
                $nlen   = unpack('v', substr($h, 28, 2))[1];
                $elen   = unpack('v', substr($h, 30, 2))[1];
                $clen   = unpack('v', substr($h, 32, 2))[1];
                $lho    = unpack('V', substr($h, 42, 4))[1];
                $name   = $nlen > 0 ? (string)fread($fh, $nlen) : '';
                $cdOffset += 46 + $nlen + $elen + $clen;

                if ($name === '' || str_ends_with($name, '/')) {
                    continue;
                }

                fseek($fh, $lho);
                $lh = fread($fh, 30);
                if (strlen($lh) !== 30 || substr($lh, 0, 4) !== "PK\x03\x04") {
                    continue;
                }
                $lNlen = unpack('v', substr($lh, 26, 2))[1];
                $lElen = unpack('v', substr($lh, 28, 2))[1];
                fseek($fh, $lho + 30 + $lNlen + $lElen);
                $raw = $csize > 0 ? (string)fread($fh, $csize) : '';

                if ($method === 0) {
                    yield $name => $raw;
                } elseif ($method === 8) {
                    $inflated = @gzinflate($raw);
                    if (is_string($inflated)) {
                        yield $name => $inflated;
                    }
                }
            }
            fclose($fh);
        }

        /**
         * Extrae una entrada a un fichero por streaming (sin cargarla entera
         * en memoria). Necesario para el ZIP anidado del snapshot.
         */
        public static function extractEntryTo(string $zipPath, string $entryName, string $dest): bool
        {
            if (!is_file($zipPath)) {
                return false;
            }
            $in = @fopen($zipPath, 'rb');
            if ($in === false) {
                return false;
            }
            $cd = self::centralDirectory($in);
            if ($cd === null) {
                fclose($in);
                return false;
            }

            $found = null;
            $cdOffset = $cd['offset'];
            for ($i = 0; $i < $cd['count']; $i++) {
                fseek($in, $cdOffset);
                $h = fread($in, 46);
                if (strlen($h) !== 46 || substr($h, 0, 4) !== "PK\x01\x02") {
                    break;
                }
                $method = unpack('v', substr($h, 10, 2))[1];
                $csize  = unpack('V', substr($h, 20, 4))[1];
                $nlen   = unpack('v', substr($h, 28, 2))[1];
                $elen   = unpack('v', substr($h, 30, 2))[1];
                $clen   = unpack('v', substr($h, 32, 2))[1];
                $lho    = unpack('V', substr($h, 42, 4))[1];
                $name   = $nlen > 0 ? (string)fread($in, $nlen) : '';
                $cdOffset += 46 + $nlen + $elen + $clen;
                if ($name === $entryName) {
                    $found = ['method' => $method, 'csize' => $csize, 'lho' => $lho];
                    break;
                }
            }
            if ($found === null) {
                fclose($in);
                return false;
            }

            fseek($in, $found['lho']);
            $lh = fread($in, 30);
            if (strlen($lh) !== 30 || substr($lh, 0, 4) !== "PK\x03\x04") {
                fclose($in);
                return false;
            }
            $lNlen = unpack('v', substr($lh, 26, 2))[1];
            $lElen = unpack('v', substr($lh, 28, 2))[1];
            fseek($in, $found['lho'] + 30 + $lNlen + $lElen);

            $out = @fopen($dest, 'wb');
            if ($out === false) {
                fclose($in);
                return false;
            }

            $ok = true;
            if ($found['method'] === 0) {
                $left = $found['csize'];
                while ($left > 0) {
                    $chunk = fread($in, min(262144, $left));
                    if ($chunk === false || $chunk === '') {
                        $ok = false;
                        break;
                    }
                    $left -= strlen($chunk);
                    fwrite($out, $chunk);
                }
            } elseif ($found['method'] === 8 && function_exists('inflate_init')) {
                $ctx = inflate_init(ZLIB_ENCODING_RAW);
                $left = $found['csize'];
                while ($left > 0) {
                    $chunk = fread($in, min(262144, $left));
                    if ($chunk === false || $chunk === '') {
                        $ok = false;
                        break;
                    }
                    $left -= strlen($chunk);
                    $inflated = @inflate_add($ctx, $chunk, ZLIB_SYNC_FLUSH);
                    if ($inflated === false) {
                        $ok = false;
                        break;
                    }
                    fwrite($out, $inflated);
                }
            } else {
                $ok = false;
            }

            fclose($out);
            fclose($in);
            if (!$ok) {
                @unlink($dest);
            }
            return $ok;
        }

        /**
         * Localiza el directorio central (EOCD) y devuelve offset y nº de
         * entradas.
         *
         * @param resource $fh
         * @return array{offset:int,count:int}|null
         */
        private static function centralDirectory($fh): ?array
        {
            $stat = fstat($fh);
            $size = (int)($stat['size'] ?? 0);
            if ($size < 22) {
                return null;
            }
            $tailLen = min($size, 65557);
            fseek($fh, $size - $tailLen);
            $tail = (string)fread($fh, $tailLen);
            $eocd = strrpos($tail, "PK\x05\x06");
            if ($eocd === false || $eocd + 22 > strlen($tail)) {
                return null;
            }
            $count  = unpack('v', substr($tail, $eocd + 10, 2))[1];
            $offset = unpack('V', substr($tail, $eocd + 16, 4))[1];
            if ($count <= 0 || $offset <= 0 || $offset >= $size) {
                return null;
            }
            return ['offset' => $offset, 'count' => $count];
        }

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
         * Registros CVE JSON 5.1 de un ZIP de la release, uno a uno (memoria
         * acotada). Soporta el snapshot, que es un ZIP dentro de otro ZIP.
         *
         * @return Generator<int,array<string,mixed>>
         */
        public static function iterateRecords(string $zipPath): Generator
        {
            $names = CveZipReader::listNames($zipPath);
            if ($names === []) {
                return;
            }

            // Snapshot: un único .zip anidado (663 MB). Se extrae en streaming
            // a un temporal y se recorre; nunca se carga entero en memoria.
            if (count($names) === 1 && str_ends_with(strtolower($names[0]), '.zip')) {
                $tmp = tempnam(sys_get_temp_dir(), 'cvelist');
                if ($tmp === false) {
                    return;
                }
                try {
                    if (CveZipReader::extractEntryTo($zipPath, $names[0], $tmp)) {
                        yield from self::iterateRecords($tmp);
                    }
                } finally {
                    @unlink($tmp);
                }
                return;
            }

            foreach (CveZipReader::streamEntries($zipPath) as $name => $content) {
                if (!str_ends_with(strtolower((string)$name), '.json')) {
                    continue;
                }
                $decoded = json_decode((string)$content, true);
                if (is_array($decoded) && isset($decoded['cveMetadata'])) {
                    yield $decoded;
                }
            }
        }

        /**
         * Registros CVE JSON 5.1 de un ZIP de la release (array). Para ficheros
         * grandes usa iterateRecords().
         *
         * @return array<int,array<string,mixed>>
         */
        public static function recordsFromZip(string $path, int $limit = 0): array
        {
            $records = [];
            foreach (self::iterateRecords($path) as $record) {
                $records[] = $record;
                if ($limit > 0 && count($records) >= $limit) {
                    break;
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
