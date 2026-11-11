<?php
/**
 * exposed_report_parser.php — Parser del CSV de Advanced Hunting para el
 * informe de equipos internet-exposed con parcheo de SO pendiente.
 *
 * Puro: no toca base de datos, no hace red y no depende del módulo. El
 * contrato son las 14 columnas de la especificación, en este orden exacto.
 *
 * Uso:
 *   $out = ExposedReportParser::parse($csv);
 *   if (!$out['ok']) { ... $out['errors'] ... }
 *   $rows = $out['rows']; $stats = $out['stats'];
 */

declare(strict_types=1);

if (!class_exists('ExposedReportParser')) {
    final class ExposedReportParser
    {
        /** Tope de subida propio; la interfaz muestra el mínimo con php.ini. */
        public const MAX_BYTES = 5242880; // 5 MB

        /** Servidores por informe: más filas no caben en una llamada razonable. */
        public const MAX_ROWS = 500;

        /** Tamaño máximo del CSV que se envía al modelo. */
        public const MAX_PROMPT_BYTES = 1048576; // 1 MB

        /** Avisos que se conservan; el resto solo se cuentan. */
        public const MAX_WARNINGS = 50;

        public const COLUMNS = [
            'DeviceName',
            'ExposureLevel',
            'OSPlatform',
            'PublicIP',
            'KBsPendientes',
            'PaquetesPendientes',
            'CVEs',
            'Criticos',
            'ExploitsPublicos',
            'CVEsConExploit',
            'SinParchearDesde',
            'PaqueteMasAntiguo',
            'DiasSinParchear',
            'TieneExploit',
        ];

        public const EXPOSURE_LEVELS = ['High', 'Medium'];

        /** Consulta de origen (Defender XDR → Hunting → Advanced Hunting). */
        public const KQL = <<<'KQL'
let ExposedDevices =
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | where IsInternetFacing == true and ExposureLevel in ("High", "Medium")
    | project DeviceId, DeviceName, ExposureLevel, OSPlatform, PublicIP;
ExposedDevices
| join kind=inner DeviceTvmSoftwareVulnerabilities on DeviceId
| where SoftwareName startswith "Windows"
| lookup kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
| summarize
      KBsPendientes      = dcount(RecommendedSecurityUpdateId),
      PaquetesPendientes = make_set(RecommendedSecurityUpdate),
      CVEs               = dcount(CveId),
      Criticos           = countif(VulnerabilitySeverityLevel == "Critical"),
      ExploitsPublicos   = countif(IsExploitAvailable == true),
      CVEsConExploit     = make_set_if(CveId, IsExploitAvailable == true),
      (SinParchearDesde, PaqueteMasAntiguo) = arg_min(PublishedDate, RecommendedSecurityUpdate)
    by DeviceName, ExposureLevel, OSPlatform, PublicIP
| extend DiasSinParchear = datetime_diff("day", now(), SinParchearDesde),
         TieneExploit    = ExploitsPublicos > 0
| order by ExploitsPublicos desc, DiasSinParchear desc
KQL;

        /**
         * Tamaño máximo de subida real: el menor entre el tope propio y php.ini.
         */
        public static function maxUploadBytes(): int
        {
            $ini = self::iniBytes((string)ini_get('upload_max_filesize'));
            return $ini > 0 ? min(self::MAX_BYTES, $ini) : self::MAX_BYTES;
        }

        /** Convierte "2M"/"8M"/"512K" de php.ini a bytes. */
        public static function iniBytes(string $value): int
        {
            $value = trim($value);
            if ($value === '') {
                return 0;
            }
            $unit = strtolower(substr($value, -1));
            $number = (float)$value;
            return (int)match ($unit) {
                'g' => $number * 1073741824,
                'm' => $number * 1048576,
                'k' => $number * 1024,
                default => $number,
            };
        }

        /**
         * Lee y valida el CSV completo.
         *
         * @return array{ok:bool,errors:string[],warnings:string[],warnings_total:int,rows:array<int,array<string,mixed>>,stats:array<string,mixed>,csv:string,bytes:int,skipped:int}
         */
        public static function parse(string $content, ?DateTimeImmutable $now = null): array
        {
            $now ??= new DateTimeImmutable('now', new DateTimeZone('UTC'));
            $errors = [];
            $warnings = [];
            $warningsTotal = 0;

            $addWarning = static function (string $message) use (&$warnings, &$warningsTotal): void {
                $warningsTotal++;
                if (count($warnings) < self::MAX_WARNINGS) {
                    $warnings[] = $message;
                }
            };

            $bytes = strlen($content);
            if (str_starts_with($content, "\xEF\xBB\xBF")) {
                $content = substr($content, 3);
            }

            $csv = trim($content);

            if ($csv === '') {
                return self::failure(['El fichero CSV está vacío.'], $bytes);
            }
            if (str_contains($content, "\0")) {
                return self::failure(['El fichero no parece un CSV de texto (contiene bytes nulos).'], $bytes);
            }
            if (strlen($content) > self::MAX_BYTES) {
                return self::failure([
                    'El CSV supera el límite de ' . self::formatBytes(self::MAX_BYTES) . '.',
                ], $bytes);
            }
            if (strlen($csv) > self::MAX_PROMPT_BYTES) {
                return self::failure([
                    'El CSV ocupa ' . self::formatBytes(strlen($csv)) . ' y el máximo para enviarlo a la IA es '
                    . self::formatBytes(self::MAX_PROMPT_BYTES) . '. Divide el export por grupos de servidores.',
                ], $bytes);
            }
            if (function_exists('mb_check_encoding') && !mb_check_encoding($content, 'UTF-8')) {
                return self::failure(['El CSV no está codificado en UTF-8.'], $bytes);
            }

            $fh = fopen('php://temp', 'r+');
            if ($fh === false) {
                return self::failure(['No se pudo leer el CSV en el servidor.'], $bytes);
            }
            fwrite($fh, $csv);
            rewind($fh);

            $header = fgetcsv($fh, 0, ',', '"', '');
            if (!is_array($header) || $header === [null]) {
                fclose($fh);
                return self::failure(['No se pudo leer la cabecera del CSV.'], $bytes);
            }
            $header = array_map(static fn($h): string => trim((string)$h), $header);

            if (count($header) !== count(self::COLUMNS)) {
                fclose($fh);
                return self::failure([
                    'El CSV debe tener ' . count(self::COLUMNS) . ' columnas y tiene ' . count($header) . '. '
                    . '¿Es el export de Advanced Hunting de la consulta de la especificación?',
                ], $bytes);
            }

            $mismatched = [];
            foreach (self::COLUMNS as $index => $expected) {
                $actual = (string)($header[$index] ?? '');
                if (strcasecmp($actual, $expected) !== 0) {
                    $mismatched[] = 'columna ' . ($index + 1) . ': se esperaba «' . $expected . '» y llegó «' . $actual . '»';
                }
            }
            if ($mismatched !== []) {
                fclose($fh);
                return self::failure(array_merge(
                    ['La cabecera del CSV no coincide con el contrato de columnas:'],
                    $mismatched
                ), $bytes);
            }

            $rows = [];
            $skipped = 0;
            $line = 1;

            while (($data = fgetcsv($fh, 0, ',', '"', '')) !== false) {
                $line++;
                if ($data === [null] || $data === ['']) {
                    continue; // línea en blanco
                }
                if (count($data) !== count(self::COLUMNS)) {
                    $skipped++;
                    $addWarning('Línea ' . $line . ': descartada, tiene ' . count($data) . ' columnas en vez de ' . count(self::COLUMNS) . '.');
                    continue;
                }

                $rows[] = self::normalizeRow($data, $line, $now, $addWarning);
            }
            fclose($fh);

            if ($rows === []) {
                return self::failure(['No se ha encontrado ninguna fila de servidor en el CSV.'], $bytes);
            }
            if (count($rows) > self::MAX_ROWS) {
                return self::failure([
                    'El CSV tiene ' . count($rows) . ' servidores y el máximo por informe es ' . self::MAX_ROWS . '. '
                    . 'Divide el export y genera un informe por grupo.',
                ], $bytes);
            }

            return [
                'ok'             => true,
                'errors'         => [],
                'warnings'       => $warnings,
                'warnings_total' => $warningsTotal,
                'rows'           => $rows,
                'stats'          => self::stats($rows),
                'csv'            => $csv,
                'bytes'          => $bytes,
                'skipped'        => $skipped,
            ];
        }

        /**
         * Ordena para la vista: exploit público → exposición → antigüedad.
         *
         * @param array<int,array<string,mixed>> $rows
         * @return array<int,array<string,mixed>>
         */
        public static function sortRows(array $rows): array
        {
            usort($rows, static function (array $a, array $b): int {
                return ($b['exploits'] <=> $a['exploits'])
                    ?: (($a['exposure'] === 'High' ? 0 : 1) <=> ($b['exposure'] === 'High' ? 0 : 1))
                    ?: ($b['days'] <=> $a['days'])
                    ?: ($b['critical'] <=> $a['critical'])
                    ?: ($b['cves'] <=> $a['cves']);
            });
            return $rows;
        }

        /**
         * KQL lista para incrustar dentro de una cadena JSON (sin las comillas
         * exteriores): los saltos de línea y las comillas dobles se escapan
         * para que el JSON de especificación siga siendo válido.
         */
        public static function kqlJson(): string
        {
            $encoded = json_encode(self::KQL, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (is_string($encoded) && strlen($encoded) >= 2) {
                return substr($encoded, 1, -1);
            }
            return str_replace(
                ['\\', '"', "\r", "\n", "\t"],
                ['\\\\', '\\"', '', '\\n', '\\t'],
                self::KQL
            );
        }

        /** Quita el sufijo «(Last updated at …)» de un paquete mensual. */
        public static function cleanPackage(string $name): string
        {
            $clean = preg_replace('/\s*\(Last updated at[^)]*\)\s*$/i', '', $name) ?? $name;
            return trim($clean);
        }

        public static function formatBytes(int $bytes): string
        {
            if ($bytes >= 1048576) {
                return rtrim(rtrim(number_format($bytes / 1048576, 1, ',', '.'), '0'), ',') . ' MB';
            }
            if ($bytes >= 1024) {
                return (int)round($bytes / 1024) . ' KB';
            }
            return max(0, $bytes) . ' B';
        }

        /* =================================================================
         * Interno
         * ============================================================== */

        /**
         * @param array<int,mixed> $data
         * @param callable(string):void $addWarning
         * @return array<string,mixed>
         */
        private static function normalizeRow(array $data, int $line, DateTimeImmutable $now, callable $addWarning): array
        {
            $cell = static fn(int $i): string => trim((string)($data[$i] ?? ''));

            $packages = self::parseJsonList($cell(5));
            if ($packages === null) {
                $addWarning('Línea ' . $line . ': PaquetesPendientes no es un array JSON válido; se ignora ese campo.');
                $packages = [];
            }
            $exploitCves = self::parseJsonList($cell(9));
            if ($exploitCves === null) {
                $addWarning('Línea ' . $line . ': CVEsConExploit no es un array JSON válido; se ignora ese campo.');
                $exploitCves = [];
            }

            foreach (['KBsPendientes' => 4, 'CVEs' => 6, 'Criticos' => 7, 'ExploitsPublicos' => 8, 'DiasSinParchear' => 12] as $name => $index) {
                $value = $cell($index);
                if ($value !== '' && preg_match('/^-?\d+$/', $value) !== 1) {
                    $addWarning('Línea ' . $line . ': ' . $name . ' no es un número («' . self::clip($value, 40) . '»).');
                }
            }

            $rawSince = $cell(10);
            $since = self::parseDate($rawSince);
            if ($rawSince !== '' && $since === null) {
                $addWarning('Línea ' . $line . ': SinParchearDesde no se pudo interpretar («' . self::clip($rawSince, 40) . '»).');
            }

            $row = [
                'line'           => $line,
                'device'         => $cell(0),
                'exposure'       => $cell(1),
                'os'             => $cell(2),
                'ip'             => $cell(3),
                'kbs'            => self::toInt($cell(4)),
                'packages'       => self::dedupePackages($packages),
                'cves'           => self::toInt($cell(6)),
                'critical'       => self::toInt($cell(7)),
                'exploits'       => self::toInt($cell(8)),
                'exploit_cves'   => $exploitCves,
                'since_raw'      => $rawSince,
                'since'          => $since,
                'oldest_package' => self::cleanPackage($cell(11)),
                'days'           => self::toInt($cell(12)),
                'has_exploit'    => self::toBool($cell(13)),
            ];

            if ($row['device'] === '') {
                $addWarning('Línea ' . $line . ': la fila no tiene DeviceName.');
            }
            if (!in_array($row['exposure'], self::EXPOSURE_LEVELS, true)) {
                $addWarning('Línea ' . $line . ': ExposureLevel es «' . self::clip($row['exposure'], 20) . '» (se esperaban High o Medium).');
            }

            // Coherencias de la §7 de la especificación: se avisa, no se bloquea.
            if (($row['exploits'] > 0) !== ($row['exploit_cves'] !== [])) {
                $addWarning('Línea ' . $line . ': CVEsConExploit no cuadra con ExploitsPublicos (' . $row['exploits'] . ').');
            }
            if ($row['has_exploit'] !== ($row['exploits'] > 0)) {
                $addWarning('Línea ' . $line . ': TieneExploit no cuadra con ExploitsPublicos (' . $row['exploits'] . ').');
            }
            if ($since !== null) {
                $computed = (int)floor(($now->getTimestamp() - (int)strtotime($since . ' UTC')) / 86400);
                if (abs($computed - $row['days']) > 1) {
                    $addWarning('Línea ' . $line . ': DiasSinParchear (' . $row['days'] . ') no cuadra con SinParchearDesde (' . $computed . ' días).');
                }
            }

            return $row;
        }

        /**
         * @param array<int,array<string,mixed>> $rows
         * @return array<string,mixed>
         */
        private static function stats(array $rows): array
        {
            $high = 0;
            $withExploit = 0;
            $criticalTotal = 0;
            $cvesTotal = 0;
            $kbsTotal = 0;
            $maxDays = 0;
            $oldest = null;
            $oldestPackage = '';
            $packages = [];

            foreach ($rows as $row) {
                if ($row['exposure'] === 'High') {
                    $high++;
                }
                if ($row['has_exploit'] || $row['exploits'] > 0) {
                    $withExploit++;
                }
                $criticalTotal += (int)$row['critical'];
                $cvesTotal += (int)$row['cves'];
                $kbsTotal += (int)$row['kbs'];
                $maxDays = max($maxDays, (int)$row['days']);
                if (is_string($row['since']) && ($oldest === null || $row['since'] < $oldest)) {
                    $oldest = $row['since'];
                    $oldestPackage = (string)$row['oldest_package'];
                }
                foreach ((array)$row['packages'] as $package) {
                    $packages[strtolower((string)$package)] = (string)$package;
                }
            }

            ksort($packages);

            return [
                'servers'        => count($rows),
                'high'           => $high,
                'medium'         => count($rows) - $high,
                'with_exploit'   => $withExploit,
                'critical_total' => $criticalTotal,
                'cves_total'     => $cvesTotal,
                'kbs_total'      => $kbsTotal,
                'max_days'       => $maxDays,
                'oldest'         => $oldest,
                'oldest_label'   => $oldest !== null
                    ? (new DateTimeImmutable($oldest, new DateTimeZone('UTC')))->format('d/m/Y')
                    : '',
                'oldest_package' => $oldestPackage,
                'packages'       => array_values($packages),
            ];
        }

        /**
         * @param array<int,string> $items
         * @return array<int,string>
         */
        private static function dedupePackages(array $items): array
        {
            $out = [];
            foreach ($items as $item) {
                $clean = self::cleanPackage((string)$item);
                if ($clean === '') {
                    continue;
                }
                $key = strtolower($clean);
                if (!isset($out[$key])) {
                    $out[$key] = $clean;
                }
            }
            return array_values($out);
        }

        /**
         * @return array<int,string>|null Null si el campo no es un array válido.
         */
        private static function parseJsonList(string $raw): ?array
        {
            $raw = trim($raw);
            if ($raw === '') {
                return [];
            }
            $first = $raw[0] ?? '';
            if ($first !== '[') {
                return [$raw];
            }
            $decoded = json_decode($raw, true);
            if (!is_array($decoded)) {
                return null;
            }
            $out = [];
            foreach ($decoded as $value) {
                if (is_scalar($value)) {
                    $text = trim((string)$value);
                    if ($text !== '') {
                        $out[] = $text;
                    }
                }
            }
            return $out;
        }

        private static function parseDate(string $value): ?string
        {
            $value = trim($value);
            if ($value === '') {
                return null;
            }
            $tz = new DateTimeZone('UTC');
            $formats = [
                'M j, Y g:i:s A',
                'M j, Y, g:i:s A',
                'F j, Y g:i:s A',
                'M j, Y g:i A',
                'Y-m-d H:i:s',
                'Y-m-d\TH:i:s',
                'Y-m-d',
            ];
            foreach ($formats as $format) {
                $dt = DateTimeImmutable::createFromFormat($format, $value, $tz);
                if (!$dt instanceof DateTimeImmutable) {
                    continue;
                }
                $errors = DateTimeImmutable::getLastErrors();
                if (is_array($errors) && ($errors['warning_count'] > 0 || $errors['error_count'] > 0)) {
                    continue;
                }
                return $dt->format('Y-m-d H:i:s');
            }
            $ts = strtotime($value);
            return $ts !== false ? gmdate('Y-m-d H:i:s', $ts) : null;
        }

        private static function toInt(string $value): int
        {
            $value = trim($value);
            return preg_match('/^-?\d+$/', $value) === 1 ? (int)$value : 0;
        }

        private static function toBool(string $value): bool
        {
            return in_array(strtolower(trim($value)), ['1', 'true', 'yes', 'si', 'sí'], true);
        }

        private static function clip(string $value, int $length): string
        {
            $value = trim(preg_replace('/\s+/u', ' ', $value) ?? $value);
            if (function_exists('mb_substr')) {
                return mb_substr($value, 0, $length);
            }
            return substr($value, 0, $length);
        }

        /**
         * @param array<int,string> $errors
         * @return array{ok:bool,errors:string[],warnings:string[],warnings_total:int,rows:array,stats:array,csv:string,bytes:int,skipped:int}
         */
        private static function failure(array $errors, int $bytes): array
        {
            return [
                'ok'             => false,
                'errors'         => $errors,
                'warnings'       => [],
                'warnings_total' => 0,
                'rows'           => [],
                'stats'          => [
                    'servers'        => 0,
                    'high'           => 0,
                    'medium'         => 0,
                    'with_exploit'   => 0,
                    'critical_total' => 0,
                    'cves_total'     => 0,
                    'kbs_total'      => 0,
                    'max_days'       => 0,
                    'oldest'         => null,
                    'oldest_label'   => '',
                    'oldest_package' => '',
                    'packages'       => [],
                ],
                'csv'            => '',
                'bytes'          => $bytes,
                'skipped'        => 0,
            ];
        }
    }
}
