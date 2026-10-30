<?php
/**
 * CveTvmImport — lectura y normalización del CSV exportado por Microsoft
 * Defender (TVM → Vulnerabilidades → Exportar).
 *
 * El fichero tiene dos líneas de cabecera:
 *   1) "Vulnerabilities Export,<fecha>"
 *   2) "Name,Severity,CVSS v3,Epss score,..."
 *
 * Esta clase es puramente funcional (sin base de datos) para poder probarla
 * en los smoke tests. La persistencia vive en Module_Cve::importTvmCsv().
 */

declare(strict_types=1);

final class CveTvmImport
{
    public const MAX_BYTES = 5 * 1024 * 1024;
    public const MAX_ROWS  = 5000;

    /**
     * Lee el CSV completo y devuelve las filas normalizadas.
     *
     * @return array{
     *   export_date: string,
     *   rows: array<int, array<string, mixed>>,
     *   skipped: int,
     *   total: int
     * }
     */
    public static function parseCsv(string $csv, int $maxRows = self::MAX_ROWS): array
    {
        $result = ['export_date' => '', 'rows' => [], 'skipped' => 0, 'total' => 0];
        $csv = self::normalizeEncoding($csv);
        if (trim($csv) === '') {
            return $result;
        }

        $stream = fopen('php://temp', 'r+');
        if ($stream === false) {
            return $result;
        }
        fwrite($stream, $csv);
        rewind($stream);

        $header = null;
        $indexes = [];
        $seen = [];
        $lineNo = 0;

        while (($cells = fgetcsv($stream, 0, ',', '"', '\\')) !== false) {
            $lineNo++;
            if (!is_array($cells) || $cells === [null]) {
                continue;
            }
            $cells = array_map(
                static fn($value): string => is_string($value) ? trim($value) : '',
                $cells
            );

            // Línea 1: metadatos del export ("Vulnerabilities Export,<fecha>").
            if ($header === null) {
                if (strcasecmp($cells[0] ?? '', 'Vulnerabilities Export') === 0) {
                    $result['export_date'] = self::normalizeDate($cells[1] ?? '');
                    continue;
                }
                // Localiza la cabecera real (primera celda "Name").
                if (strcasecmp($cells[0] ?? '', 'Name') !== 0) {
                    $result['skipped']++;
                    continue;
                }
                $header = self::mapHeader($cells);
                continue;
            }

            $result['total']++;
            $row = self::mapRow($cells, $header);
            if ($row === null) {
                $result['skipped']++;
                continue;
            }
            if (isset($seen[$row['cve_id']])) {
                $result['skipped']++;
                continue;
            }
            $seen[$row['cve_id']] = true;
            $result['rows'][] = $row;
            if (count($result['rows']) >= max(1, $maxRows)) {
                break;
            }
        }
        fclose($stream);

        return $result;
    }

    /**
     * Mapa de nombre de columna normalizado → índice.
     *
     * @param string[] $cells
     * @return array<string, int>
     */
    public static function mapHeader(array $cells): array
    {
        $map = [];
        foreach ($cells as $i => $cell) {
            $key = self::headerKey((string)$cell);
            if ($key !== '' && !isset($map[$key])) {
                $map[$key] = (int)$i;
            }
        }
        return $map;
    }

    /**
     * Convierte una fila del CSV en el array normalizado.
     *
     * @param string[]           $cells
     * @param array<string, int> $header
     * @return array<string, mixed>|null
     */
    public static function mapRow(array $cells, array $header): ?array
    {
        $get = static function (string $key) use ($cells, $header): string {
            $idx = $header[$key] ?? null;
            return $idx === null ? '' : (string)($cells[$idx] ?? '');
        };

        $cveId = strtoupper(trim($get('name')));
        if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId)) {
            return null;
        }

        $tvmStatus = $get('status');
        $description = $get('description');

        return [
            'cve_id'             => $cveId,
            'severity'           => self::normalizeSeverity($get('severity')),
            'cvss'               => self::numberOrNull($get('cvssv3')),
            'epss'               => self::numberOrNull($get('epssscore')),
            'age_days'           => self::intOrZero($get('agedays')),
            'published_at'       => self::normalizeDate($get('published')),
            'first_detected_at'  => self::normalizeDate($get('firstdetected')),
            'updated_at'         => self::normalizeDate($get('updated')),
            'has_exploit'        => self::boolToInt($get('hasexploit')),
            'has_known_threats'  => self::boolToInt($get('hasknownthreats')),
            'has_alerts'         => self::boolToInt($get('hasassociatedalerts')),
            'related_software'   => $get('relatedsoftware'),
            'software_pairs'     => self::splitSoftware($get('relatedsoftware')),
            'exposed_machines'   => self::intOrZero($get('exposedmachines')),
            'description'        => $description,
            'tvm_status'         => $tvmStatus,
        ];
    }

    /**
     * Separa la columna "Related Software" en pares vendor/product.
     * Admite "vendor:product;vendor:product" y también URIs CPE 2.3.
     *
     * @return array<int, array{vendor: string, product: string}>
     */
    public static function splitSoftware(string $raw): array
    {
        $raw = trim($raw);
        if ($raw === '') {
            return [];
        }

        $pairs = [];
        foreach (preg_split('/[;,]+/', $raw) ?: [] as $item) {
            $item = trim($item);
            if ($item === '') {
                continue;
            }

            if (stripos($item, 'cpe:2.3:') === 0) {
                $parts = explode(':', $item);
                $vendor = $parts[3] ?? '';
                $product = $parts[4] ?? '';
            } else {
                $parts = explode(':', $item, 2);
                $vendor = $parts[0] ?? '';
                $product = $parts[1] ?? '';
            }

            $vendor = trim((string)$vendor);
            $product = trim((string)$product);
            if ($product === '') {
                continue;
            }
            $key = self::token($vendor) . '|' . self::token($product);
            if (isset($pairs[$key])) {
                continue;
            }
            $pairs[$key] = ['vendor' => $vendor, 'product' => $product];
        }

        return array_values($pairs);
    }

    /**
     * Etiquetas legibles "vendor:product" para la interfaz.
     *
     * @param array<int, array{vendor: string, product: string}> $pairs
     * @return string[]
     */
    public static function softwareLabels(array $pairs, int $max = 8): array
    {
        $labels = [];
        foreach (array_slice($pairs, 0, max(0, $max)) as $pair) {
            $vendor = (string)($pair['vendor'] ?? '');
            $product = (string)($pair['product'] ?? '');
            $labels[] = $vendor !== '' ? $vendor . ':' . $product : $product;
        }
        return $labels;
    }

    /**
     * Busca el software del CSV dentro del inventario de un cliente.
     *
     * Cada fila del inventario debe traer: id, name, vendor, product.
     *
     * @param array<int, array{vendor: string, product: string}> $pairs
     * @param array<int, array<string, mixed>>                   $watchlist
     * @param array<int, string[]>                               $aliases  watchlist_id => alias
     * @return int[]
     */
    public static function matchWatchlist(array $pairs, array $watchlist, array $aliases = []): array
    {
        if ($pairs === [] || $watchlist === []) {
            return [];
        }

        $candidates = [];
        foreach ($watchlist as $row) {
            $id = (int)($row['id'] ?? 0);
            if ($id <= 0) {
                continue;
            }
            $tokens = [];
            $vendor = self::token((string)($row['vendor'] ?? ''));
            $product = self::token((string)($row['product'] ?? ''));
            $name = self::token((string)($row['name'] ?? ''));
            if ($product !== '') {
                $tokens[] = ['kind' => 'product', 'vendor' => $vendor, 'value' => $product];
            }
            if ($name !== '') {
                $tokens[] = ['kind' => 'product', 'vendor' => $vendor, 'value' => $name];
            }
            foreach (($aliases[$id] ?? []) as $alias) {
                $token = self::token((string)$alias);
                if ($token !== '') {
                    $tokens[] = ['kind' => 'alias', 'vendor' => $vendor, 'value' => $token];
                }
            }
            if ($tokens !== []) {
                $candidates[$id] = $tokens;
            }
        }

        $matched = [];
        foreach ($pairs as $pair) {
            $pVendor = self::token((string)($pair['vendor'] ?? ''));
            $pProduct = self::token((string)($pair['product'] ?? ''));
            if ($pProduct === '') {
                continue;
            }

            foreach ($candidates as $id => $tokens) {
                foreach ($tokens as $token) {
                    $value = (string)$token['value'];
                    $vendor = (string)$token['vendor'];
                    if ($value === '') {
                        continue;
                    }

                    $vendorOk = $vendor === '' || $pVendor === '' || $vendor === $pVendor
                        || str_contains($vendor, $pVendor) || str_contains($pVendor, $vendor);

                    $exact = ($value === $pProduct && $vendorOk)
                        || ($vendor !== '' && $pVendor !== '' && $vendor . $value === $pVendor . $pProduct);

                    $loose = strlen($value) >= 4 && strlen($pProduct) >= 4
                        && $vendorOk
                        && (str_contains($pProduct, $value) || str_contains($value, $pProduct));

                    if ($exact || $loose) {
                        $matched[$id] = true;
                        break 2;
                    }
                }
            }
        }

        return array_keys($matched);
    }

    /**
     * Token de comparación: minúsculas y solo letras/números.
     */
    public static function token(string $value): string
    {
        $value = strtolower(trim($value));
        return preg_replace('/[^a-z0-9]+/', '', $value) ?? '';
    }

    public static function normalizeSeverity(string $value): string
    {
        $value = strtolower(trim($value));
        return match (true) {
            str_starts_with($value, 'crit') => 'critical',
            str_starts_with($value, 'high') => 'high',
            str_starts_with($value, 'med')  => 'medium',
            str_starts_with($value, 'low')  => 'low',
            default                          => $value === '' ? '' : 'info',
        };
    }

    public static function normalizeDate(string $value): string
    {
        $value = trim($value);
        if ($value === '') {
            return '';
        }

        $formats = [
            'd M, Y', 'd M Y', 'd/m/Y', 'Y-m-d', 'Y-m-d\TH:i:s\Z',
            'd M, Y h:i A', 'd M, Y g:i A', 'M d, Y', 'Y/m/d',
        ];
        foreach ($formats as $format) {
            $date = DateTimeImmutable::createFromFormat('!' . $format, $value);
            if ($date instanceof DateTimeImmutable) {
                return $date->format('Y-m-d');
            }
        }

        $ts = strtotime($value);
        return $ts === false ? '' : date('Y-m-d', $ts);
    }

    public static function boolToInt(string $value): int
    {
        return in_array(strtolower(trim($value)), ['true', '1', 'yes', 'y', 'sí', 'si'], true) ? 1 : 0;
    }

    public static function numberOrNull(string $value): ?float
    {
        $value = str_replace(',', '.', trim($value));
        return is_numeric($value) ? (float)$value : null;
    }

    public static function intOrZero(string $value): int
    {
        $value = trim($value);
        return is_numeric($value) ? max(0, (int)round((float)$value)) : 0;
    }

    private static function headerKey(string $cell): string
    {
        return preg_replace('/[^a-z0-9]+/', '', strtolower(trim($cell))) ?? '';
    }

    private static function normalizeEncoding(string $csv): string
    {
        // Defender exporta en UTF-8; algunos clientes guardan UTF-16 con BOM.
        if (str_starts_with($csv, "\xFF\xFE") || str_starts_with($csv, "\xFE\xFF")) {
            $converted = @mb_convert_encoding($csv, 'UTF-8', 'UTF-16');
            if (is_string($converted) && $converted !== '') {
                $csv = $converted;
            }
        }
        return ltrim($csv, "\xEF\xBB\xBF");
    }
}
