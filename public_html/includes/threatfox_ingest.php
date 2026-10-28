<?php
/**
 * ThreatfoxIngest — Ingesta de IOCs: API de ThreatFox → SQLite local.
 *
 * Dos modos:
 *  1. Diaria: get_iocs (1-7 días) + upsert idempotente. Es la única llamada
 *     recurrente a la API (fair use de abuse.ch).
 *  2. Backfill completo: get_iocs solo cubre 7 días, así que para poblar los
 *     ~6 meses que publica la fuente se descarga el export oficial
 *     (full.csv.zip) y se importa por bloques, guardando el progreso para
 *     reanudar sin duplicar si el hosting corta la petición.
 */

declare(strict_types=1);

final class ThreatfoxIngest
{
    /** Filas importadas por petición en el backfill web. */
    public const CHUNK = THREATFOX_BACKFILL_CHUNK;

    /** Ruta del estado del backfill (junto a la base). */
    public static function statePath(): string
    {
        return dirname((string)THREATFOX_DB_PATH) . '/threatfox-backfill.json';
    }

    /** Ruta del CSV del export mientras dura el backfill (junto a la base). */
    private static function csvPath(): string
    {
        return dirname((string)THREATFOX_DB_PATH) . '/threatfox-export.csv';
    }

    /** Estado del backfill en curso, o null si no hay ninguno. */
    public static function state(): ?array
    {
        $path = self::statePath();
        if (!is_file($path)) {
            return null;
        }
        $state = safe_json_decode((string)@file_get_contents($path), null);
        return is_array($state) ? $state : null;
    }

    /**
     * Ingesta diaria.
     *
     * @return array{received:int,written:int,total:int,days:int}
     * @throws RuntimeException si la API no responde "ok"
     */
    public static function run(int $days = THREATFOX_DEFAULT_DAYS): array
    {
        $days = max(1, min(THREATFOX_DAYS_MAX, $days));
        $key = ThreatfoxApi::resolveAuthKey();
        if ($key === '') {
            throw new RuntimeException('No hay Auth-Key de abuse.ch configurada.');
        }

        $api = new ThreatfoxApi($key);
        $res = $api->getIocs($days);
        $status = (string)($res['query_status'] ?? 'unknown');
        if ($status !== ThreatfoxApi::STATUS_OK) {
            $detail = (string)($res['error'] ?? '');
            throw new RuntimeException(
                "La API respondió '$status'" . ($detail !== '' ? ': ' . $detail : '.')
            );
        }

        $rows = is_array($res['data'] ?? null) ? $res['data'] : [];
        $store = new ThreatfoxStore();
        $written = $store->upsert($rows);
        $total = $store->count();
        $store->logIngest('daily', $written, $total);

        return ['received' => count($rows), 'written' => $written, 'total' => $total, 'days' => $days];
    }

    /* =====================================================================
     * Backfill por pasos
     * ================================================================== */

    /**
     * Paso 1: descarga el export completo, lo descomprime y deja el CSV junto
     * a la base, con el estado inicial (filas totales para el progreso).
     *
     * @return array{rows_total:int,rows_done:int,started_at:string}
     */
    public static function backfillStart(): array
    {
        if (!class_exists('ZipArchive')) {
            throw new RuntimeException('Falta la extensión PHP "zip" (necesaria para descomprimir el export).');
        }

        $key = ThreatfoxApi::resolveAuthKey();
        if ($key === '') {
            throw new RuntimeException('No hay Auth-Key de abuse.ch configurada.');
        }

        $api = new ThreatfoxApi($key);
        $zipPath = tempnam(sys_get_temp_dir(), 'tfexport_') . '.zip';
        if (!$api->downloadFullExport($zipPath)) {
            @unlink($zipPath);
            throw new RuntimeException('No se pudo descargar el export completo de ThreatFox.');
        }

        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            @unlink($zipPath);
            throw new RuntimeException('El export descargado no es un ZIP válido.');
        }

        $csvName = '';
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = (string)$zip->getNameIndex($i);
            if (str_ends_with(strtolower($name), '.csv')) {
                $csvName = $name;
                break;
            }
        }
        if ($csvName === '') {
            $zip->close();
            @unlink($zipPath);
            throw new RuntimeException('El export no contiene ningún CSV.');
        }

        $tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'tfexport_' . uniqid('', true);
        if (!@mkdir($tmpDir, 0700, true) || $zip->extractTo($tmpDir, [$csvName]) !== true) {
            $zip->close();
            @unlink($zipPath);
            throw new RuntimeException('No se pudo extraer el CSV del export.');
        }
        $zip->close();
        @unlink($zipPath);

        $csvPath = self::csvPath();
        $source = $tmpDir . DIRECTORY_SEPARATOR . basename($csvName);
        if (!@rename($source, $csvPath) && !@copy($source, $csvPath)) {
            @unlink($source);
            throw new RuntimeException('No se pudo mover el CSV del export al directorio de datos.');
        }
        @unlink($source);
        @rmdir($tmpDir);

        /* Contar filas de datos (para el progreso de la interfaz). */
        $rowsTotal = 0;
        $handle = fopen($csvPath, 'r');
        if ($handle !== false) {
            while (($line = fgets($handle)) !== false) {
                $trimmed = ltrim($line);
                if ($trimmed === '' || $trimmed[0] === '#') {
                    continue;
                }
                $rowsTotal++;
            }
            fclose($handle);
        }

        $state = [
            'rows_total' => max(0, $rowsTotal - 1),
            'rows_done'  => 0,
            'started_at' => gmdate('c'),
        ];
        @file_put_contents(self::statePath(), json_encode($state));

        return $state;
    }

    /**
     * Cabecera + mapeo de columnas del CSV del export. Devuelve el puntero y
     * deja el índice de columnas en $colIdx.
     *
     * @param array<string,int> $colIdx
     * @return resource
     */
    private static function openExportCsv(string $csvPath, array &$colIdx)
    {
        $map = [
            'id'                => ['ioc_id', 'id'],
            'ioc'               => ['ioc_value', 'ioc'],
            'ioc_type'          => ['ioc_type'],
            'threat_type'       => ['threat_type'],
            'malware'           => ['fk_malware', 'malware'],
            'malware_printable' => ['malware_printable'],
            'malware_alias'     => ['malware_alias'],
            'confidence_level'  => ['confidence_level'],
            'first_seen'        => ['first_seen_utc', 'first_seen'],
            'last_seen'         => ['last_seen_utc', 'last_seen'],
            'reference'         => ['reference'],
            'reporter'          => ['reporter'],
            'tags'              => ['tags'],
        ];

        $handle = fopen($csvPath, 'r');
        if ($handle === false) {
            throw new RuntimeException('No se pudo abrir el CSV del export.');
        }

        $header = false;
        while (($line = fgets($handle)) !== false) {
            $line = rtrim($line, "\r\n");
            if (trim($line) === '') {
                continue;
            }
            if (str_starts_with(ltrim($line), '#')) {
                /* Cabecera comentada: '# "first_seen_utc","ioc_id",...' */
                if (str_contains($line, 'ioc_id')) {
                    $header = str_getcsv(ltrim(ltrim($line), '# '), ',', '"', '\\');
                    break;
                }
                continue;
            }
            $header = str_getcsv($line, ',', '"', '\\');
            break;
        }

        if (!is_array($header) || $header === []) {
            fclose($handle);
            throw new RuntimeException('El CSV del export está vacío o no tiene cabecera.');
        }

        $header = array_map(static fn($h) => strtolower(trim((string)$h, " \t\"")), $header);
        $colIdx = [];
        foreach ($map as $field => $candidates) {
            foreach ($candidates as $candidate) {
                $index = array_search($candidate, $header, true);
                if ($index !== false) {
                    $colIdx[$field] = (int)$index;
                    break;
                }
            }
        }

        if (!isset($colIdx['id'], $colIdx['ioc'])) {
            fclose($handle);
            throw new RuntimeException('El CSV del export no tiene las columnas esperadas.');
        }

        return $handle;
    }

    /**
     * Convierte una fila del CSV del export al formato de fila del almacén.
     *
     * @param array<string,int> $colIdx
     */
    private static function exportRowToIoc(array $row, array $colIdx): array
    {
        $get = static fn(string $field): string
            => isset($colIdx[$field]) ? trim((string)($row[$colIdx[$field]] ?? '')) : '';

        $firstSeen = $get('first_seen');
        if ($firstSeen !== '' && !str_contains($firstSeen, 'UTC')) {
            $firstSeen .= ' UTC';
        }

        return [
            'id'                => $get('id'),
            'ioc'               => $get('ioc'),
            'ioc_type'          => $get('ioc_type'),
            'threat_type'       => $get('threat_type'),
            'malware'           => $get('malware'),
            'malware_printable' => $get('malware_printable'),
            'malware_alias'     => $get('malware_alias'),
            'confidence_level'  => (int)$get('confidence_level'),
            'first_seen'        => $firstSeen,
            'last_seen'         => $get('last_seen'),
            'reference'         => $get('reference'),
            'reporter'          => $get('reporter'),
            'tags'              => array_values(array_filter(array_map('trim', explode(',', $get('tags'))))),
        ];
    }

    /**
     * Paso 2: importa el siguiente bloque del CSV.
     *
     * @return array{done:bool,rows_done:int,rows_total:int}
     */
    public static function backfillChunk(): array
    {
        $state = self::state();
        if ($state === null) {
            throw new RuntimeException('No hay ninguna descarga completa en curso.');
        }

        $csvPath = self::csvPath();
        if (!is_file($csvPath)) {
            @unlink(self::statePath());
            throw new RuntimeException('Falta el CSV del export: reinicia la descarga completa.');
        }

        $colIdx = [];
        $handle = self::openExportCsv($csvPath, $colIdx);

        /* Saltar las filas ya importadas. */
        $skip = (int)($state['rows_done'] ?? 0);
        while ($skip > 0 && ($line = fgets($handle)) !== false) {
            $trimmed = ltrim($line);
            if ($trimmed === '' || $trimmed[0] === '#') {
                continue;
            }
            $skip--;
        }

        $store = new ThreatfoxStore();
        $batch = [];
        $imported = 0;
        while ($imported < self::CHUNK && ($row = fgetcsv($handle, 0, ',', '"', '\\')) !== false) {
            if (count($row) === 1 && trim((string)$row[0]) === '') {
                continue;
            }
            if (str_starts_with(ltrim((string)$row[0]), '#')) {
                continue;
            }
            $batch[] = self::exportRowToIoc($row, $colIdx);
            $imported++;
        }

        $eof = feof($handle);
        fclose($handle);

        if ($batch !== []) {
            $store->upsert($batch);
        }

        $state['rows_done'] = (int)($state['rows_done'] ?? 0) + $imported;
        $done = $eof || $imported === 0;

        if ($done) {
            /* El registro "full" solo se escribe al llegar al final: es la
               prueba definitiva de que el backfill terminó. */
            $store->logIngest('full', (int)$state['rows_done'], $store->count());
            @unlink($csvPath);
            @unlink(self::statePath());
        } else {
            @file_put_contents(self::statePath(), json_encode($state));
        }

        return [
            'done'       => $done,
            'rows_done'  => (int)$state['rows_done'],
            'rows_total' => (int)($state['rows_total'] ?? 0),
        ];
    }

    /**
     * Backfill completo de una tirada (CLI/cron).
     *
     * @return array{rows:int,total:int}
     */
    public static function backfill(): array
    {
        if (self::state() === null) {
            self::backfillStart();
        }
        $last = ['done' => false, 'rows_done' => 0, 'rows_total' => 0];
        do {
            $last = self::backfillChunk();
        } while (!$last['done']);

        $store = new ThreatfoxStore();
        return ['rows' => (int)$last['rows_done'], 'total' => $store->count()];
    }
}
