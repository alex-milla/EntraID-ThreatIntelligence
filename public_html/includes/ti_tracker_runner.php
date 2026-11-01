<?php
/**
 * TiTrackerRunner — Resolución de las búsquedas guardadas del Seguimiento TI.
 *
 * Compartido por el módulo (ejecución manual) y el cron diario. La fuente
 * "base local" consulta storage/threatfox.sqlite sin red; la fuente "API en
 * vivo" reutiliza ThreatfoxQuery con su paginación.
 */

declare(strict_types=1);

final class TiTrackerRunner
{
    /**
     * Filas completas del conjunto filtrado (máximo TI_TRACKER_MAX_ROWS).
     *
     * @param array $filters filtros normalizados de ThreatfoxQuery
     * @return array<int,array> filas normalizadas (con tags_list)
     */
    public static function resolveRows(array $filters): array
    {
        if (($filters['source'] ?? 'db') === 'api') {
            return self::resolveFromApi($filters);
        }

        $store = new ThreatfoxStore();
        $rows = $store->queryAll(ThreatfoxQuery::storeFiltersFor($filters), TI_TRACKER_MAX_ROWS);

        return array_map([ThreatfoxQuery::class, 'normalizeRow'], $rows);
    }

    /** Paginación de la API: se recorre hasta el tope de filas. */
    private static function resolveFromApi(array $filters): array
    {
        $result = ThreatfoxQuery::run(array_merge($filters, ['limit' => 1000]), 1);
        if (($result['status'] ?? '') !== 'ok') {
            throw new RuntimeException((string)($result['message'] ?? 'La API no devolvió resultados.'));
        }

        $rows = $result['rows'];
        for ($page = 2; $page <= (int)$result['totalPages']; $page++) {
            if (count($rows) >= TI_TRACKER_MAX_ROWS) {
                break;
            }
            $next = ThreatfoxQuery::run(array_merge($filters, ['limit' => 1000]), $page);
            if (($next['status'] ?? '') !== 'ok') {
                break;
            }
            $rows = array_merge($rows, $next['rows']);
        }

        return array_slice($rows, 0, TI_TRACKER_MAX_ROWS);
    }

    /**
     * Ejecuta una búsqueda guardada, actualiza el seguimiento y devuelve el
     * resumen con los IOCs nuevos.
     *
     * @return array{rows:array,new_rows:array,result:array,source:string}
     */
    public static function execute(TiTrackerStore $store, array $search): array
    {
        $filters = self::filtersFor($search);
        $rows = self::resolveRows($filters);

        $marked = $store->markRun((int)$search['id'], $rows, (string)$filters['source']);

        /* Marca en la lista las filas que no existían antes de esta ejecución. */
        $newKeys = [];
        foreach ((array)$marked['new_iocs'] as $ioc) {
            $newKeys[(string)$ioc] = true;
        }
        $newRows = [];
        foreach ($rows as $row) {
            if (isset($newKeys[(string)($row['ioc'] ?? '')])) {
                $newRows[] = $row;
            }
        }

        return [
            'rows'     => $rows,
            'new_rows' => $newRows,
            'result'   => $marked,
            'source'   => (string)$filters['source'],
        ];
    }

    /**
     * Filtros efectivos de una búsqueda guardada. Aplica valores por defecto
     * y el tope de días según la fuente (API 7, base local 190).
     */
    public static function filtersFor(array $search): array
    {
        $filters = array_merge(ThreatfoxQuery::normalize([]), (array)($search['filters'] ?? []));
        $filters['days'] = self::clampDays(
            (string)($filters['source'] ?? 'db'),
            (int)($filters['days'] ?? 0)
        );

        return $filters;
    }

    /** Días efectivos: la API solo acepta 7; la base local, la retención. */
    public static function clampDays(string $source, int $days): int
    {
        $max = $source === 'api' ? THREATFOX_DAYS_MAX : TI_TRACKER_DAYS_DB_MAX;

        return max(0, min($max, $days));
    }
}
