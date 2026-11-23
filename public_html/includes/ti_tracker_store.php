<?php
/**
 * TiTrackerStore — Almacén del seguimiento de Threat Intelligence.
 *
 * Base independiente (TI_TRACKER_DB_PATH, por defecto storage/ti_tracker.sqlite)
 * que guarda:
 *
 *  · searches      búsquedas guardadas (filtros y opciones de export en JSON)
 *  · tracked_iocs  IOCs ya vistos por cada búsqueda → la BBDD de seguimiento
 *                  que permite calcular novedades entre ejecuciones
 *  · activity      historial de ejecuciones y exportaciones
 *  · last_results  snapshot de la última ejecución por búsqueda, para poder
 *                  ver los resultados sin volver a consultar la fuente
 *
 * No duplica la base de IOCs de ThreatFox: solo recuerda qué ha visto cada
 * búsqueda. Esa es la memoria que se refresca con cada ejecución/cron.
 */

declare(strict_types=1);

final class TiTrackerStore
{
    /** Formatos de exportación soportados por la herramienta. */
    public const FORMATS = [
        'stix' => 'STIX 2.1',
        'misp' => 'MISP',
        'txt'  => 'TXT',
    ];

    /** Filas del snapshot que se guardan para la vista de resultados. */
    public const SNAPSHOT_ROWS = 500;

    private PDO $pdo;

    public function __construct(?string $dbPath = null)
    {
        $path = $dbPath ?? (string)TI_TRACKER_DB_PATH;
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }

        $this->pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $this->pdo->exec('PRAGMA journal_mode = WAL');
        $this->pdo->exec('PRAGMA busy_timeout = 5000');

        $this->ensureSchema();
    }

    private function ensureSchema(): void
    {
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS searches (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            name           TEXT NOT NULL,
            notes          TEXT,
            filters        TEXT NOT NULL,
            formats        TEXT NOT NULL,
            tlp            TEXT NOT NULL DEFAULT \'amber\',
            valid_days     INTEGER NOT NULL DEFAULT 365,
            source_name    TEXT NOT NULL DEFAULT \'abuse.ch ThreatFox\',
            threat_actor   TEXT,
            extra_tags     TEXT,
            created_at     TEXT NOT NULL,
            updated_at     TEXT NOT NULL
        )');

        /* Publicación API (v0.4.29): columnas aditivas e idempotentes. */
        $searchCols = [];
        foreach ($this->pdo->query('PRAGMA table_info(searches)') as $col) {
            $searchCols[(string)$col['name']] = true;
        }
        if (!isset($searchCols['api_enabled'])) {
            $this->pdo->exec('ALTER TABLE searches ADD COLUMN api_enabled INTEGER NOT NULL DEFAULT 1');
        }
        if (!isset($searchCols['slug'])) {
            $this->pdo->exec("ALTER TABLE searches ADD COLUMN slug TEXT NOT NULL DEFAULT ''");
        }
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_searches_api ON searches(api_enabled)');

        $this->pdo->exec('CREATE TABLE IF NOT EXISTS tracked_iocs (
            search_id   INTEGER NOT NULL,
            ioc         TEXT NOT NULL,
            ioc_id      TEXT,
            first_seen  TEXT,
            found_at    TEXT NOT NULL,
            last_run_at TEXT NOT NULL,
            PRIMARY KEY (search_id, ioc)
        )');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_tracked_search ON tracked_iocs(search_id)');

        $this->pdo->exec('CREATE TABLE IF NOT EXISTS activity (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            search_id  INTEGER NOT NULL,
            kind       TEXT NOT NULL,
            rows       INTEGER NOT NULL DEFAULT 0,
            new_rows   INTEGER NOT NULL DEFAULT 0,
            detail     TEXT,
            created_at TEXT NOT NULL
        )');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_activity_search ON activity(search_id, kind)');

        /* Snapshot de la última ejecución: se sobreescribe en cada markRun().
           row_count guarda el total real (puede superar las filas mostradas). */
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS last_results (
            search_id     INTEGER PRIMARY KEY,
            run_at        TEXT NOT NULL,
            source        TEXT NOT NULL,
            row_count     INTEGER NOT NULL DEFAULT 0,
            new_count     INTEGER NOT NULL DEFAULT 0,
            tracked_count INTEGER NOT NULL DEFAULT 0,
            new_iocs      TEXT NOT NULL DEFAULT \'[]\',
            rows_json     TEXT NOT NULL DEFAULT \'[]\'
        )');
    }

    /* =====================================================================
     * Búsquedas guardadas
     * ================================================================== */

    /** @return array<int,array> Búsquedas con estadísticas de seguimiento. */
    public function listSearches(): array
    {
        $rows = $this->pdo->query(
            "SELECT s.*,
                    (SELECT COUNT(*) FROM tracked_iocs t WHERE t.search_id = s.id) AS tracked,
                    (SELECT a.new_rows FROM activity a
                      WHERE a.search_id = s.id AND a.kind = 'run'
                      ORDER BY a.id DESC LIMIT 1) AS last_new,
                    (SELECT a.rows FROM activity a
                      WHERE a.search_id = s.id AND a.kind = 'run'
                      ORDER BY a.id DESC LIMIT 1) AS last_rows,
                    (SELECT a.created_at FROM activity a
                      WHERE a.search_id = s.id AND a.kind = 'run'
                      ORDER BY a.id DESC LIMIT 1) AS last_run_at,
                    (SELECT a.created_at FROM activity a
                      WHERE a.search_id = s.id AND a.kind = 'export'
                      ORDER BY a.id DESC LIMIT 1) AS last_export_at,
                    (SELECT COUNT(*) FROM activity a
                      WHERE a.search_id = s.id AND a.kind = 'export') AS export_count
               FROM searches s
              ORDER BY s.updated_at DESC, s.id DESC"
        )->fetchAll();

        return array_map([$this, 'hydrate'], $rows);
    }

    /**
     * Búsquedas publicadas en la API, opcionalmente restringidas por el token.
     * Si $allowedIds es null no hay restricción; si es [] no se publica ninguna.
     *
     * @param array<int,int>|null $allowedIds
     * @return array<int,array>
     */
    public function listApiSearches(?array $allowedIds = null): array
    {
        $sql = 'SELECT * FROM searches WHERE api_enabled = 1';
        $args = [];
        if ($allowedIds !== null) {
            $ids = array_values(array_unique(array_filter(array_map('intval', $allowedIds), static fn(int $v): bool => $v > 0)));
            if ($ids === []) {
                return [];
            }
            $sql .= ' AND id IN (' . implode(',', array_fill(0, count($ids), '?')) . ')';
            $args = $ids;
        }
        $sql .= ' ORDER BY name COLLATE NOCASE, id';
        $st = $this->pdo->prepare($sql);
        $st->execute($args);

        return array_map([$this, 'hydrate'], $st->fetchAll());
    }

    /** ¿Está publicada en la API esta búsqueda? */
    public function isApiEnabled(int $id): bool
    {
        $st = $this->pdo->prepare('SELECT api_enabled FROM searches WHERE id = ?');
        $st->execute([$id]);

        return (int)$st->fetchColumn() === 1;
    }

    /**
     * IOCs en seguimiento de una búsqueda (para scope=tracked del feed).
     *
     * @return array<int,array>
     */
    public function trackedRows(int $searchId, ?string $since = null): array
    {
        $sql = 'SELECT ioc, ioc_id, first_seen, found_at, last_run_at
                  FROM tracked_iocs WHERE search_id = ?';
        $args = [$searchId];
        if ($since !== null && $since !== '') {
            $sql .= ' AND found_at >= ?';
            $args[] = $since;
        }
        $sql .= ' ORDER BY found_at ASC, ioc ASC';
        $st = $this->pdo->prepare($sql);
        $st->execute($args);

        return $st->fetchAll();
    }

    /** Registra una lectura externa de la API (sin novedades). */
    public function logApiPull(int $searchId, int $rows): void
    {
        $this->addActivity($searchId, 'api_pull', $rows, 0, 'api');
    }

    public function getSearch(int $id): ?array
    {
        $st = $this->pdo->prepare('SELECT * FROM searches WHERE id = ?');
        $st->execute([$id]);
        $row = $st->fetch();

        return $row === false ? null : $this->hydrate($row);
    }

    /** Decodifica filtros y formatos para la vista. */
    private function hydrate(array $row): array
    {
        $filters = safe_json_decode((string)($row['filters'] ?? ''), []);
        $row['filters'] = is_array($filters) ? $filters : [];

        $formats = array_map('trim', explode(',', (string)($row['formats'] ?? '')));
        $row['formats'] = array_values(array_filter($formats, static fn(string $f): bool => isset(self::FORMATS[$f])));
        $row['api_enabled'] = (int)($row['api_enabled'] ?? 1);
        $row['slug'] = (string)($row['slug'] ?? '');

        return $row;
    }

    /** Slug legible y estable para una búsqueda publicada en la API. */
    public static function slugify(string $name): string
    {
        $slug = strtolower(trim((string)preg_replace('/[^A-Za-z0-9]+/', '-', $name)));
        $slug = trim($slug, '-');

        return $slug !== '' ? substr($slug, 0, 80) : 'busqueda';
    }

    private function slugTaken(string $slug, ?int $exceptId): bool
    {
        $sql = 'SELECT COUNT(*) FROM searches WHERE slug = ?';
        $args = [$slug];
        if ($exceptId !== null && $exceptId > 0) {
            $sql .= ' AND id <> ?';
            $args[] = $exceptId;
        }
        $st = $this->pdo->prepare($sql);
        $st->execute($args);

        return (int)$st->fetchColumn() > 0;
    }

    /**
     * Crea o actualiza una búsqueda guardada.
     *
     * @param array{name:string,notes:string,filters:array,formats:array,
     *              tlp:string,valid_days:int,source_name:string,
     *              threat_actor:string,extra_tags:string,api_enabled?:int|bool,slug?:string} $data
     */
    public function saveSearch(array $data, ?int $id = null): int
    {
        $now = gmdate('Y-m-d H:i:s') . ' UTC';
        $formats = implode(',', array_values(array_filter(
            array_map('strval', (array)$data['formats']),
            static fn(string $f): bool => isset(self::FORMATS[$f])
        )));
        if ($formats === '') {
            $formats = 'stix';
        }

        $baseSlug = trim((string)($data['slug'] ?? '')) !== ''
            ? self::slugify((string)$data['slug'])
            : self::slugify((string)$data['name']);
        $slug = $baseSlug;
        for ($suffix = 2; $this->slugTaken($slug, $id); $suffix++) {
            $slug = $baseSlug . '-' . $suffix;
        }

        $params = [
            ':name'         => (string)$data['name'],
            ':notes'        => (string)($data['notes'] ?? ''),
            ':filters'      => json_encode((array)$data['filters'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ':formats'      => $formats,
            ':tlp'          => (string)$data['tlp'],
            ':valid_days'   => (int)$data['valid_days'],
            ':source_name'  => (string)$data['source_name'],
            ':threat_actor' => (string)($data['threat_actor'] ?? ''),
            ':extra_tags'   => (string)($data['extra_tags'] ?? ''),
            /* Por defecto publicada: las búsquedas creadas desde la UI siguen
               disponibles en la API sin que haya que tocar el formulario. */
            ':api_enabled'  => array_key_exists('api_enabled', $data)
                ? (!empty($data['api_enabled']) ? 1 : 0)
                : 1,
            ':slug'         => $slug,
            ':updated_at'   => $now,
        ];

        if ($id !== null && $this->getSearch($id) !== null) {
            $st = $this->pdo->prepare(
                'UPDATE searches
                    SET name = :name, notes = :notes, filters = :filters, formats = :formats,
                        tlp = :tlp, valid_days = :valid_days, source_name = :source_name,
                        threat_actor = :threat_actor, extra_tags = :extra_tags,
                        api_enabled = :api_enabled, slug = :slug, updated_at = :updated_at
                  WHERE id = :id'
            );
            $st->execute($params + [':id' => $id]);

            return $id;
        }

        $params[':created_at'] = $now;
        $st = $this->pdo->prepare(
            'INSERT INTO searches
                (name, notes, filters, formats, tlp, valid_days, source_name,
                 threat_actor, extra_tags, api_enabled, slug, created_at, updated_at)
             VALUES
                (:name, :notes, :filters, :formats, :tlp, :valid_days, :source_name,
                 :threat_actor, :extra_tags, :api_enabled, :slug, :created_at, :updated_at)'
        );
        $st->execute($params);

        return (int)$this->pdo->lastInsertId();
    }

    public function deleteSearch(int $id): void
    {
        $this->pdo->beginTransaction();
        try {
            foreach (['activity', 'last_results', 'tracked_iocs', 'searches'] as $table) {
                $st = $this->pdo->prepare('DELETE FROM ' . $table . ' WHERE ' . ($table === 'searches' ? 'id' : 'search_id') . ' = ?');
                $st->execute([$id]);
            }
            $this->pdo->commit();
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    public function count(): int
    {
        return (int)$this->pdo->query('SELECT COUNT(*) FROM searches')->fetchColumn();
    }

    /* =====================================================================
     * Seguimiento: IOCs vistos y novedades
     * ================================================================== */

    /**
     * Registra una ejecución: actualiza los IOCs vistos y devuelve cuántos son
     * nuevos para esa búsqueda.
     *
     * @param array<int,array> $rows filas normalizadas de ThreatfoxQuery
     * @return array{rows:int,new:int,new_iocs:array<int,string>,tracked:int}
     */
    public function markRun(int $searchId, array $rows, string $source = 'db'): array
    {
        $now = gmdate('Y-m-d H:i:s') . ' UTC';

        $existing = [];
        $st = $this->pdo->prepare('SELECT ioc FROM tracked_iocs WHERE search_id = ?');
        $st->execute([$searchId]);
        foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $ioc) {
            $existing[(string)$ioc] = true;
        }

        $insert = $this->pdo->prepare(
            'INSERT OR IGNORE INTO tracked_iocs
                (search_id, ioc, ioc_id, first_seen, found_at, last_run_at)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        $update = $this->pdo->prepare(
            'UPDATE tracked_iocs
                SET last_run_at = ?, ioc_id = COALESCE(?, ioc_id)
              WHERE search_id = ? AND ioc = ?'
        );

        $new = 0;
        $total = 0;
        $seen = [];
        $newIocs = [];

        $this->pdo->beginTransaction();
        try {
            foreach ($rows as $row) {
                $ioc = trim((string)($row['ioc'] ?? ''));
                if ($ioc === '') {
                    continue;
                }
                $total++;
                if (!isset($existing[$ioc]) && !isset($seen[$ioc])) {
                    $new++;
                    $newIocs[] = $ioc;
                }
                $seen[$ioc] = true;

                $iocId = (string)($row['id'] ?? '');
                $firstSeen = (string)($row['first_seen'] ?? '');
                $insert->execute([$searchId, $ioc, $iocId, $firstSeen, $now, $now]);
                $update->execute([$now, $iocId, $searchId, $ioc]);
            }

            $this->addActivity($searchId, 'run', $total, $new, $source);

            $result = [
                'rows'     => $total,
                'new'      => $new,
                'new_iocs' => $newIocs,
                'tracked'  => count($existing) + $new,
            ];
            $this->saveLastResult($searchId, $rows, $result, $source);

            $this->pdo->commit();
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }

        return $result;
    }

    /**
     * Snapshot de la ejecución, dentro de la transacción de markRun().
     * Se sobreescribe en cada ejecución (manual, lote, cron o sincronización).
     *
     * @param array<int,array> $rows
     * @param array{rows:int,new:int,new_iocs:array,tracked:int} $result
     */
    private function saveLastResult(int $searchId, array $rows, array $result, string $source): void
    {
        $shown = array_slice(array_values($rows), 0, self::SNAPSHOT_ROWS);
        $st = $this->pdo->prepare(
            'INSERT OR REPLACE INTO last_results
                (search_id, run_at, source, row_count, new_count, tracked_count, new_iocs, rows_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        );
        $st->execute([
            $searchId,
            gmdate('Y-m-d H:i:s') . ' UTC',
            $source,
            (int)($result['rows'] ?? 0),
            (int)($result['new'] ?? 0),
            (int)($result['tracked'] ?? 0),
            json_encode(array_values((array)($result['new_iocs'] ?? [])), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '[]',
            json_encode($shown, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '[]',
        ]);
    }

    /**
     * Resultados de la última ejecución guardada, listos para la vista (sin red).
     * La forma es la misma que devuelve TiTrackerRunner::execute().
     *
     * @return array{rows:array,result:array,source:string,run_at:string,row_count:int}|null
     */
    public function getLastResult(int $searchId): ?array
    {
        $st = $this->pdo->prepare('SELECT * FROM last_results WHERE search_id = ?');
        $st->execute([$searchId]);
        $row = $st->fetch();
        if ($row === false) {
            return null;
        }

        $rows = safe_json_decode((string)($row['rows_json'] ?? ''), []);
        $newIocs = safe_json_decode((string)($row['new_iocs'] ?? ''), []);

        return [
            'rows'      => is_array($rows) ? $rows : [],
            'result'    => [
                'rows'     => (int)($row['row_count'] ?? 0),
                'new'      => (int)($row['new_count'] ?? 0),
                'new_iocs' => is_array($newIocs) ? $newIocs : [],
                'tracked'  => (int)($row['tracked_count'] ?? 0),
            ],
            'source'    => (string)($row['source'] ?? 'db'),
            'run_at'    => (string)($row['run_at'] ?? ''),
            'row_count' => (int)($row['row_count'] ?? 0),
        ];
    }

    /** IOCs en seguimiento (opcional: solo los de una búsqueda). */
    public function trackedCount(?int $searchId = null): int
    {
        if ($searchId === null) {
            return (int)$this->pdo->query('SELECT COUNT(*) FROM tracked_iocs')->fetchColumn();
        }

        $st = $this->pdo->prepare('SELECT COUNT(*) FROM tracked_iocs WHERE search_id = ?');
        $st->execute([$searchId]);

        return (int)$st->fetchColumn();
    }

    /* =====================================================================
     * Actividad (ejecuciones y exportaciones)
     * ================================================================== */

    public function logExport(int $searchId, string $format, int $rows, string $filename): void
    {
        $this->addActivity($searchId, 'export', $rows, 0, $format . '|' . $filename);
    }

    private function addActivity(int $searchId, string $kind, int $rows, int $newRows, string $detail = ''): void
    {
        $st = $this->pdo->prepare(
            'INSERT INTO activity (search_id, kind, rows, new_rows, detail, created_at)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        $st->execute([$searchId, $kind, $rows, $newRows, $detail, gmdate('Y-m-d H:i:s') . ' UTC']);
    }

    /** @return array<int,array> Últimas actividades de una búsqueda. */
    public function history(int $searchId, int $limit = 15): array
    {
        $st = $this->pdo->prepare(
            'SELECT * FROM activity WHERE search_id = ? ORDER BY id DESC LIMIT ' . max(1, $limit)
        );
        $st->execute([$searchId]);

        return $st->fetchAll();
    }

    /** Totales para la cabecera del panel. */
    public function totals(): array
    {
        return [
            'searches'   => $this->count(),
            'tracked'    => $this->trackedCount(),
            'exports'    => (int)$this->pdo->query("SELECT COUNT(*) FROM activity WHERE kind = 'export'")->fetchColumn(),
            'new_last'   => (int)$this->pdo->query(
                "SELECT COALESCE(SUM(new_rows), 0) FROM activity
                  WHERE kind = 'run' AND id IN (SELECT MAX(id) FROM activity WHERE kind = 'run' GROUP BY search_id)"
            )->fetchColumn(),
        ];
    }

    /** Elimina el seguimiento de IOCs antiguos (opcional, mantenimiento). */
    public function purgeTracked(int $days = 365): int
    {
        $st = $this->pdo->prepare(
            "DELETE FROM tracked_iocs WHERE substr(last_run_at, 1, 19) < datetime('now', :days_ago)"
        );
        $st->execute([':days_ago' => '-' . max(1, $days) . ' days']);

        return $st->rowCount();
    }
}
