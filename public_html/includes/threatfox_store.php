<?php
/**
 * ThreatfoxStore — Almacén local de IOCs de ThreatFox en SQLite.
 *
 * Base independiente (THREATFOX_DB_PATH, por defecto storage/threatfox.sqlite)
 * para no cargar la base principal de la aplicación. El esquema replica el
 * contrato de la API: una fila por IOC, `tags` aplanado como "a,b,c" y
 * `ingested_at` con la fecha de la última ingesta de esa fila.
 *
 * El upsert es idempotente por `id`: reingestar nunca duplica, solo actualiza.
 */

declare(strict_types=1);

final class ThreatfoxStore
{
    /** Columnas válidas para los desplegables de filtro. */
    private const DISTINCT_COLUMNS = ['ioc_type', 'threat_type', 'malware', 'malware_printable'];

    private PDO $pdo;
    private string $dbPath;

    public function __construct(?string $dbPath = null)
    {
        $this->dbPath = $dbPath ?? (string)THREATFOX_DB_PATH;

        $dir = dirname($this->dbPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }

        $this->pdo = new PDO('sqlite:' . $this->dbPath, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $this->pdo->exec('PRAGMA journal_mode = WAL');
        $this->pdo->exec('PRAGMA busy_timeout = 5000');

        $this->ensureSchema();
    }

    public function path(): string
    {
        return $this->dbPath;
    }

    private function ensureSchema(): void
    {
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS iocs (
            id                TEXT PRIMARY KEY,
            ioc               TEXT NOT NULL,
            ioc_type          TEXT,
            threat_type       TEXT,
            malware           TEXT,
            malware_printable TEXT,
            malware_alias     TEXT,
            confidence_level  INTEGER,
            first_seen        TEXT,
            last_seen         TEXT,
            reference         TEXT,
            reporter          TEXT,
            tags              TEXT,
            ingested_at       TEXT
        )');

        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_iocs_type   ON iocs(ioc_type)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_iocs_threat ON iocs(threat_type)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_iocs_conf   ON iocs(confidence_level)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_iocs_seen   ON iocs(first_seen)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_iocs_malware ON iocs(malware)');

        $this->pdo->exec('CREATE TABLE IF NOT EXISTS ingest_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT NOT NULL,
            rows        INTEGER NOT NULL,
            total       INTEGER NOT NULL,
            finished_at TEXT NOT NULL
        )');
    }

    /* =====================================================================
     * Ingesta
     * ================================================================== */

    /** Registra una ingesta terminada (type: daily | full). */
    public function logIngest(string $type, int $rows, int $total): void
    {
        $st = $this->pdo->prepare(
            'INSERT INTO ingest_log (type, rows, total, finished_at) VALUES (?, ?, ?, ?)'
        );
        $st->execute([$type, $rows, $total, gmdate('Y-m-d H:i:s') . ' UTC']);
    }

    /** Última ingesta registrada de cada tipo. @return array<string,array> */
    public function lastIngests(): array
    {
        $out = [];
        $st = $this->pdo->query(
            'SELECT type, rows, total, finished_at FROM ingest_log ORDER BY id DESC LIMIT 40'
        );
        foreach ($st->fetchAll() as $row) {
            if (!isset($out[$row['type']])) {
                $out[$row['type']] = $row;
            }
        }
        return $out;
    }

    /**
     * Inserta o actualiza IOCs (upsert por id de ThreatFox).
     * Las filas llegan tal cual de la API; `tags` se guarda como "a,b,c".
     *
     * @return int filas escritas
     */
    public function upsert(array $rows): int
    {
        if ($rows === []) {
            return 0;
        }

        $now = gmdate('Y-m-d H:i:s') . ' UTC';
        $sql = 'INSERT INTO iocs (id, ioc, ioc_type, threat_type, malware, malware_printable,
                    malware_alias, confidence_level, first_seen, last_seen, reference, reporter, tags, ingested_at)
                VALUES (:id, :ioc, :ioc_type, :threat_type, :malware, :malware_printable,
                    :malware_alias, :confidence_level, :first_seen, :last_seen, :reference, :reporter, :tags, :ingested_at)
                ON CONFLICT(id) DO UPDATE SET
                    ioc = excluded.ioc,
                    ioc_type = excluded.ioc_type,
                    threat_type = excluded.threat_type,
                    malware = excluded.malware,
                    malware_printable = excluded.malware_printable,
                    malware_alias = excluded.malware_alias,
                    confidence_level = excluded.confidence_level,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen,
                    reference = excluded.reference,
                    reporter = excluded.reporter,
                    tags = excluded.tags,
                    ingested_at = excluded.ingested_at';
        $st = $this->pdo->prepare($sql);

        $written = 0;
        $this->pdo->beginTransaction();
        try {
            foreach ($rows as $row) {
                if (!is_array($row) || (string)($row['ioc'] ?? '') === '') {
                    continue;
                }
                $tagList = $row['tags'] ?? [];
                if (is_string($tagList)) {
                    $tagList = array_filter(array_map('trim', explode(',', $tagList)));
                }
                $tags = implode(',', array_map('strval', (array)$tagList));

                $st->execute([
                    ':id'                => (string)($row['id'] ?? uniqid('tf_', true)),
                    ':ioc'               => (string)$row['ioc'],
                    ':ioc_type'          => (string)($row['ioc_type'] ?? ''),
                    ':threat_type'       => (string)($row['threat_type'] ?? ''),
                    ':malware'           => (string)($row['malware'] ?? ''),
                    ':malware_printable' => (string)($row['malware_printable'] ?? ''),
                    ':malware_alias'     => (string)($row['malware_alias'] ?? ''),
                    ':confidence_level'  => (int)($row['confidence_level'] ?? 0),
                    ':first_seen'        => (string)($row['first_seen'] ?? ''),
                    ':last_seen'         => (string)($row['last_seen'] ?? ''),
                    ':reference'         => (string)($row['reference'] ?? ''),
                    ':reporter'          => (string)($row['reporter'] ?? ''),
                    ':tags'              => $tags,
                    ':ingested_at'       => $now,
                ]);
                $written++;
            }
            $this->pdo->commit();
        } catch (Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }

        return $written;
    }

    /** Borra los IOCs que la fuente ya no expone (más de 6 meses). */
    public function purgeExpired(int $days = 190): int
    {
        $st = $this->pdo->prepare(
            "DELETE FROM iocs WHERE substr(first_seen, 1, 19) < datetime('now', :days_ago)"
        );
        $st->execute([':days_ago' => '-' . max(1, $days) . ' days']);
        return $st->rowCount();
    }

    /* =====================================================================
     * Consultas
     * ================================================================== */

    public function count(): int
    {
        return (int)$this->pdo->query('SELECT COUNT(*) FROM iocs')->fetchColumn();
    }

    /**
     * Construye WHERE y parámetros a partir de los filtros de la interfaz.
     * Compartida por query(), queryAll() y countFiltered().
     *
     * @return array{0:string,1:array<string,mixed>}
     */
    private function buildWhere(array $f): array
    {
        $where = [];
        $params = [];

        /* Multi-término: cada término (separado por comas) debe aparecer en el
           IOC, la familia de malware o los tags (AND entre términos). */
        foreach ((array)($f['terms'] ?? []) as $i => $term) {
            $term = trim((string)$term);
            if ($term === '') {
                continue;
            }
            $where[] = "(ioc LIKE :term{$i} OR malware LIKE :term{$i} "
                . "OR malware_printable LIKE :term{$i} OR tags LIKE :term{$i})";
            $params[":term{$i}"] = '%' . $term . '%';
        }

        if ((int)($f['days'] ?? 0) > 0) {
            $where[] = "substr(first_seen, 1, 19) >= datetime('now', :days_ago)";
            $params[':days_ago'] = '-' . (int)$f['days'] . ' days';
        }
        if (($f['malware'] ?? '') !== '') {
            $where[] = '(malware LIKE :malware OR malware_printable LIKE :malware)';
            $params[':malware'] = '%' . $f['malware'] . '%';
        }
        if (($f['ioc_type'] ?? '') !== '') {
            $where[] = 'ioc_type = :ioc_type';
            $params[':ioc_type'] = $f['ioc_type'];
        }
        if (($f['threat_type'] ?? '') !== '') {
            $where[] = 'threat_type = :threat_type';
            $params[':threat_type'] = $f['threat_type'];
        }
        if (($f['tag'] ?? '') !== '') {
            $where[] = "(',' || tags || ',') LIKE :tag";
            $params[':tag'] = '%,' . $f['tag'] . ',%';
        }
        if ((int)($f['conf'] ?? 0) > 0) {
            $where[] = 'confidence_level >= :conf';
            $params[':conf'] = (int)$f['conf'];
        }
        if (!empty($f['ref_only'])) {
            /* ThreatFox escribe "None"/"null" cuando no hay referencia. */
            $where[] = "reference IS NOT NULL AND reference != '' "
                . "AND lower(reference) NOT IN ('none', 'null', '-')";
        }

        return [$where ? 'WHERE ' . implode(' AND ', $where) : '', $params];
    }

    public function query(array $f, int $limit, int $offset): array
    {
        [$where, $params] = $this->buildWhere($f);
        $st = $this->pdo->prepare(
            "SELECT * FROM iocs $where ORDER BY confidence_level DESC, first_seen DESC LIMIT :lim OFFSET :off"
        );
        foreach ($params as $key => $value) {
            $st->bindValue($key, $value);
        }
        $st->bindValue(':lim', max(1, $limit), PDO::PARAM_INT);
        $st->bindValue(':off', max(0, $offset), PDO::PARAM_INT);
        $st->execute();
        return $st->fetchAll();
    }

    public function queryAll(array $f, int $max = 5000): array
    {
        [$where, $params] = $this->buildWhere($f);
        $st = $this->pdo->prepare(
            "SELECT * FROM iocs $where ORDER BY confidence_level DESC, first_seen DESC LIMIT :lim"
        );
        foreach ($params as $key => $value) {
            $st->bindValue($key, $value);
        }
        $st->bindValue(':lim', max(1, $max), PDO::PARAM_INT);
        $st->execute();
        return $st->fetchAll();
    }

    public function countFiltered(array $f): int
    {
        [$where, $params] = $this->buildWhere($f);
        $st = $this->pdo->prepare("SELECT COUNT(*) FROM iocs $where");
        $st->execute($params);
        return (int)$st->fetchColumn();
    }

    /** @return string[] valores distintos de una columna para los filtros */
    public function distinct(string $column): array
    {
        if (!in_array($column, self::DISTINCT_COLUMNS, true)) {
            $column = 'ioc_type';
        }
        $st = $this->pdo->query(
            "SELECT DISTINCT $column FROM iocs WHERE $column IS NOT NULL AND $column != '' ORDER BY $column"
        );
        return $st->fetchAll(PDO::FETCH_COLUMN);
    }

    /**
     * Datos para la tira de KPIs de la vista.
     *
     * @return array{total:int,last24h:int,malware:int,types:int,newest:string,oldest:string}
     */
    public function stats(): array
    {
        $total = $this->count();
        if ($total === 0) {
            return [
                'total' => 0, 'last24h' => 0, 'malware' => 0, 'types' => 0,
                'newest' => '', 'oldest' => '',
            ];
        }

        $last24h = (int)$this->pdo->query(
            "SELECT COUNT(*) FROM iocs WHERE substr(ingested_at, 1, 19) >= datetime('now', '-1 day')"
        )->fetchColumn();
        $malware = (int)$this->pdo->query(
            "SELECT COUNT(DISTINCT malware) FROM iocs WHERE malware IS NOT NULL AND malware != ''"
        )->fetchColumn();
        $types = (int)$this->pdo->query(
            "SELECT COUNT(DISTINCT ioc_type) FROM iocs WHERE ioc_type IS NOT NULL AND ioc_type != ''"
        )->fetchColumn();
        $range = $this->pdo->query('SELECT MIN(first_seen), MAX(first_seen) FROM iocs')->fetch(PDO::FETCH_NUM);

        return [
            'total'   => $total,
            'last24h' => $last24h,
            'malware' => $malware,
            'types'   => $types,
            'newest'  => (string)($range[1] ?? ''),
            'oldest'  => (string)($range[0] ?? ''),
        ];
    }
}
