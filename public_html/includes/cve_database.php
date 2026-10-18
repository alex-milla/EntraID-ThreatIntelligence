<?php
/**
 * CveDatabase — conexión SQLite independiente para el catálogo público de CVEs
 * y el inventario de software. Se mantiene separada de database.sqlite para
 * que el catálogo (potencialmente grande) no penalice al resto de la app.
 */

declare(strict_types=1);

class CveDatabase
{
    private static ?PDO $instance = null;

    public static function getInstance(): PDO
    {
        if (self::$instance === null) {
            $path = defined('CVE_DB_PATH') ? CVE_DB_PATH : (STORAGE_PATH . '/cve.sqlite');
            $dir = dirname($path);
            if (!is_dir($dir)) {
                mkdir($dir, 0750, true);
            }

            self::$instance = new PDO('sqlite:' . $path, null, null, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);

            self::$instance->exec('PRAGMA journal_mode = WAL');
            self::$instance->exec('PRAGMA synchronous = NORMAL');
            self::$instance->exec('PRAGMA foreign_keys = ON');
            self::$instance->exec('PRAGMA busy_timeout = 5000');

            self::createSchema(self::$instance);
            self::migrateSchema(self::$instance);
        }
        return self::$instance;
    }

    private static function createSchema(PDO $db): void
    {
        // Catálogo NVD. WITHOUT ROWID ahorra espacio con PK de texto.
        $db->exec("CREATE TABLE IF NOT EXISTS cve_catalog (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            description_lang TEXT,
            published_at TEXT,
            last_modified_at TEXT,
            vuln_status TEXT,
            source_identifier TEXT,
            severity TEXT,
            cvss_v3_score REAL,
            cvss_v3_vector TEXT,
            cvss_v2_score REAL,
            cwe_ids TEXT,
            references_json TEXT,
            products_json TEXT,
            nvd_url TEXT,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        ) WITHOUT ROWID");

        $db->exec("CREATE TABLE IF NOT EXISTS cve_product (
            cve_id TEXT NOT NULL,
            vendor TEXT NOT NULL DEFAULT '',
            product TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (cve_id, vendor, product)
        ) WITHOUT ROWID");

        $db->exec("CREATE TABLE IF NOT EXISTS cve_kev (
            cve_id TEXT PRIMARY KEY,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added TEXT,
            short_description TEXT,
            required_action TEXT,
            due_date TEXT,
            known_ransomware TEXT,
            notes TEXT,
            cwes TEXT,
            forensic_triage TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        ) WITHOUT ROWID");

        $db->exec("CREATE TABLE IF NOT EXISTS cve_epss (
            cve_id TEXT PRIMARY KEY,
            epss REAL,
            percentile REAL,
            score_date TEXT
        ) WITHOUT ROWID");

        $db->exec("CREATE TABLE IF NOT EXISTS software_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            parent_id INTEGER REFERENCES software_groups(id) ON DELETE SET NULL,
            position INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS software_watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER REFERENCES software_groups(id) ON DELETE SET NULL,
            name TEXT NOT NULL,
            vendor TEXT,
            product TEXT,
            version TEXT NOT NULL DEFAULT '',
            environment TEXT NOT NULL DEFAULT '',
            criticality TEXT,
            asset_count INTEGER,
            notes TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(name, version, environment)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS software_cpe (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            watchlist_id INTEGER NOT NULL REFERENCES software_watchlist(id) ON DELETE CASCADE,
            cpe_name TEXT NOT NULL,
            is_primary INTEGER NOT NULL DEFAULT 1,
            notes TEXT,
            UNIQUE(watchlist_id, cpe_name)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS software_alias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            watchlist_id INTEGER NOT NULL REFERENCES software_watchlist(id) ON DELETE CASCADE,
            alias TEXT NOT NULL,
            UNIQUE(watchlist_id, alias)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS cve_watchlist_match (
            watchlist_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            matched_cpe TEXT,
            matched_by TEXT,
            version_match TEXT,
            affected_versions TEXT,
            first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (watchlist_id, cve_id),
            FOREIGN KEY (watchlist_id) REFERENCES software_watchlist(id) ON DELETE CASCADE
        ) WITHOUT ROWID");

        $db->exec("CREATE TABLE IF NOT EXISTS cve_sync_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            status TEXT NOT NULL DEFAULT 'idle',
            mode TEXT,
            phase TEXT,
            cursor INTEGER NOT NULL DEFAULT 0,
            window_start TEXT,
            window_end TEXT,
            total INTEGER NOT NULL DEFAULT 0,
            processed INTEGER NOT NULL DEFAULT 0,
            inserted INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0,
            token TEXT,
            base_url TEXT,
            message TEXT,
            target_watchlist_id INTEGER,
            target_cpes TEXT,
            target_index INTEGER NOT NULL DEFAULT 0,
            started_at TEXT,
            finished_at TEXT,
            last_success_at TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS cve_sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            mode TEXT,
            status TEXT NOT NULL DEFAULT 'running',
            records INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            started_at TEXT NOT NULL DEFAULT (datetime('now')),
            finished_at TEXT
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS cve_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            report_type TEXT NOT NULL DEFAULT 'cve_software',
            period_start TEXT,
            period_end TEXT,
            filters TEXT,
            summary_json TEXT,
            data TEXT NOT NULL,
            generated_by INTEGER,
            generated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_catalog_severity ON cve_catalog(severity)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_reports_generated ON cve_reports(generated_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_catalog_published ON cve_catalog(published_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_catalog_cvss ON cve_catalog(cvss_v3_score DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_product_vendor ON cve_product(vendor, product)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_kev_date ON cve_kev(date_added DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_epss_score ON cve_epss(epss DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_match_cve ON cve_watchlist_match(cve_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_software_group ON software_watchlist(group_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_software_cpe_watch ON software_cpe(watchlist_id)");

        $db->exec("INSERT OR IGNORE INTO cve_sync_state (id, status) VALUES (1, 'idle')");
    }

    private static function migrateSchema(PDO $db): void
    {
        // v0.2.6.1 creó software_watchlist con environment NULL y
        // UNIQUE(name, version). v0.2.7.0 añade entorno a la clave única.
        // SQLite no permite alterar una UNIQUE: reconstruimos la tabla.
        $cols = [];
        foreach ($db->query("PRAGMA table_info(software_watchlist)") as $col) {
            $cols[$col['name']] = $col;
        }
        if (!empty($cols) && (!isset($cols['environment']) || (int)($cols['environment']['notnull'] ?? 0) === 0)) {
            self::rebuildSoftwareWatchlist($db);
        }

        // v0.2.7.3: destino del backfill de un producto.
        $syncCols = [];
        foreach ($db->query("PRAGMA table_info(cve_sync_state)") as $col) {
            $syncCols[$col['name']] = true;
        }
        if (!isset($syncCols['target_watchlist_id'])) {
            $db->exec("ALTER TABLE cve_sync_state ADD COLUMN target_watchlist_id INTEGER");
        }
        if (!isset($syncCols['target_cpes'])) {
            $db->exec("ALTER TABLE cve_sync_state ADD COLUMN target_cpes TEXT");
        }
        if (!isset($syncCols['target_index'])) {
            $db->exec("ALTER TABLE cve_sync_state ADD COLUMN target_index INTEGER NOT NULL DEFAULT 0");
        }
    }

    private static function rebuildSoftwareWatchlist(PDO $db): void
    {
        $db->exec("PRAGMA foreign_keys = OFF");
        try {
            $db->beginTransaction();
            $db->exec("DROP TABLE IF EXISTS software_watchlist_new");
            $db->exec("CREATE TABLE software_watchlist_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER REFERENCES software_groups(id) ON DELETE SET NULL,
                name TEXT NOT NULL,
                vendor TEXT,
                product TEXT,
                version TEXT NOT NULL DEFAULT '',
                environment TEXT NOT NULL DEFAULT '',
                criticality TEXT,
                asset_count INTEGER,
                notes TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(name, version, environment)
            )");
            $db->exec(
                "INSERT INTO software_watchlist_new
                 (id, group_id, name, vendor, product, version, environment, criticality, asset_count, notes, is_active, created_at, updated_at)
                 SELECT id, group_id, name, vendor, product,
                        COALESCE(version, ''), COALESCE(environment, ''),
                        criticality, asset_count, notes, COALESCE(is_active, 1),
                        COALESCE(created_at, datetime('now')), COALESCE(updated_at, datetime('now'))
                 FROM software_watchlist"
            );
            $db->exec("DROP TABLE software_watchlist");
            $db->exec("ALTER TABLE software_watchlist_new RENAME TO software_watchlist");
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        } finally {
            $db->exec("PRAGMA foreign_keys = ON");
        }

        $db->exec("CREATE INDEX IF NOT EXISTS idx_software_group ON software_watchlist(group_id)");
    }

    public static function query(string $sql, array $params = []): PDOStatement
    {
        $stmt = self::getInstance()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    public static function fetchOne(string $sql, array $params = []): ?array
    {
        $stmt = self::query($sql, $params);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public static function fetchAll(string $sql, array $params = []): array
    {
        $stmt = self::query($sql, $params);
        return $stmt->fetchAll();
    }

    public static function insert(string $sql, array $params = []): int
    {
        self::query($sql, $params);
        return (int)self::getInstance()->lastInsertId();
    }

    public static function update(string $sql, array $params = []): int
    {
        $stmt = self::query($sql, $params);
        return $stmt->rowCount();
    }

    public static function transaction(callable $callback): mixed
    {
        $db = self::getInstance();
        $db->beginTransaction();
        try {
            $result = $callback($db);
            $db->commit();
            return $result;
        } catch (Throwable $e) {
            $db->rollBack();
            throw $e;
        }
    }
}
