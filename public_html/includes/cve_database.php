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
            description_es TEXT,
            description_es_hash TEXT,
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
            required_action_es TEXT,
            required_action_es_hash TEXT,
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
            kind TEXT NOT NULL DEFAULT 'application',
            company_id INTEGER REFERENCES software_groups(id) ON DELETE SET NULL,
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
            UNIQUE(name, version, environment, group_id)
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

        // v0.2.7.10: informes de CVE generados con IA (formato SploitScan).
        $db->exec("CREATE TABLE IF NOT EXISTS cve_ai_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_ids TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            data_json TEXT,
            content_text TEXT,
            ai_text TEXT,
            ai_profile_id INTEGER,
            ai_model TEXT,
            ai_error TEXT,
            ai_duration_ms INTEGER,
            defender_json TEXT,
            token TEXT,
            generated_by INTEGER,
            no_ai INTEGER NOT NULL DEFAULT 0,
            revision INTEGER NOT NULL DEFAULT 1,
            group_id INTEGER REFERENCES software_groups(id) ON DELETE SET NULL,
            mode TEXT NOT NULL DEFAULT 'extended',
            tags TEXT,
            processed_items INTEGER NOT NULL DEFAULT 0,
            total_items INTEGER NOT NULL DEFAULT 0,
            started_at TEXT,
            updated_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            finished_at TEXT
        )");

        // v0.2.8.1: análisis independiente, tags y grupo por CVE.
        $db->exec("CREATE TABLE IF NOT EXISTS cve_ai_report_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL REFERENCES cve_ai_reports(id) ON DELETE CASCADE,
            cve_id TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            tags TEXT,
            group_id INTEGER REFERENCES software_groups(id) ON DELETE SET NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            ai_text TEXT,
            sections_json TEXT,
            ai_model TEXT,
            ai_error TEXT,
            started_at TEXT,
            finished_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(report_id, cve_id)
        )");

        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_catalog_severity ON cve_catalog(severity)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_ai_items_report ON cve_ai_report_items(report_id, position)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_reports_generated ON cve_reports(generated_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_ai_reports_created ON cve_ai_reports(created_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_cve_ai_reports_token ON cve_ai_reports(token)");
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

        // v0.2.8.5: jerarquía Empresas > Empresa > Grupos de aplicaciones.
        $groupCols = [];
        foreach ($db->query("PRAGMA table_info(software_groups)") as $col) {
            $groupCols[$col['name']] = true;
        }
        if (!isset($groupCols['kind'])) {
            $db->exec("ALTER TABLE software_groups ADD COLUMN kind TEXT NOT NULL DEFAULT 'application'");
        }
        if (!isset($groupCols['company_id'])) {
            $db->exec("ALTER TABLE software_groups ADD COLUMN company_id INTEGER");
        }
        $db->exec("CREATE INDEX IF NOT EXISTS idx_software_group_kind ON software_groups(kind)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_software_group_company ON software_groups(company_id)");

        // Categoría raíz fija «Empresas». Si ya existe un grupo con ese nombre
        // en la raíz, se reutiliza como categoría para no duplicarlo.
        $root = $db->query("SELECT id FROM software_groups WHERE kind = 'root' ORDER BY id LIMIT 1")->fetch();
        if (!$root) {
            $existingRoot = $db->query(
                "SELECT id FROM software_groups
                 WHERE parent_id IS NULL AND lower(name) = 'empresas'
                 ORDER BY id LIMIT 1"
            )->fetch();
            if ($existingRoot) {
                $db->prepare(
                    "UPDATE software_groups
                     SET kind = 'root', company_id = NULL, position = -1, updated_at = datetime('now')
                     WHERE id = ?"
                )->execute([(int)$existingRoot['id']]);
            } else {
                $db->exec(
                    "INSERT INTO software_groups (name, parent_id, position, kind, company_id)
                     VALUES ('Empresas', NULL, -1, 'root', NULL)"
                );
            }
        }

        // Permitir la misma aplicación/versión en grupos/empresas distintas.
        $hasGroupUnique = false;
        foreach ($db->query("PRAGMA index_list(software_watchlist)") as $idx) {
            if ((int)($idx['unique'] ?? 0) !== 1) {
                continue;
            }
            $indexCols = [];
            $indexName = (string)($idx['name'] ?? '');
            if ($indexName === '') {
                continue;
            }
            foreach ($db->query("PRAGMA index_info(" . $db->quote($indexName) . ")") as $ci) {
                $indexCols[] = (string)($ci['name'] ?? '');
            }
            if ($indexCols === ['name', 'version', 'environment', 'group_id']) {
                $hasGroupUnique = true;
                break;
            }
        }
        if (!$hasGroupUnique) {
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

        // v0.2.7.11: modo sin IA y marca de inicio del informe.
        $aiCols = [];
        foreach ($db->query("PRAGMA table_info(cve_ai_reports)") as $col) {
            $aiCols[$col['name']] = true;
        }
        if (!isset($aiCols['no_ai'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN no_ai INTEGER NOT NULL DEFAULT 0");
        }
        if (!isset($aiCols['started_at'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN started_at TEXT");
        }
        // v0.2.7.13: respuesta de la IA sin formatear (la vista es HTML).
        if (!isset($aiCols['ai_text'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN ai_text TEXT");
        }
        if (!isset($aiCols['revision'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN revision INTEGER NOT NULL DEFAULT 1");
        }
        if (!isset($aiCols['group_id'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN group_id INTEGER REFERENCES software_groups(id) ON DELETE SET NULL");
        }
        if (!isset($aiCols['updated_at'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN updated_at TEXT");
        }
        if (!isset($aiCols['defender_json'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN defender_json TEXT");
        }
        // v0.2.8.1: análisis extendido por CVE, tags y progreso.
        if (!isset($aiCols['mode'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN mode TEXT NOT NULL DEFAULT 'extended'");
        }
        if (!isset($aiCols['tags'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN tags TEXT");
        }
        if (!isset($aiCols['processed_items'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN processed_items INTEGER NOT NULL DEFAULT 0");
        }
        if (!isset($aiCols['total_items'])) {
            $db->exec("ALTER TABLE cve_ai_reports ADD COLUMN total_items INTEGER NOT NULL DEFAULT 0");
        }

        // v0.2.7.15: descripción traducida y hash del texto original.
        $catCols = [];
        foreach ($db->query("PRAGMA table_info(cve_catalog)") as $col) {
            $catCols[$col['name']] = true;
        }
        if (!isset($catCols['description_es'])) {
            $db->exec("ALTER TABLE cve_catalog ADD COLUMN description_es TEXT");
        }
        if (!isset($catCols['description_es_hash'])) {
            $db->exec("ALTER TABLE cve_catalog ADD COLUMN description_es_hash TEXT");
        }

        // v0.2.7.19: traducción cacheada de la acción requerida por CISA.
        $kevCols = [];
        foreach ($db->query("PRAGMA table_info(cve_kev)") as $col) {
            $kevCols[$col['name']] = true;
        }
        if (!isset($kevCols['required_action_es'])) {
            $db->exec("ALTER TABLE cve_kev ADD COLUMN required_action_es TEXT");
        }
        if (!isset($kevCols['required_action_es_hash'])) {
            $db->exec("ALTER TABLE cve_kev ADD COLUMN required_action_es_hash TEXT");
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
                UNIQUE(name, version, environment, group_id)
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
