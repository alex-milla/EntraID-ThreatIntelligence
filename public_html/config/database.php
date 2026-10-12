<?php
/**
 * Gestión de la conexión SQLite y esquema de base de datos.
 * Usa PDO con prepared statements en todo momento.
 */

declare(strict_types=1);

class Database
{
    private static ?PDO $instance = null;

    public static function getInstance(): PDO
    {
        if (self::$instance === null) {
            $dbDir = dirname(DB_PATH);
            if (!is_dir($dbDir)) {
                mkdir($dbDir, 0750, true);
            }

            $dsn = 'sqlite:' . DB_PATH;
            self::$instance = new PDO($dsn, null, null, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);

            // Optimizaciones SQLite
            self::$instance->exec('PRAGMA journal_mode = WAL');
            self::$instance->exec('PRAGMA synchronous = NORMAL');
            self::$instance->exec('PRAGMA foreign_keys = ON');
            self::$instance->exec('PRAGMA busy_timeout = 5000');

            self::createSchema(self::$instance);
            self::migrateSchema(self::$instance);
        }
        return self::$instance;
    }

    /**
     * Migraciones idempotentes: añade columnas nuevas a tablas existentes
     * sin perder datos (las BD ya creadas con CREATE TABLE IF NOT EXISTS no
     * reciben columnas nuevas solas).
     */
    private static function migrateSchema(PDO $db): void
    {
        $cols = [];
        foreach ($db->query("PRAGMA table_info(tenants)") as $c) {
            $cols[$c['name']] = true;
        }
        if (!isset($cols['industry'])) {
            $db->exec("ALTER TABLE tenants ADD COLUMN industry TEXT");
        }
        if (!isset($cols['country'])) {
            $db->exec("ALTER TABLE tenants ADD COLUMN country TEXT");
        }
    }

    /**
     * Crea el esquema completo de la base de datos.
     */
    private static function createSchema(PDO $db): void
    {
        $db->exec("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
            must_change_password INTEGER NOT NULL DEFAULT 0,
            last_login_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            tenant_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            client_secret_encrypted TEXT NOT NULL,
            client_secret_iv TEXT NOT NULL,
            permissions TEXT NOT NULL DEFAULT '[]',
            is_active INTEGER NOT NULL DEFAULT 1,
            last_sync_at TEXT,
            last_sync_status TEXT,
            last_error TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS tenant_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS tenant_group_members (
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            group_id INTEGER NOT NULL REFERENCES tenant_groups(id) ON DELETE CASCADE,
            PRIMARY KEY (tenant_id, group_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS ti_articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            article_id TEXT NOT NULL,
            title TEXT NOT NULL,
            created_date TEXT,
            last_updated TEXT,
            summary TEXT,
            body TEXT,
            tags TEXT,
            is_featured INTEGER DEFAULT 0,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(tenant_id, article_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS ti_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            article_id INTEGER REFERENCES ti_articles(id) ON DELETE CASCADE,
            ioc_id TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            source TEXT,
            description TEXT,
            severity TEXT,
            first_seen TEXT,
            last_seen TEXT,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(tenant_id, ioc_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            incident_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            severity TEXT,
            status TEXT,
            classification TEXT,
            determination TEXT,
            assigned_to TEXT,
            created_date TEXT,
            last_update_date TEXT,
            recommended_actions TEXT,
            custom_tags TEXT,
            raw_data TEXT,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(tenant_id, incident_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            alert_id TEXT NOT NULL,
            incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
            title TEXT NOT NULL,
            threat_display_name TEXT,
            threat_family_name TEXT,
            category TEXT,
            severity TEXT,
            status TEXT,
            service_source TEXT,
            detection_source TEXT,
            mitre_techniques TEXT,
            first_activity TEXT,
            last_activity TEXT,
            raw_data TEXT,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(tenant_id, alert_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS machines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            machine_id TEXT NOT NULL,
            computer_dns_name TEXT,
            os_platform TEXT,
            os_version TEXT,
            health_status TEXT,
            risk_score TEXT,
            exposure_level TEXT,
            last_seen TEXT,
            last_ip_address TEXT,
            machine_tags TEXT,
            rbac_group_id INTEGER,
            aad_device_id TEXT,
            raw_data TEXT,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(tenant_id, machine_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            machine_id INTEGER REFERENCES machines(id) ON DELETE CASCADE,
            cve_id TEXT NOT NULL,
            product_name TEXT,
            product_vendor TEXT,
            product_version TEXT,
            severity TEXT,
            cvss_v3 REAL,
            fixing_kb_id TEXT,
            published_on TEXT,
            updated_on TEXT,
            public_exploit INTEGER DEFAULT 0,
            exploit_verified INTEGER DEFAULT 0,
            epss REAL,
            exposed_machines INTEGER,
            raw_data TEXT,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(tenant_id, machine_id, cve_id, product_name)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS secure_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            score_date TEXT NOT NULL,
            current_score REAL,
            max_score REAL,
            active_user_count INTEGER,
            licensed_user_count INTEGER,
            enabled_services TEXT,
            average_comparative TEXT,
            raw_data TEXT,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(tenant_id, score_date)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS hunting_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            query_hash TEXT NOT NULL,
            query_text TEXT NOT NULL,
            query_name TEXT,
            results TEXT NOT NULL,
            row_count INTEGER DEFAULT 0,
            executed_at TEXT NOT NULL DEFAULT (datetime('now')),
            period_start TEXT,
            period_end TEXT
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
            group_id INTEGER REFERENCES tenant_groups(id) ON DELETE SET NULL,
            report_type TEXT NOT NULL,
            period_type TEXT NOT NULL,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT,
            data TEXT NOT NULL,
            generated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            generated_at TEXT NOT NULL DEFAULT (datetime('now')),
            file_path TEXT
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS modules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_key TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT,
            version TEXT NOT NULL DEFAULT '1.0.0',
            is_active INTEGER NOT NULL DEFAULT 1,
            config TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT NOT NULL UNIQUE,
            setting_value TEXT,
            is_encrypted INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            module_key TEXT NOT NULL,
            sync_type TEXT NOT NULL,
            status TEXT NOT NULL,
            records_processed INTEGER DEFAULT 0,
            error_message TEXT,
            started_at TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at TEXT
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            permissions TEXT NOT NULL DEFAULT '[]',
            expires_at TEXT,
            last_used_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        // Crear usuario admin por defecto si no existe ninguno
        $stmt = $db->query("SELECT COUNT(*) as cnt FROM users");
        $row = $stmt->fetch();
        if ((int)$row['cnt'] === 0) {
            $defaultHash = password_hash('admin', PASSWORD_DEFAULT);
            $db->prepare("INSERT INTO users (username, email, password_hash, display_name, role, must_change_password)
                          VALUES (?, ?, ?, ?, ?, 1)")
               ->execute(['admin', 'admin@localhost', $defaultHash, 'Administrador', 'admin']);
        }

        // Registrar módulos por defecto
        self::registerDefaultModules($db);
    }

    private static function registerDefaultModules(PDO $db): void
    {
        $modules = [
            ['graph_connector',    'Microsoft Graph Connector',     'Conexión y gestión de tenants de Microsoft Graph', '1.0.0'],
            ['threat_intelligence','Threat Intelligence',           'Informes TI, IOCs, CVEs e intel profiles',         '1.0.0'],
            ['incidents',          'Incidentes y Alertas',          'Incidentes y alertas de Defender XDR',             '1.0.0'],
            ['vulnerabilities',    'Vulnerabilidades (TVM)',        'Vulnerabilidades de equipos y software',           '1.0.0'],
            ['secure_score',       'Secure Score',                  'Evolución de la postura de seguridad',             '1.0.0'],
            ['hunting',            'Advanced Hunting (KQL)',        'Consultas programáticas KQL',                      '1.0.0'],
            ['entra_users',        'Usuarios Entra ID',             'Investigación de usuarios: MFA, logins y riesgo',  '1.0.0'],
            ['reports',            'Reportes',                      'Generación de reportes periódicos',                '1.0.0'],
            ['llm',                'Integración LLM',               'Análisis de datos con modelos de lenguaje',        '1.0.0'],
            ['export',             'Exportación',                   'Exportación a STIX, MISP, CSV y TXT',             '1.0.0'],
        ];

        $stmt = $db->prepare("INSERT OR IGNORE INTO modules (module_key, name, description, version, is_active)
                              VALUES (?, ?, ?, ?, 1)");
        foreach ($modules as $m) {
            $stmt->execute($m);
        }
    }

    /**
     * Ejecuta una consulta preparada.
     */
    public static function query(string $sql, array $params = []): PDOStatement
    {
        $stmt = self::getInstance()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    /**
     * Obtiene una fila.
     */
    public static function fetchOne(string $sql, array $params = []): ?array
    {
        $stmt = self::query($sql, $params);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Obtiene todas las filas.
     */
    public static function fetchAll(string $sql, array $params = []): array
    {
        $stmt = self::query($sql, $params);
        return $stmt->fetchAll();
    }

    /**
     * Inserta y devuelve el último ID.
     */
    public static function insert(string $sql, array $params = []): int
    {
        self::query($sql, $params);
        return (int)self::getInstance()->lastInsertId();
    }

    /**
     * Actualiza y devuelve el número de filas afectadas.
     */
    public static function update(string $sql, array $params = []): int
    {
        $stmt = self::query($sql, $params);
        return $stmt->rowCount();
    }

    /**
     * Ejecuta dentro de una transacción.
     */
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
