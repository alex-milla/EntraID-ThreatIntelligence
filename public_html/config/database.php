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

        // ti_iocs.profile_id (indicadores asociados a un intel profile)
        $iocCols = [];
        foreach ($db->query("PRAGMA table_info(ti_iocs)") as $c) {
            $iocCols[$c['name']] = true;
        }
        if (!isset($iocCols['profile_id'])) {
            $db->exec("ALTER TABLE ti_iocs ADD COLUMN profile_id INTEGER");
        }

        // v0.2.5.23: retirada del proveedor OpenCode (sus modelos gratis no se
        // pueden usar desde la web). Limpieza idempotente, una sola vez.
        self::cleanupRemovedProviders($db);
    }

    /**
     * Elimina la configuración del proveedor OpenCode retirado en v0.2.5.23.
     * Se ejecuta una única vez (bandera en settings) y sin depender de helpers.
     */
    private static function cleanupRemovedProviders(PDO $db): void
    {
        try {
            $stmt = $db->prepare("SELECT setting_value FROM settings WHERE setting_key = 'llm_cleanup_opencode'");
            $stmt->execute();
            if ($stmt->fetchColumn() === '1') {
                return;
            }

            // Perfiles cuyo proveedor ya no existe
            $db->exec("DELETE FROM llm_profiles WHERE lower(provider) = 'opencode'");
            // Configuración única heredada apuntando a OpenCode
            $db->exec("UPDATE settings SET setting_value = '' WHERE setting_key = 'llm_provider' AND lower(setting_value) = 'opencode'");
            // Caché de modelos de OpenCode
            $db->exec("DELETE FROM settings WHERE setting_key = 'llm_models_cache_opencode'");
            // Tareas que apuntaban a perfiles borrados → predeterminado
            $db->exec("UPDATE settings SET setting_value = '0' WHERE setting_key LIKE 'llm_task_%'");
            // Bandera de limpieza realizada
            $db->exec("INSERT OR REPLACE INTO settings (setting_key, setting_value, updated_at) VALUES ('llm_cleanup_opencode', '1', datetime('now'))");
        } catch (Throwable $e) {
            // Instalaciones sin estas tablas: no hacer nada.
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

        // Intel profiles de Threat Intelligence (threat actors y tools)
        $db->exec("CREATE TABLE IF NOT EXISTS ti_intel_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            profile_id TEXT NOT NULL,
            kind TEXT,
            title TEXT NOT NULL,
            summary TEXT,
            description TEXT,
            tradecraft TEXT,
            aliases TEXT,
            targets TEXT,
            industries TEXT,
            regions TEXT,
            countries TEXT,
            first_active TEXT,
            raw_data TEXT,
            indicators_synced_at TEXT,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(tenant_id, profile_id)
        )");

        // Migración: columnas añadidas en instalaciones antiguas
        $profCols = [];
        foreach ($db->query("PRAGMA table_info(ti_intel_profiles)") as $c) {
            $profCols[$c['name']] = true;
        }
        if (!isset($profCols['indicators_synced_at'])) {
            $db->exec("ALTER TABLE ti_intel_profiles ADD COLUMN indicators_synced_at TEXT");
        }
        if (!isset($profCols['industries'])) {
            $db->exec("ALTER TABLE ti_intel_profiles ADD COLUMN industries TEXT");
        }
        if (!isset($profCols['regions'])) {
            $db->exec("ALTER TABLE ti_intel_profiles ADD COLUMN regions TEXT");
        }

        // Estado por usuario de cada artículo de TI (leído / favorito).
        // Se apoya en ti_articles.id, que desde v0.2.5.49 es estable (upsert,
        // no REPLACE, para no borrar en cascada los IOCs ni perder el estado).
        $db->exec("CREATE TABLE IF NOT EXISTS ti_article_state (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            article_id INTEGER NOT NULL REFERENCES ti_articles(id) ON DELETE CASCADE,
            is_read INTEGER NOT NULL DEFAULT 0,
            read_at TEXT,
            is_favorite INTEGER NOT NULL DEFAULT 0,
            favorite_at TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (user_id, article_id)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_ti_article_state_article ON ti_article_state(article_id)");

        // Caché de traducciones IA de artículos (con caducidad lógica de 90 días).
        $db->exec("CREATE TABLE IF NOT EXISTS ti_article_translations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER NOT NULL REFERENCES ti_articles(id) ON DELETE CASCADE,
            lang TEXT NOT NULL DEFAULT 'es',
            content TEXT,
            source_updated TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(article_id, lang)
        )");

        // Sincronizaciones en segundo plano (job encadenado vía PHP-FPM).
        $db->exec("CREATE TABLE IF NOT EXISTS sync_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            job_type TEXT NOT NULL DEFAULT 'ti_full',
            status TEXT NOT NULL DEFAULT 'queued',
            phase TEXT,
            cursor INTEGER NOT NULL DEFAULT 0,
            total INTEGER NOT NULL DEFAULT 0,
            processed INTEGER NOT NULL DEFAULT 0,
            added INTEGER NOT NULL DEFAULT 0,
            skipped INTEGER NOT NULL DEFAULT 0,
            message TEXT,
            token TEXT NOT NULL,
            base_url TEXT,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_sync_jobs_tenant ON sync_jobs(tenant_id, status)");

        // Registro de intentos de acceso (seguridad / detección de fuerza bruta).
        $db->exec("CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            user_id INTEGER,
            ip TEXT,
            user_agent TEXT,
            success INTEGER NOT NULL DEFAULT 0,
            reason TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_created ON login_attempts(created_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip, created_at)");

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

        // Perfiles de IA (varios proveedores guardados a la vez)
        $db->exec("CREATE TABLE IF NOT EXISTS llm_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT '',
            api_url TEXT,
            api_key_encrypted TEXT,
            model TEXT,
            max_tokens INTEGER NOT NULL DEFAULT 2048,
            is_default INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        // Acciones rápidas de Análisis IA (editables)
        $db->exec("CREATE TABLE IF NOT EXISTS llm_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            prompt TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            scope TEXT NOT NULL DEFAULT 'tenant',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )");

        // Migración: columna scope en instalaciones antiguas
        $actionCols = [];
        foreach ($db->query("PRAGMA table_info(llm_actions)") as $c) {
            $actionCols[$c['name']] = true;
        }
        if (!isset($actionCols['scope'])) {
            $db->exec("ALTER TABLE llm_actions ADD COLUMN scope TEXT NOT NULL DEFAULT 'tenant'");
        }

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

        // Sembrar las acciones rápidas de Análisis IA (solo si no hay)
        self::registerDefaultActions($db);
    }

    private static function registerDefaultModules(PDO $db): void
    {
        $modules = [
            ['graph_connector',    'Microsoft Graph Connector',     'Conexión y gestión de tenants de Microsoft Graph', '1.0.0'],
            ['threat_intelligence','Threat Intelligence',           'Informes TI, IOCs, CVEs e intel profiles',         '1.0.0'],
            ['incidents',          'Incidentes y Alertas',          'Incidentes y alertas de Defender XDR',             '1.0.0'],
            ['vulnerabilities',    'Vulnerabilidades (TVM)',        'Vulnerabilidades de equipos y software',           '1.0.0'],
            ['cve',                'CVE (catálogo público)',        'Catálogo público de CVEs e inventario de software', '0.1.0'],
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
     * Siembra las acciones rápidas por defecto de cada ámbito (solo si ese
     * ámbito no tiene acciones). Son editables desde la propia UI (⋮).
     */
    private static function registerDefaultActions(PDO $db): void
    {
        foreach (['tenant', 'actor', 'tool', 'indicator', 'article'] as $scope) {
            self::ensureScopeActions($db, $scope, self::defaultActionsForScope($scope));
        }
    }

    /** Acciones rápidas por defecto para un ámbito. */
    private static function defaultActionsForScope(string $scope): array
    {
        $sets = [
            'tenant' => [
                ['Resumen ejecutivo', 'Elabora un RESUMEN EJECUTIVO de la postura de seguridad del tenant: lo más relevante, los riesgos principales y 3-5 recomendaciones priorizadas.'],
                ['Incidentes y alertas', 'Analiza los INCIDENTES y ALERTAS: tendencias, severidad, amenazas y técnicas más relevantes, y acciones recomendadas.'],
                ['Vulnerabilidades', 'Analiza las VULNERABILIDADES: prioriza por explotabilidad (exploit público, EPSS, CVSS) y propón un plan de remediación.'],
                ['Secure Score', 'Analiza el SECURE SCORE: interpreta el valor y su evolución y propón mejoras concretas y priorizadas.'],
                ['IOCs', 'Analiza los IOCs recientes: agrúpalos por tipo y relevancia, indica de qué artículo provienen y qué acciones tomar.'],
                ['Artículos TI', 'Lista los ARTÍCULOS de Threat Intelligence recientes con su título, fecha, enlace y los IOCs asociados a cada uno, y resume brevemente su relevancia para el tenant.'],
                ['Riesgos', 'Identifica los PRINCIPALES RIESGOS del tenant (incidentes, alertas, vulnerabilidades, IOCs y postura) y priorízalos.'],
            ],
            'actor' => [
                ['Perfil del actor', 'Elabora un perfil del actor: quién es, motivación, atribución, país/región de origen y a quién suele atacar, basándote SOLO en los datos proporcionados.'],
                ['TTPs y MITRE', 'Resume las TTPs y técnicas MITRE de este actor a partir de la información y de sus indicadores; agrúpalas por táctica.'],
                ['Detección', 'Propón recomendaciones de detección para este actor: señales a monitorizar, reglas/búsquedas (KQL conceptual) y prioridades.'],
                ['Indicadores clave', 'Resume los indicadores asociados más relevantes (tipos y valores clave) y qué acciones tomar con ellos.'],
            ],
            'tool' => [
                ['Qué es y cómo se usa', 'Explica qué es esta herramienta, para qué la usan los atacantes y en qué fase del ataque (MITRE) encaja, basándote SOLO en los datos.'],
                ['TTPs / uso en campañas', 'Resume cómo se emplea esta herramienta (técnicas MITRE) y ejemplos de uso en campañas.'],
                ['Detección', 'Propón recomendaciones de detección para esta herramienta (señales, reglas/búsquedas y prioridades).'],
                ['Indicadores clave', 'Resume los indicadores asociados más relevantes y qué acciones tomar con ellos.'],
            ],
            'indicator' => [
                ['Análisis de indicadores', 'Analiza los indicadores mostrados: clasifícalos por tipo, indica su relevancia/riesgo y posibles falsos positivos.'],
                ['Prioriza accionables', 'Prioriza los indicadores más accionables y explica por qué, con el contexto disponible.'],
                ['Bloqueo/detección', 'Propón cómo usar estos indicadores (bloqueo, reglas, búsquedas) y qué precauciones tomar para evitar falsos positivos.'],
            ],
            'article' => [
                ['Resumen ejecutivo (cliente)', 'Redacta un RESUMEN EJECUTIVO para un cliente no técnico (150-250 palabras): qué ha ocurrido, a quién afecta y por qué es relevante, en lenguaje claro y sin jerga. Empieza con un titular de una línea. Basado SOLO en el artículo.'],
                ['Indicadores accionables', 'Genera una TABLA Markdown de los indicadores del artículo con columnas: Tipo, Valor, Contexto y Acción recomendada (bloquear/detectar/monitorizar). Muestra las direcciones IP y los dominios con el ÚLTIMO punto como "[.]" (p. ej. 203.0.113[.]45, evil[.]com). Prioriza por riesgo y avisa de posibles falsos positivos. No inventes indicadores.'],
                ['Nota divulgativa (publicación interna)', 'Redacta una NOTA DIVULGATIVA lista para publicación interna o blog, con esta estructura: Titular, Contexto, Qué ha pasado, Análisis, Implicaciones y Recomendaciones. Tono profesional y claro, 300-450 palabras, basado solo en el artículo.'],
                ['Impacto para el cliente/sector', 'Analiza el IMPACTO para nuestra organización teniendo en cuenta nuestro sector (se indica en los datos): relevancia de la amenaza, activos o servicios potencialmente afectados, exposición y qué priorizar. Si faltan datos, indícalo explícitamente.'],
                ['Mitigación y hardening', 'Propón un plan de MITIGACIÓN con medidas concretas y priorizadas (controles, configuraciones, segmentación, MFA, concienciación), ordenadas por impacto/esfuerzo, y señala las 3 más urgentes.'],
            ],
        ];
        return $sets[$scope] ?? [];
    }

    /** Inserta las acciones de un ámbito solo si ese ámbito no tiene ninguna. */
    private static function ensureScopeActions(PDO $db, string $scope, array $actions): void
    {
        if (empty($actions)) {
            return;
        }
        try {
            $stmt = $db->prepare("SELECT COUNT(*) FROM llm_actions WHERE scope = ?");
            $stmt->execute([$scope]);
            if ((int)$stmt->fetchColumn() > 0) {
                return;
            }
        } catch (Throwable $e) {
            return;
        }

        $stmt = $db->prepare("INSERT INTO llm_actions (label, prompt, position, is_active, scope) VALUES (?, ?, ?, 1, ?)");
        $pos = 10;
        foreach ($actions as $a) {
            $stmt->execute([$a[0], $a[1], $pos, $scope]);
            $pos += 10;
        }
    }

    /** Borra las acciones de un ámbito y reinserta las de por defecto. */
    public static function resetDefaultActions(string $scope = 'tenant'): void
    {
        $db = self::getInstance();
        $stmt = $db->prepare("DELETE FROM llm_actions WHERE scope = ?");
        $stmt->execute([$scope]);
        self::ensureScopeActions($db, $scope, self::defaultActionsForScope($scope));
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
