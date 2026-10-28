<?php
/**
 * Módulo: IOCs ThreatFox (abuse.ch)
 *
 * Extracción y consulta de indicadores de compromiso publicados en ThreatFox.
 * Trabaja contra una base local propia (storage/threatfox.sqlite) y, si se
 * pide, contra la API v1 en vivo. No requiere permisos de Microsoft Graph.
 *
 * Rutas:
 *   GET  /modules/threatfox                  consulta + filtros + tabla
 *   GET  /modules/threatfox/settings         ajustes (Auth-Key) — solo admin
 *   POST /modules/threatfox/settings         guarda la Auth-Key — solo admin
 *   POST /modules/threatfox/ingest           ingesta diaria — solo admin
 *   POST /modules/threatfox/backfill/start   descarga del histórico — solo admin
 *   GET  /modules/threatfox/backfill/chunk   siguiente bloque (progreso)
 *   GET  /modules/threatfox/export           panel de exportación
 *   POST /modules/threatfox/export           genera los ficheros
 *   GET  /modules/threatfox/state            estado en JSON
 */

declare(strict_types=1);

class Module_Threatfox extends BaseModule
{
    public function key(): string
    {
        return 'threatfox';
    }

    public function name(): string
    {
        return 'IOCs ThreatFox';
    }

    public function description(): string
    {
        return 'Indicadores de compromiso de abuse.ch (ThreatFox)';
    }

    public function version(): string
    {
        return '1.0.0';
    }

    /** ThreatFox no usa Microsoft Graph. */
    public function requiredPermissions(): array
    {
        return [];
    }

    /** No tiene sincronización de tenant: la ingesta va por su propio cron. */
    public function isSyncable(): bool
    {
        return false;
    }

    public function sync(int $tenantId): array
    {
        return ['success' => false, 'error' => 'ThreatFox no se sincroniza por tenant.'];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'IOCs ThreatFox',
            'url'   => base_url('modules/threatfox'),
            'icon'  => 'bug',
            'group' => 'Inteligencia',
            'after' => 'threat_intelligence',
        ];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',               'handler' => [$this, 'index']],
            ['method' => 'GET',  'pattern' => 'settings',       'handler' => [$this, 'settingsPage']],
            ['method' => 'POST', 'pattern' => 'settings',       'handler' => [$this, 'saveSettings']],
            ['method' => 'POST', 'pattern' => 'ingest',         'handler' => [$this, 'ingestNow']],
            ['method' => 'POST', 'pattern' => 'backfill/start', 'handler' => [$this, 'backfillStart']],
            ['method' => 'GET',  'pattern' => 'backfill/chunk', 'handler' => [$this, 'backfillChunk']],
            ['method' => 'GET',  'pattern' => 'export',         'handler' => [$this, 'exportPanel']],
            ['method' => 'POST', 'pattern' => 'export',         'handler' => [$this, 'exportRun']],
            ['method' => 'GET',  'pattern' => 'state',          'handler' => [$this, 'stateEndpoint']],
        ];
    }

    /* =====================================================================
     * Consulta
     * ================================================================== */

    public function index(array $params = []): void
    {
        $filters = ThreatfoxQuery::normalize($_GET);
        $page = max(1, (int)($_GET['page'] ?? 1));
        $result = ThreatfoxQuery::run($filters, $page);

        $store = new ThreatfoxStore();

        echo $this->page('index', [
            'module'   => $this,
            'filters'  => $filters,
            'result'   => $result,
            'stats'    => $store->stats(),
            'ingests'  => $store->lastIngests(),
            'catalogs' => ThreatfoxQuery::catalogs(),
            'hasKey'   => ThreatfoxApi::hasAuthKey(),
            'keyEnv'   => ThreatfoxApi::authKeyFromEnv(),
            'backfill' => ThreatfoxIngest::state(),
            'notice'   => flash('threatfox'),
            'isAdmin'  => Auth::isAdmin(),
        ]);
    }

    /* =====================================================================
     * Ajustes (Auth-Key)
     * ================================================================== */

    public function settingsPage(array $params = []): void
    {
        Auth::requireAdmin();

        echo $this->page('settings', [
            'module'   => $this,
            'hasKey'   => ThreatfoxApi::hasAuthKey(),
            'keyEnv'   => ThreatfoxApi::authKeyFromEnv(),
            'keyMasked' => $this->maskKey(ThreatfoxApi::resolveAuthKey()),
            'dbPath'   => (string)THREATFOX_DB_PATH,
            'dbExists' => is_file((string)THREATFOX_DB_PATH),
            'notice'   => flash('threatfox_settings'),
            'cronCmd'  => 'php ' . ROOT_PATH . '/cron/threatfox-ingest.php --days=1',
        ]);
    }

    public function saveSettings(array $params = []): void
    {
        Auth::requireAdmin();

        if (ThreatfoxApi::authKeyFromEnv()) {
            flash('threatfox_settings', [
                'type' => 'warning',
                'text' => 'La Auth-Key viene de THREATFOX_AUTH_KEY (.env): cámbiala allí para que tenga efecto.',
            ]);
            redirect(base_url('modules/threatfox/settings'));
        }

        if (!empty($_POST['clear_key'])) {
            setting_set('threatfox_auth_key', null, true);
            flash('threatfox_settings', ['type' => 'success', 'text' => 'Auth-Key eliminada.']);
            redirect(base_url('modules/threatfox/settings'));
        }

        $key = trim((string)($_POST['auth_key'] ?? ''));
        if ($key === '') {
            flash('threatfox_settings', ['type' => 'warning', 'text' => 'Escribe una Auth-Key válida.']);
            redirect(base_url('modules/threatfox/settings'));
        }
        if (strlen($key) < 16 || preg_match('/\s/', $key)) {
            flash('threatfox_settings', [
                'type' => 'error',
                'text' => 'La Auth-Key no parece válida (mínimo 16 caracteres y sin espacios).',
            ]);
            redirect(base_url('modules/threatfox/settings'));
        }

        try {
            setting_set('threatfox_auth_key', $key, true);
        } catch (Throwable $e) {
            flash('threatfox_settings', [
                'type' => 'error',
                'text' => 'No se pudo cifrar la clave: ' . $e->getMessage()
                    . ' Define ENCRYPTION_KEY en el .env o usa THREATFOX_AUTH_KEY.',
            ]);
            redirect(base_url('modules/threatfox/settings'));
        }

        /* El catálogo de tipos se refresca la próxima vez que se pida. */
        @unlink(STORAGE_PATH . '/threatfox-types.json');

        flash('threatfox_settings', ['type' => 'success', 'text' => 'Auth-Key guardada (cifrada).']);
        redirect(base_url('modules/threatfox/settings'));
    }

    private function maskKey(string $key): string
    {
        if ($key === '') {
            return '';
        }
        if (strlen($key) <= 8) {
            return str_repeat('•', strlen($key));
        }
        return substr($key, 0, 4) . str_repeat('•', 10) . substr($key, -4);
    }

    /* =====================================================================
     * Ingesta
     * ================================================================== */

    public function ingestNow(array $params = []): void
    {
        Auth::requireAdmin();

        $days = (int)($_POST['days'] ?? THREATFOX_DEFAULT_DAYS);
        $days = max(1, min(THREATFOX_DAYS_MAX, $days));

        try {
            $result = ThreatfoxIngest::run($days);
            flash('threatfox', [
                'type' => 'success',
                'text' => sprintf(
                    'Ingesta completada: %s filas recibidas, %s escritas. Total en la base: %s IOCs.',
                    number_format($result['received'], 0, ',', '.'),
                    number_format($result['written'], 0, ',', '.'),
                    number_format($result['total'], 0, ',', '.')
                ),
            ]);
        } catch (Throwable $e) {
            flash('threatfox', ['type' => 'error', 'text' => 'Error de ingesta: ' . $e->getMessage()]);
        }

        redirect(base_url('modules/threatfox'));
    }

    public function backfillStart(array $params = []): void
    {
        Auth::requireAdmin();

        try {
            $state = ThreatfoxIngest::backfillStart();
            flash('threatfox', [
                'type' => 'info',
                'text' => 'Descarga completa lista: ' . number_format((int)$state['rows_total'], 0, ',', '.')
                    . ' filas por importar. La importación continúa automáticamente.',
            ]);
        } catch (Throwable $e) {
            flash('threatfox', ['type' => 'error', 'text' => 'Error en la descarga completa: ' . $e->getMessage()]);
        }

        redirect(base_url('modules/threatfox'));
    }

    public function backfillChunk(array $params = []): void
    {
        Auth::requireAdmin();

        try {
            json_response(ThreatfoxIngest::backfillChunk());
        } catch (Throwable $e) {
            json_response(['error' => $e->getMessage()], 500);
        }
    }

    public function stateEndpoint(array $params = []): void
    {
        $store = new ThreatfoxStore();
        json_response([
            'total'    => $store->count(),
            'stats'    => $store->stats(),
            'ingests'  => $store->lastIngests(),
            'backfill' => ThreatfoxIngest::state(),
            'has_key'  => ThreatfoxApi::hasAuthKey(),
        ]);
    }

    /* =====================================================================
     * Exportación
     * ================================================================== */

    public function exportPanel(array $params = []): void
    {
        $filters = ThreatfoxQuery::normalize($_GET);
        $config = $this->exportConfig();

        /* Con la base local el recuento es SQL (sin red). Con la API se
           calcula al generar, para no gastar una llamada al abrir el panel. */
        $selection = null;
        if ($filters['source'] === 'db') {
            $store = new ThreatfoxStore();
            $selection = $store->countFiltered(ThreatfoxQuery::storeFiltersFor($filters));
        }

        echo $this->page('export', [
            'module'    => $this,
            'filters'   => $filters,
            'config'    => $config,
            'selection' => $selection,
            'types'     => ThreatfoxExport::INDICATOR_TYPES,
            'tlpLevels' => ThreatfoxExport::TLP_LEVELS,
        ]);
    }

    public function exportRun(array $params = []): void
    {
        Auth::require();

        /* La interfaz envía JSON (api()); los formularios clásicos, $_POST. */
        $input = $_POST;
        if ($input === []) {
            $decoded = json_decode((string)file_get_contents('php://input'), true);
            if (is_array($decoded)) {
                $input = $decoded;
            }
        }

        $filters = ThreatfoxQuery::normalize($input);
        $format = strtolower((string)($input['format'] ?? 'stix'));
        if (!in_array($format, ['stix', 'misp', 'csv', 'json', 'txt'], true)) {
            json_response(['success' => false, 'error' => 'Formato no soportado.'], 400);
        }

        $split = !empty($input['split']) && (string)$input['split'] !== '0';
        $tlp = strtolower((string)($input['tlp'] ?? 'amber'));
        if (!isset(ThreatfoxExport::TLP_LEVELS[$tlp])) {
            $tlp = 'amber';
        }
        $validDays = max(1, min(3650, (int)($input['valid_days'] ?? 365)));

        $confidence = null;
        if (empty($input['use_ioc_confidence'])) {
            $confidence = max(0, min(100, (int)($input['confidence'] ?? 75)));
        }

        $config = [
            'sourceName'    => trim((string)($input['source_name'] ?? '')) ?: 'abuse.ch ThreatFox',
            'threatActor'   => trim((string)($input['threat_actor'] ?? '')),
            'tags'          => trim((string)($input['tags'] ?? '')),
            'indicatorType' => (string)($input['indicator_type'] ?? 'malicious-activity'),
            'confidence'    => $confidence,
            'ip_direction'  => (string)($input['ip_direction'] ?? 'ip-dst'),
        ];

        try {
            $rows = $this->selectionRows($filters);
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }

        if ($rows === []) {
            json_response(['success' => false, 'error' => 'No hay IOCs que exportar con los filtros actuales.'], 400);
        }

        $exporter = new ThreatfoxExport($tlp, $validDays, $config);
        $result = $exporter->files($rows, $format, $split);

        /* Se recuerda la configuración usada (como hace el extractor original). */
        try {
            setting_set('threatfox_export_config', json_encode($config, JSON_UNESCAPED_SLASHES), false);
        } catch (Throwable $e) {
            /* Recordar la configuración es opcional: nunca impide la descarga. */
        }

        json_response([
            'success' => true,
            'files'   => $result['files'],
            'count'   => $result['count'],
            'skipped' => $result['skipped'],
            'format'  => $format,
        ]);
    }

    /**
     * Filas del conjunto filtrado para exportar (máximo THREATFOX_EXPORT_MAX_ROWS).
     */
    private function selectionRows(array $filters): array
    {
        if ($filters['source'] === 'api') {
            $result = ThreatfoxQuery::run(array_merge($filters, ['limit' => 1000]), 1);
            $rows = $result['rows'];
            /* La API pagina en memoria: se recorren las páginas restantes. */
            for ($page = 2; $page <= (int)$result['totalPages']; $page++) {
                $next = ThreatfoxQuery::run(array_merge($filters, ['limit' => 1000]), $page);
                $rows = array_merge($rows, $next['rows']);
                if (count($rows) >= THREATFOX_EXPORT_MAX_ROWS) {
                    break;
                }
            }
            return array_slice($rows, 0, THREATFOX_EXPORT_MAX_ROWS);
        }

        $store = new ThreatfoxStore();
        return $store->queryAll(ThreatfoxQuery::storeFiltersFor($filters), THREATFOX_EXPORT_MAX_ROWS);
    }

    /** Configuración de exportación recordada (con valores por defecto). */
    private function exportConfig(): array
    {
        $defaults = [
            'sourceName'    => 'abuse.ch ThreatFox',
            'threatActor'   => '',
            'tags'          => '',
            'indicatorType' => 'malicious-activity',
            'confidence'    => 75,
            'ip_direction'  => 'ip-dst',
        ];

        $saved = safe_json_decode((string)setting_get('threatfox_export_config', ''), null);
        if (!is_array($saved)) {
            return $defaults + ['tlp' => 'green', 'valid_days' => 365, 'split' => true];
        }

        return [
            'sourceName'    => (string)($saved['sourceName'] ?? $defaults['sourceName']),
            'threatActor'   => (string)($saved['threatActor'] ?? ''),
            'tags'          => (string)($saved['tags'] ?? ''),
            'indicatorType' => (string)($saved['indicatorType'] ?? $defaults['indicatorType']),
            'confidence'    => $saved['confidence'] === null ? 75 : (int)$saved['confidence'],
            'ip_direction'  => (string)($saved['ip_direction'] ?? 'ip-dst'),
            'tlp'           => 'green',
            'valid_days'    => 365,
            'split'         => true,
        ];
    }
}
