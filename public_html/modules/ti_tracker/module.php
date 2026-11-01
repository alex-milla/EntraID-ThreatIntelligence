<?php
/**
 * Módulo: Seguimiento TI (ti_tracker)
 *
 * Búsquedas guardadas sobre los IOCs de ThreatFox con memoria de lo ya visto
 * (novedades) y exportación STIX 2.1 / MISP / TXT para herramientas de
 * seguridad.
 *
 * La base de IOCs la mantiene el módulo IOCs ThreatFox
 * (storage/threatfox.sqlite, refrescada por su cron diario); este módulo solo
 * guarda búsquedas, IOCs vistos y actividad en storage/ti_tracker.sqlite.
 *
 * Rutas:
 *   GET  /modules/ti_tracker                panel de búsquedas
 *   GET  /modules/ti_tracker/new            formulario de alta
 *   GET  /modules/ti_tracker/edit/{id}      edición
 *   POST /modules/ti_tracker/save           guardar (alta/edición)
 *   POST /modules/ti_tracker/delete/{id}    borrar búsqueda y su seguimiento
 *   POST /modules/ti_tracker/run/{id}       ejecutar y actualizar novedades
 *   POST /modules/ti_tracker/export/{id}    descargar STIX/MISP/TXT
 */

declare(strict_types=1);

class Module_TiTracker extends BaseModule
{
    public function key(): string
    {
        return 'ti_tracker';
    }

    public function name(): string
    {
        return 'Seguimiento TI TF';
    }

    public function description(): string
    {
        return 'Seguimiento de Threat Intelligence de ThreatFox: búsquedas guardadas, novedades y export STIX/MISP/TXT';
    }

    public function version(): string
    {
        return '1.0.0';
    }

    /** No usa Microsoft Graph. */
    public function requiredPermissions(): array
    {
        return [];
    }

    /** No sincroniza por tenant: trabaja con la base local de ThreatFox. */
    public function isSyncable(): bool
    {
        return false;
    }

    public function sync(int $tenantId): array
    {
        return ['success' => false, 'error' => 'El Seguimiento TI no se sincroniza por tenant.'];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Seguimiento TI',
            'url'   => base_url('modules/ti_tracker'),
            'icon'  => 'radar',
            'group' => 'Inteligencia',
            'after' => 'threatfox',
        ];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',          'handler' => [$this, 'index']],
            ['method' => 'GET',  'pattern' => 'new',       'handler' => [$this, 'create']],
            ['method' => 'GET',  'pattern' => 'edit/{id}', 'handler' => [$this, 'edit']],
            ['method' => 'POST', 'pattern' => 'save',      'handler' => [$this, 'save']],
            ['method' => 'POST', 'pattern' => 'delete/{id}', 'handler' => [$this, 'delete']],
            ['method' => 'POST', 'pattern' => 'run/{id}',  'handler' => [$this, 'run']],
            ['method' => 'POST', 'pattern' => 'export/{id}', 'handler' => [$this, 'export']],
        ];
    }

    private function store(): TiTrackerStore
    {
        return new TiTrackerStore();
    }

    /* =====================================================================
     * Panel
     * ================================================================== */

    public function index(array $params = []): void
    {
        $store = $this->store();

        echo $this->page('index', [
            'module'   => $this,
            'searches' => $store->listSearches(),
            'totals'   => $store->totals(),
            'formats'  => TiTrackerStore::FORMATS,
            'notice'   => flash('ti_tracker'),
        ]);
    }

    /* =====================================================================
     * Alta y edición
     * ================================================================== */

    public function create(array $params = []): void
    {
        /* Si llega desde IOCs ThreatFox, los filtros vienen por query string. */
        $filters = ThreatfoxQuery::normalize($_GET);
        if (!isset($_GET['mode'])) {
            /* Una búsqueda nueva arranca con ventana temporal (modo recientes). */
            $filters['mode'] = 'recent';
        }
        $filters['days'] = isset($_GET['days'])
            ? TiTrackerRunner::clampDays($filters['source'], (int)$_GET['days'])
            : 30;

        $search = [
            'id'           => 0,
            'name'         => '',
            'notes'        => '',
            'filters'      => $filters,
            'formats'      => array_keys(TiTrackerStore::FORMATS),
            'tlp'          => 'amber',
            'valid_days'   => 365,
            'source_name'  => 'abuse.ch ThreatFox',
            'threat_actor' => '',
            'extra_tags'   => '',
        ];

        $this->renderForm($search);
    }

    public function edit(array $params = []): void
    {
        $search = $this->store()->getSearch((int)($params['id'] ?? 0));
        if ($search === null) {
            flash('ti_tracker', ['type' => 'error', 'text' => 'La búsqueda no existe.']);
            redirect(base_url('modules/ti_tracker'));
        }

        $this->renderForm($search);
    }

    private function renderForm(array $search): void
    {
        echo $this->page('edit', [
            'module'    => $this,
            'search'    => $search,
            'filters'   => $search['filters'],
            'catalogs'  => ThreatfoxQuery::catalogs(),
            'formats'   => TiTrackerStore::FORMATS,
            'tlpLevels' => ThreatfoxExport::TLP_LEVELS,
            'notice'    => flash('ti_tracker'),
        ]);
    }

    public function save(array $params = []): void
    {
        $store = $this->store();
        $id = (int)($_POST['id'] ?? 0);
        $id = $id > 0 ? $id : null;

        $name = self::clean((string)($_POST['name'] ?? ''), 120);
        if ($name === '') {
            flash('ti_tracker', ['type' => 'error', 'text' => 'La búsqueda necesita un nombre.']);
            redirect(base_url('modules/ti_tracker/' . ($id !== null ? 'edit/' . $id : 'new')));
        }

        $formats = [];
        foreach ((array)($_POST['formats'] ?? []) as $format) {
            $format = strtolower(trim((string)$format));
            if (isset(TiTrackerStore::FORMATS[$format])) {
                $formats[] = $format;
            }
        }
        if ($formats === []) {
            flash('ti_tracker', ['type' => 'error', 'text' => 'Selecciona al menos un formato de exportación.']);
            redirect(base_url('modules/ti_tracker/' . ($id !== null ? 'edit/' . $id : 'new')));
        }

        if ($id === null && $store->count() >= TI_TRACKER_MAX_SEARCHES) {
            flash('ti_tracker', [
                'type' => 'error',
                'text' => 'Límite de búsquedas alcanzado (' . TI_TRACKER_MAX_SEARCHES . '). Borra alguna antes de crear otra.',
            ]);
            redirect(base_url('modules/ti_tracker'));
        }

        $filters = ThreatfoxQuery::normalize($_POST);
        $filters['days'] = TiTrackerRunner::clampDays($filters['source'], (int)($_POST['days'] ?? 0));

        $tlp = strtolower((string)($_POST['tlp'] ?? 'amber'));
        if (!isset(ThreatfoxExport::TLP_LEVELS[$tlp])) {
            $tlp = 'amber';
        }

        $savedId = $store->saveSearch([
            'name'         => $name,
            'notes'        => self::clean((string)($_POST['notes'] ?? ''), 500),
            'filters'      => $filters,
            'formats'      => $formats,
            'tlp'          => $tlp,
            'valid_days'   => max(1, min(3650, (int)($_POST['valid_days'] ?? 365))),
            'source_name'  => self::clean((string)($_POST['source_name'] ?? ''), 80) ?: 'abuse.ch ThreatFox',
            'threat_actor' => self::clean((string)($_POST['threat_actor'] ?? ''), 120),
            'extra_tags'   => self::clean((string)($_POST['extra_tags'] ?? ''), 200),
        ], $id);

        flash('ti_tracker', [
            'type' => 'success',
            'text' => 'Búsqueda «' . $name . '» guardada. Pulsa Ejecutar para actualizar las novedades.',
        ]);
        redirect(base_url('modules/ti_tracker') . '?saved=' . $savedId);
    }

    public function delete(array $params = []): void
    {
        $id = (int)($params['id'] ?? 0);
        $store = $this->store();
        $search = $store->getSearch($id);
        if ($search === null) {
            flash('ti_tracker', ['type' => 'error', 'text' => 'La búsqueda no existe.']);
            redirect(base_url('modules/ti_tracker'));
        }

        $store->deleteSearch($id);
        flash('ti_tracker', ['type' => 'success', 'text' => 'Búsqueda «' . $search['name'] . '» eliminada.']);
        redirect(base_url('modules/ti_tracker'));
    }

    /* =====================================================================
     * Ejecución y exportación
     * ================================================================== */

    public function run(array $params = []): void
    {
        $store = $this->store();
        $search = $store->getSearch((int)($params['id'] ?? 0));
        if ($search === null) {
            flash('ti_tracker', ['type' => 'error', 'text' => 'La búsqueda no existe.']);
            redirect(base_url('modules/ti_tracker'));
        }

        try {
            $exec = TiTrackerRunner::execute($store, $search);
        } catch (Throwable $e) {
            flash('ti_tracker', ['type' => 'error', 'text' => 'Error al ejecutar: ' . $e->getMessage()]);
            redirect(base_url('modules/ti_tracker'));
        }

        $displayLimit = 500;
        $displayRows = array_slice($exec['rows'], 0, $displayLimit);

        /* Ficha completa de cada fila (mismos campos que IOCs ThreatFox). */
        $details = [];
        foreach ($displayRows as $index => $row) {
            $details['tt-detail-' . $index] = array_filter([
                'IOC'               => (string)($row['ioc'] ?? ''),
                'Tipo de IOC'       => (string)($row['ioc_type'] ?? ''),
                'Tipo de amenaza'   => (string)($row['threat_type'] ?? ''),
                'Malware'           => (string)($row['malware'] ?? ''),
                'Malware (legible)' => (string)($row['malware_printable'] ?? ''),
                'Alias'             => (string)($row['malware_alias'] ?? ''),
                'Confianza'         => (string)(int)($row['confidence_level'] ?? 0),
                'Primera vez'       => (string)($row['first_seen'] ?? ''),
                'Última vez'        => (string)($row['last_seen'] ?? ''),
                'Reporter'          => (string)($row['reporter'] ?? ''),
                'Tags'              => implode(', ', (array)($row['tags_list'] ?? [])),
                'Referencia'        => (string)($row['reference'] ?? ''),
                'Ingestado'         => (string)($row['ingested_at'] ?? ''),
            ], static fn($value) => trim((string)$value) !== '');
        }

        echo $this->page('run', [
            'module'       => $this,
            'search'       => $search,
            'exec'         => $exec,
            'rows'         => $displayRows,
            'details'      => $details,
            'displayLimit' => $displayLimit,
            'history'      => $store->history((int)$search['id'], 10),
            'formats'      => TiTrackerStore::FORMATS,
            'notice'       => flash('ti_tracker'),
        ]);
    }

    public function export(array $params = []): void
    {
        $input = $_POST;
        if ($input === []) {
            $decoded = json_decode((string)file_get_contents('php://input'), true);
            if (is_array($decoded)) {
                $input = $decoded;
            }
        }

        $format = strtolower((string)($input['format'] ?? ''));
        if (!isset(TiTrackerStore::FORMATS[$format])) {
            json_response(['success' => false, 'error' => 'Formato no soportado.'], 400);
        }

        $store = $this->store();
        $search = $store->getSearch((int)($params['id'] ?? 0));
        if ($search === null) {
            json_response(['success' => false, 'error' => 'La búsqueda no existe.'], 404);
        }
        if (!in_array($format, $search['formats'], true)) {
            json_response(['success' => false, 'error' => 'Ese formato no está configurado en la búsqueda.'], 400);
        }

        try {
            $rows = TiTrackerRunner::resolveRows(TiTrackerRunner::filtersFor($search));
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }

        if ($rows === []) {
            json_response(['success' => false, 'error' => 'La búsqueda no devuelve IOCs ahora mismo.'], 400);
        }

        $exporter = new ThreatfoxExport((string)$search['tlp'], (int)$search['valid_days'], [
            'sourceName'    => (string)$search['source_name'],
            'threatActor'   => (string)$search['threat_actor'],
            'tags'          => (string)$search['extra_tags'],
            'indicatorType' => 'malicious-activity',
            'confidence'    => null,
            'ip_direction'  => 'ip-dst',
        ]);

        $result = $exporter->files($rows, $format, false);
        $filename = (string)($result['files'][0]['filename'] ?? '');

        $store->logExport((int)$search['id'], $format, (int)$result['count'], $filename);

        json_response([
            'success' => true,
            'files'   => $result['files'],
            'count'   => $result['count'],
            'skipped' => $result['skipped'] ?? 0,
            'format'  => $format,
        ]);
    }

    /** Texto saneado y acotado (sin controles, espacios normalizados). */
    private static function clean(string $value, int $max): string
    {
        $value = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $value) ?? '';
        $value = trim(preg_replace('/\s+/u', ' ', $value) ?? '');

        return function_exists('mb_substr') ? mb_substr($value, 0, $max) : substr($value, 0, $max);
    }
}
