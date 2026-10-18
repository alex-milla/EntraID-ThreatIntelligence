<?php
/**
 * Módulo: CVE — catálogo público e inventario de software.
 *
 * Catálogo NVD (full/recent/incremental), matching por CPE y backfill por producto.
 * Es un módulo GLOBAL: no depende de tenants ni de permisos de Microsoft Graph.
 */

declare(strict_types=1);

class Module_Cve extends BaseModule
{
    public function key(): string { return 'cve'; }
    public function name(): string { return 'CVE'; }
    public function description(): string { return 'Catálogo público de CVEs e inventario de software'; }
    public function version(): string { return '0.1.0'; }

    public function requiredPermissions(): array { return []; }
    public function isSyncable(): bool { return false; }
    public function sync(int $tenantId): array { return ['success' => true, 'records' => 0, 'skipped' => true]; }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'CVE',
            'url'   => base_url('modules/cve'),
            'icon'  => 'bug',
            'group' => 'Seguridad',
            'after' => 'vulnerabilities',
        ];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                'handler' => [$this, 'index']],
            ['method' => 'GET',  'pattern' => 'detail/{cveId}',  'handler' => [$this, 'detail']],
            ['method' => 'GET',  'pattern' => 'status',          'handler' => [$this, 'syncStatus']],
            ['method' => 'GET',  'pattern' => 'active',          'handler' => [$this, 'syncActive']],
            ['method' => 'GET',  'pattern' => 'cpe-search',      'handler' => [$this, 'cpeSearch']],
            ['method' => 'POST', 'pattern' => 'reports/generate', 'handler' => [$this, 'generateReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-start', 'handler' => [$this, 'startAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-run/{id}', 'handler' => [$this, 'runAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-generate', 'handler' => [$this, 'startAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-retry/{id}', 'handler' => [$this, 'retryAiReport']],
            ['method' => 'GET',  'pattern' => 'reports/ai-status/{id}', 'handler' => [$this, 'aiReportStatus']],
            ['method' => 'GET',  'pattern' => 'report/{id}/csv',  'handler' => [$this, 'reportCsv']],
            ['method' => 'GET',  'pattern' => 'report-ai/{id}/txt', 'handler' => [$this, 'aiReportTxt']],
            ['method' => 'GET',  'pattern' => 'report-ai/{id}',   'handler' => [$this, 'aiReportView']],
            ['method' => 'GET',  'pattern' => 'report/{id}',      'handler' => [$this, 'reportView']],
            ['method' => 'POST', 'pattern' => 'sync',            'handler' => [$this, 'triggerSync']],
            ['method' => 'POST', 'pattern' => 'stream',          'handler' => [$this, 'streamSync']],
            ['method' => 'POST', 'pattern' => 'step',            'handler' => [$this, 'stepSync']],
            ['method' => 'POST', 'pattern' => 'cancel',          'handler' => [$this, 'cancelSync']],
            ['method' => 'POST', 'pattern' => 'groups/save',     'handler' => [$this, 'saveGroup']],
            ['method' => 'POST', 'pattern' => 'groups/delete',   'handler' => [$this, 'deleteGroup']],
            ['method' => 'POST', 'pattern' => 'software/save',   'handler' => [$this, 'saveSoftware']],
            ['method' => 'POST', 'pattern' => 'software/backfill','handler' => [$this, 'backfillSoftware']],
            ['method' => 'POST', 'pattern' => 'software/delete', 'handler' => [$this, 'deleteSoftware']],
        ];
    }

    // ============================================================
    // Página principal
    // ============================================================

    public function index(array $params = []): void
    {
        Auth::require();

        $isAdmin = Auth::isAdmin();
        $tabParam = (string)($_GET['tab'] ?? 'catalog');
        $tab = in_array($tabParam, ['software', 'reports'], true) ? $tabParam : 'catalog';
        $selectedGroup = (int)($_GET['group'] ?? 0);
        $q = trim((string)($_GET['q'] ?? ''));

        $groups = [];
        $software = [];
        $reports = [];
        $aiReports = [];
        $llmProfiles = [];
        $llmConfigured = false;
        $stats = $this->emptyStats();
        $editSoftware = null;
        $editGroup = null;
        $dbError = null;

        $catalog = [];
        $catalogTotal = 0;
        $catalogPage = 1;
        $catalogPages = 0;
        $catalogFilters = ['q' => '', 'severity' => '', 'product' => '', 'kev' => false, 'epss_min' => '', 'group' => 0, 'software_id' => 0, 'mine' => false, 'sort' => 'published'];
        $softwareOptions = [];
        $syncState = null;

        try {
            $groups = $this->groupTree();
            if ($tab === 'software') {
                $software = $this->listSoftware($selectedGroup, $q);
            } elseif ($tab === 'reports') {
                $softwareOptions = $this->listSoftware(0, '');
                $reports = $this->listReports(30);
                $aiReports = $this->listAiReports(30);
                $llmProfiles = llm_profile_list();
                $llmConfigured = class_exists('Module_Llm') && (new Module_Llm())->isConfigured();
            } else {
                $catalogFilters = [
                    'q'           => trim((string)($_GET['q'] ?? '')),
                    'severity'    => trim((string)($_GET['severity'] ?? '')),
                    'product'     => trim((string)($_GET['product'] ?? '')),
                    'kev'         => !empty($_GET['kev']),
                    'epss_min'    => trim((string)($_GET['epss_min'] ?? '')),
                    'group'       => (int)($_GET['group'] ?? 0),
                    'software_id' => (int)($_GET['software_id'] ?? 0),
                    'mine'        => !empty($_GET['mine']),
                    'sort'        => trim((string)($_GET['sort'] ?? 'published')),
                ];
                $softwareOptions = $this->listSoftware(0, '');
                $catalogPage = max(1, (int)($_GET['page'] ?? 1));
                $catalogResult = $this->listCatalog($catalogFilters, $catalogPage);
                $catalog = $catalogResult['data'];
                $catalogTotal = $catalogResult['total'];
                $catalogPages = $catalogResult['totalPages'];
                $cveSync = new CveSync();
                $syncState = $cveSync->publicState($cveSync->state());
            }
            $stats = $this->stats();

            if ($isAdmin) {
                if (array_key_exists('new_software', $_GET)) {
                    $editSoftware = [];
                } elseif (!empty($_GET['edit_software'])) {
                    $editSoftware = $this->getSoftware((int)$_GET['edit_software']);
                }
                if (array_key_exists('new_group', $_GET)) {
                    $editGroup = [];
                } elseif (!empty($_GET['edit_group'])) {
                    $editGroup = $this->getGroup((int)$_GET['edit_group']);
                }
            }
        } catch (Throwable $e) {
            $dbError = $e->getMessage();
        }

        echo $this->page('index', [
            'isAdmin'       => $isAdmin,
            'tab'           => $tab,
            'groups'        => $groups,
            'software'      => $software,
            'reports'       => $reports,
            'aiReports'     => $aiReports,
            'llmProfiles'   => $llmProfiles,
            'llmConfigured' => $llmConfigured,
            'stats'         => $stats,
            'selectedGroup' => $selectedGroup,
            'q'             => $q,
            'editSoftware'  => $editSoftware,
            'editGroup'     => $editGroup,
            'dbError'       => $dbError,
            'catalog'       => $catalog,
            'catalogTotal'  => $catalogTotal,
            'catalogPage'   => $catalogPage,
            'catalogPages'  => $catalogPages,
            'catalogFilters'=> $catalogFilters,
            'softwareOptions'=> $softwareOptions,
            'syncState'     => $syncState,
        ]);
    }

    // ============================================================
    // CRUD grupos
    // ============================================================

    public function saveGroup(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        $name = trim((string)($_POST['name'] ?? ''));
        $parentId = (int)($_POST['parent_id'] ?? 0);
        $position = (int)($_POST['position'] ?? 0);

        if ($name === '') {
            flash('error', 'El nombre del grupo es obligatorio.');
            redirect(base_url('modules/cve?tab=software'));
        }
        if ($this->textLength($name) > 120) {
            flash('error', 'El nombre del grupo es demasiado largo (máximo 120 caracteres).');
            redirect(base_url('modules/cve?tab=software'));
        }

        if ($parentId > 0) {
            if ($parentId === $id) {
                flash('error', 'Un grupo no puede ser su propio padre.');
                redirect(base_url('modules/cve?tab=software'));
            }
            if ($this->getGroup($parentId) === null) {
                flash('error', 'El grupo padre no existe.');
                redirect(base_url('modules/cve?tab=software'));
            }
            if ($id > 0 && in_array($parentId, $this->descendantGroupIds($id), true)) {
                flash('error', 'No se puede mover un grupo dentro de uno de sus descendientes.');
                redirect(base_url('modules/cve?tab=software'));
            }
        }

        try {
            if ($id > 0) {
                CveDatabase::update(
                    "UPDATE software_groups SET name = ?, parent_id = ?, position = ?, updated_at = datetime('now') WHERE id = ?",
                    [$name, $parentId > 0 ? $parentId : null, $position, $id]
                );
                flash('success', 'Grupo actualizado.');
            } else {
                $id = CveDatabase::insert(
                    "INSERT INTO software_groups (name, parent_id, position) VALUES (?, ?, ?)",
                    [$name, $parentId > 0 ? $parentId : null, $position]
                );
                flash('success', 'Grupo creado.');
            }
            log_activity('cve.group_saved', ['id' => $id, 'name' => $name, 'parent_id' => $parentId]);
        } catch (Throwable $e) {
            flash('error', 'No se pudo guardar el grupo: ' . $e->getMessage());
        }

        redirect(base_url('modules/cve?tab=software'));
    }

    public function deleteGroup(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            try {
                CveDatabase::query("DELETE FROM software_groups WHERE id = ?", [$id]);
                log_activity('cve.group_deleted', ['id' => $id]);
                flash('success', 'Grupo eliminado. Sus subgrupos y software quedan sin grupo.');
            } catch (Throwable $e) {
                flash('error', 'No se pudo eliminar el grupo: ' . $e->getMessage());
            }
        }
        redirect(base_url('modules/cve?tab=software'));
    }

    // ============================================================
    // CRUD software
    // ============================================================

    public function saveSoftware(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        $name = trim((string)($_POST['name'] ?? ''));
        $groupId = (int)($_POST['group_id'] ?? 0);
        $vendor = trim((string)($_POST['vendor'] ?? ''));
        $product = trim((string)($_POST['product'] ?? ''));
        $version = trim((string)($_POST['version'] ?? ''));
        $environment = trim((string)($_POST['environment'] ?? ''));
        $criticality = strtolower(trim((string)($_POST['criticality'] ?? 'medium')));
        $assetCountRaw = trim((string)($_POST['asset_count'] ?? ''));
        $assetCount = $assetCountRaw === '' ? null : max(0, (int)$assetCountRaw);
        $notes = trim((string)($_POST['notes'] ?? ''));
        $cpeList = trim((string)($_POST['cpe_list'] ?? $_POST['cpe_name'] ?? ''));
        $cpes = [];
        foreach (preg_split('/\r\n|\r|\n/', $cpeList) ?: [] as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            if (!str_starts_with($line, 'cpe:2.3:')) {
                flash('error', 'Cada CPE debe empezar por cpe:2.3: (por ejemplo, cpe:2.3:a:google:chrome).');
                redirect(base_url('modules/cve?tab=software'));
            }
            $cpes[$line] = true;
        }
        $cpes = array_keys($cpes);

        $allowedCriticality = ['critical', 'high', 'medium', 'low', 'info'];
        if (!in_array($criticality, $allowedCriticality, true)) {
            $criticality = 'medium';
        }

        if ($name === '') {
            flash('error', 'El nombre del software es obligatorio.');
            redirect(base_url('modules/cve?tab=software'));
        }
        if ($this->textLength($name) > 160 || $this->textLength($vendor) > 120 || $this->textLength($product) > 120) {
            flash('error', 'Nombre, vendor o producto demasiado largos.');
            redirect(base_url('modules/cve?tab=software'));
        }
        if ($version === '') {
            $version = '';
        }
        if ($groupId > 0 && $this->getGroup($groupId) === null) {
            flash('error', 'El grupo seleccionado no existe.');
            redirect(base_url('modules/cve?tab=software'));
        }

        $oldSoftware = $id > 0 ? $this->getSoftware($id) : null;
        $cpeChanged = $id === 0
            || (string)($oldSoftware['cpe_list'] ?? '') !== implode("\n", $cpes)
            || (string)($oldSoftware['version'] ?? '') !== $version;

        $syncActive = false;
        try {
            $syncActive = !empty((new CveSync())->activeStatus()['active']);
        } catch (Throwable $e) {
            // Si no se puede consultar, asumimos que no hay sync activa.
        }
        $deleteMatches = $cpeChanged && !$syncActive;

        try {
            $savedId = CveDatabase::transaction(function (PDO $db) use (
                $id, $name, $groupId, $vendor, $product, $version, $environment,
                $criticality, $assetCount, $notes, $cpes, $deleteMatches
            ): int {
                if ($id > 0) {
                    $stmt = $db->prepare(
                        "UPDATE software_watchlist
                         SET group_id = ?, name = ?, vendor = ?, product = ?, version = ?,
                             environment = ?, criticality = ?, asset_count = ?, notes = ?,
                             updated_at = datetime('now')
                         WHERE id = ?"
                    );
                    $stmt->execute([
                        $groupId > 0 ? $groupId : null,
                        $name,
                        $vendor !== '' ? $vendor : null,
                        $product !== '' ? $product : null,
                        $version,
                        $environment,
                        $criticality,
                        $assetCount,
                        $notes !== '' ? $notes : null,
                        $id,
                    ]);
                    $savedId = $id;
                } else {
                    $stmt = $db->prepare(
                        "INSERT INTO software_watchlist
                         (group_id, name, vendor, product, version, environment, criticality, asset_count, notes)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    );
                    $stmt->execute([
                        $groupId > 0 ? $groupId : null,
                        $name,
                        $vendor !== '' ? $vendor : null,
                        $product !== '' ? $product : null,
                        $version,
                        $environment,
                        $criticality,
                        $assetCount,
                        $notes !== '' ? $notes : null,
                    ]);
                    $savedId = (int)$db->lastInsertId();
                }

                if ($deleteMatches) {
                    $db->prepare("DELETE FROM cve_watchlist_match WHERE watchlist_id = ?")->execute([$savedId]);
                }

                // Varios CPE por software: el primero es el principal.
                $del = $db->prepare("DELETE FROM software_cpe WHERE watchlist_id = ?");
                $del->execute([$savedId]);
                $ins = $db->prepare("INSERT OR IGNORE INTO software_cpe (watchlist_id, cpe_name, is_primary) VALUES (?, ?, ?)");
                foreach (array_values($cpes) as $i => $cpeName) {
                    $ins->execute([$savedId, $cpeName, $i === 0 ? 1 : 0]);
                }

                return $savedId;
            });

            log_activity('cve.software_saved', ['id' => $savedId, 'name' => $name, 'group_id' => $groupId]);
            $message = $id > 0 ? 'Software actualizado.' : 'Software añadido al inventario.';
            if ($cpeChanged && !empty($cpes)) {
                try {
                    $backfill = (new CveSync())->startBackfill($savedId);
                    if (!empty($backfill['success'])) {
                        if (!empty($backfill['worker_started'])) {
                            $message .= ' Backfill iniciado en segundo plano.';
                        } else {
                            flash('warning', $backfill['message'] ?? 'Backfill preparado; usa «Continuar».');
                        }
                    } else {
                        flash('warning', 'Software guardado, pero no se pudo iniciar el backfill: '
                            . ($backfill['error'] ?? 'error desconocido')
                            . ' Puedes usar «Sincronizar» en la fila del software.');
                    }
                } catch (Throwable $e) {
                    flash('warning', 'Software guardado, pero no se pudo iniciar el backfill: ' . $e->getMessage());
                }
            }
            flash('success', $message);
        } catch (Throwable $e) {
            $msg = $e->getMessage();
            if (str_contains($msg, 'UNIQUE constraint failed')) {
                $msg = 'Ya existe un software con ese nombre, versión y entorno.';
            }
            flash('error', 'No se pudo guardar el software: ' . $msg);
        }

        redirect(base_url('modules/cve?tab=software'));
    }

    public function deleteSoftware(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            try {
                CveDatabase::query("DELETE FROM software_watchlist WHERE id = ?", [$id]);
                log_activity('cve.software_deleted', ['id' => $id]);
                flash('success', 'Software eliminado del inventario.');
            } catch (Throwable $e) {
                flash('error', 'No se pudo eliminar el software: ' . $e->getMessage());
            }
        }
        redirect(base_url('modules/cve?tab=software'));
    }

    /**
     * Backfill manual de un producto (también se lanza al guardar CPE/versión).
     */
    public function backfillSoftware(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            try {
                $result = (new CveSync())->startBackfill($id);
                if (!empty($result['success'])) {
                    if (!empty($result['worker_started'])) {
                        flash('success', $result['message'] ?? 'Backfill iniciado.');
                    } else {
                        flash('warning', $result['message'] ?? 'Backfill preparado; usa «Continuar».');
                    }
                } else {
                    flash('error', $result['error'] ?? 'No se pudo iniciar el backfill.');
                }
            } catch (Throwable $e) {
                flash('error', 'No se pudo iniciar el backfill: ' . $e->getMessage());
            }
        }
        redirect(base_url('modules/cve?tab=software'));
    }

    // ============================================================
    // Catálogo
    // ============================================================

    public function detail(array $params = []): void
    {
        Auth::require();

        $cveId = strtoupper(rawurldecode((string)($params['cveId'] ?? '')));
        $valid = (bool)preg_match('/^CVE-\d{4}-\d{4,}$/', $cveId);
        $cve = $valid ? $this->getCatalogCve($cveId) : null;

        $products = [];
        $references = [];
        $cwes = [];
        $kev = null;
        $epss = null;

        if ($cve !== null) {
            $products = CveDatabase::fetchAll(
                "SELECT vendor, product FROM cve_product WHERE cve_id = ? ORDER BY vendor ASC, product ASC",
                [$cveId]
            );
            $references = safe_json_decode($cve['references_json'] ?? '[]', []);
            $cwes = safe_json_decode($cve['cwe_ids'] ?? '[]', []);
            $kev = CveDatabase::fetchOne("SELECT * FROM cve_kev WHERE cve_id = ?", [$cveId]);
            $epss = CveDatabase::fetchOne("SELECT * FROM cve_epss WHERE cve_id = ?", [$cveId]);
        }

        http_response_code($cve !== null ? 200 : 404);

        echo $this->page('detail', [
            'cveId'      => $cveId,
            'cve'        => $cve,
            'products'   => $products,
            'references' => is_array($references) ? $references : [],
            'cwes'       => is_array($cwes) ? $cwes : [],
            'kev'        => $kev,
            'epss'       => $epss,
        ]);
    }

    // ============================================================
    // Sincronización NVD
    // ============================================================

    public function triggerSync(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;
            $mode = null;
            if (is_array($input) && isset($input['mode'])) {
                $mode = (string)$input['mode'];
            } elseif (isset($_POST['mode'])) {
                $mode = (string)$_POST['mode'];
            }
            // stream=1: el propio navegador procesará los tramos (descarga
            // continua); no lanzamos el worker HTTP para evitar dos procesos
            // compitiendo por el mismo token.
            $stream = (is_array($input) && !empty($input['stream'])) || !empty($_POST['stream']);
            json_response((new CveSync())->start($mode, !$stream));
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Descarga continua por web (sin cron ni loopback).
     *
     * Emite NDJSON con el progreso y procesa tramos hasta que el job termina
     * o se agota la ventana de esta petición (~45 s). Si el hosting corta la
     * conexión, el navegador reconecta y el job sigue desde el último cursor.
     */
    public function streamSync(array $params = []): void
    {
        // Autenticación propia para poder responder NDJSON (y 401) en vez de
        // una redirección HTML si la sesión caduca a mitad de la descarga.
        if (!Auth::check() || !Auth::isAdmin()) {
            $this->ndjsonStart();
            http_response_code(401);
            $this->ndjsonEmit(['type' => 'error', 'error' => 'Sesión expirada. Vuelve a iniciar sesión.']);
            exit;
        }
        Csrf::validateOrFail();
        @set_time_limit(0);
        release_session_lock();

        $sync = new CveSync();
        $state = $sync->state();

        $seconds = (int)($_GET['seconds'] ?? $_POST['seconds'] ?? CVE_STEP_SECONDS);
        $seconds = max(10, min((int)CVE_STEP_SECONDS_MAX, $seconds));

        $this->ndjsonStart();

        if (
            !$state
            || !in_array((string)($state['status'] ?? ''), ['queued', 'running'], true)
            || empty($state['token'])
        ) {
            $this->ndjsonEmit([
                'type'  => 'idle',
                'state' => $sync->publicState($state),
            ]);
            exit;
        }

        $token = (string)$state['token'];
        $this->ndjsonEmit(['type' => 'start', 'state' => $sync->publicState($state)]);

        $deadline = microtime(true) + $seconds;
        $emittedError = false;

        try {
            while (microtime(true) < $deadline) {
                $remaining = max(1.0, $deadline - microtime(true));
                $chunk = $sync->runChunk(
                    $token,
                    $remaining,
                    function (array $payload) use (&$emittedError): void {
                        if (($payload['type'] ?? '') === 'error') {
                            $emittedError = true;
                        }
                        $this->ndjsonEmit($payload);
                    }
                );

                if (!empty($chunk['error'])) {
                    if (!$emittedError) {
                        $this->ndjsonEmit([
                            'type'     => 'error',
                            'error'    => (string)$chunk['error'],
                            'error_id' => (int)($chunk['error_id'] ?? 0),
                        ]);
                    }
                    exit;
                }

                if (!empty($chunk['done'])) {
                    $fresh = $sync->state();
                    $this->ndjsonEmit([
                        'type'   => 'done',
                        'state'  => $sync->publicState($fresh),
                        'counts' => $sync->counts(),
                    ]);
                    exit;
                }

                $fresh = $sync->state();
                if ($fresh === null || !hash_equals((string)($fresh['token'] ?? ''), $token)) {
                    $this->ndjsonEmit(['type' => 'done', 'state' => $sync->publicState($fresh)]);
                    exit;
                }
            }

            $this->ndjsonEmit([
                'type'            => 'partial',
                'state'           => $sync->publicState($sync->state()),
                'resume_after_ms' => 200,
            ]);
            exit;
        } catch (Throwable $e) {
            $this->ndjsonEmit(['type' => 'error', 'error' => $e->getMessage()]);
            exit;
        }
    }

    private function ndjsonStart(): void
    {
        header('Content-Type: application/x-ndjson; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('X-Accel-Buffering: no');
        @ini_set('zlib.output_compression', '0');
        @ini_set('output_buffering', '0');
        @ini_set('implicit_flush', '1');
        while (ob_get_level() > 0) {
            @ob_end_flush();
        }
        @ob_implicit_flush(true);
    }

    private function ndjsonEmit(array $payload): void
    {
        echo json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
        ) . "\n";
        @flush();
    }

    public function syncStatus(array $params = []): void
    {
        Auth::require();

        try {
            json_response((new CveSync())->status());
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Endpoint ligero para el badge global (sin contadores).
     */
    public function syncActive(array $params = []): void
    {
        Auth::require();

        try {
            json_response((new CveSync())->activeStatus());
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Busca CPE en NVD para el formulario de software.
     */
    public function cpeSearch(array $params = []): void
    {
        Auth::requireAdmin();

        $q = trim((string)($_GET['q'] ?? ''));
        if ($this->textLength($q) < 2) {
            json_response(['success' => true, 'results' => []]);
        }

        try {
            $results = CveClient::fromSettings()->searchCpes($q, 20);
            json_response(['success' => true, 'results' => $results]);
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage(), 'results' => []]);
        }
    }

    public function cancelSync(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            json_response((new CveSync())->cancel());
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Fallback manual cuando el hosting no permite el loopback del worker.
     */
    public function stepSync(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();
        @set_time_limit(0);
        release_session_lock();

        try {
            $raw = file_get_contents('php://input');
            $input = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;
            $seconds = 0;
            if (is_array($input) && isset($input['seconds'])) {
                $seconds = (int)$input['seconds'];
            } elseif (isset($_POST['seconds'])) {
                $seconds = (int)$_POST['seconds'];
            }

            $sync = new CveSync();
            $state = $sync->state();
            if (!$state || !in_array((string)$state['status'], ['queued', 'running'], true) || empty($state['token'])) {
                json_response(['success' => false, 'error' => 'No hay una sincronización activa.']);
            }

            $token = (string)$state['token'];
            $result = null;

            if ($seconds > 0) {
                // Varios tramos en la misma petición (respaldo sin streaming).
                $deadline = microtime(true) + max(5, min((int)CVE_STEP_SECONDS_MAX, $seconds));
                do {
                    $result = $sync->runChunk($token, max(1.0, $deadline - microtime(true)));
                    if (!empty($result['done']) || !empty($result['error'])) {
                        break;
                    }
                    $state = $sync->state();
                } while (
                    microtime(true) < $deadline
                    && $state !== null
                    && in_array((string)($state['status'] ?? ''), ['queued', 'running'], true)
                    && hash_equals((string)($state['token'] ?? ''), $token)
                );
            } else {
                $result = $sync->runChunk($token);
            }

            $result = is_array($result) ? $result : ['done' => false];
            unset($result['token'], $result['base_url']);
            if (isset($result['state']) && is_array($result['state'])) {
                $result['state'] = $sync->publicState($result['state']);
            }
            json_response([
                'success' => empty($result['error']),
                'result'  => $result,
                'error'   => $result['error'] ?? null,
                'error_id'=> $result['error_id'] ?? 0,
            ]);
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    // ============================================================
    // Informes
    // ============================================================

    public function generateReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = json_decode((string)$raw, true);
            if (!is_array($input)) {
                $input = $_POST;
            }
            json_response($this->createReport($input));
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 400);
        }
    }

    public function reportView(array $params = []): void
    {
        Auth::require();

        $id = (int)($params['id'] ?? 0);
        $report = $id > 0 ? $this->getReport($id) : null;
        if ($report === null) {
            http_response_code(404);
        }

        $data = is_array($report['data'] ?? null) ? $report['data'] : [];
        $summary = is_array($report['summary'] ?? null) ? $report['summary'] : [];

        echo $this->page('report', [
            'report'  => $report,
            'data'    => $data,
            'summary' => $summary,
        ]);
    }

    public function reportCsv(array $params = []): void
    {
        Auth::require();

        $id = (int)($params['id'] ?? 0);
        $report = $id > 0 ? $this->getReport($id) : null;
        if ($report === null || !is_array($report['data'] ?? null)) {
            http_response_code(404);
            echo 'Informe no encontrado.';
            return;
        }

        $filename = 'cve-report-' . $id . '-' . date('Ymd-His') . '.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Cache-Control: no-store, no-cache, must-revalidate');

        $out = fopen('php://output', 'w');
        if ($out === false) {
            return;
        }
        fwrite($out, "\xEF\xBB\xBF");
        fputcsv($out, [
            'Grupo', 'Software', 'Versión', 'Entorno', 'Criticidad', 'Activos',
            'CVE', 'Severidad', 'CVSS', 'EPSS', 'Percentil EPSS',
            'KEV', 'Fecha KEV', 'Vencimiento KEV', 'Ransomware',
            'Publicado', 'Primera detección', 'Coincidencia', 'CPE',
            'Versiones afectadas', 'Descripción', 'Acción requerida', 'URL NVD',
        ], ',', '"', '');

        $softwareSections = is_array($report['data']['software'] ?? null) ? $report['data']['software'] : [];
        foreach ($softwareSections as $section) {
            $affected = is_array($section['cves'] ?? null) ? $section['cves'] : [];
            foreach ($affected as $cve) {
                $versions = is_array($cve['affected_versions'] ?? null) ? $cve['affected_versions'] : [];
                $row = [
                    (string)($section['group'] ?? ''),
                    (string)($section['name'] ?? ''),
                    (string)($section['version'] ?? ''),
                    (string)($section['environment'] ?? ''),
                    (string)($section['criticality'] ?? ''),
                    ($section['asset_count'] ?? null) !== null ? (string)$section['asset_count'] : '',
                    (string)($cve['cve_id'] ?? ''),
                    (string)($cve['severity'] ?? ''),
                    ($cve['cvss'] ?? null) !== null ? (string)$cve['cvss'] : '',
                    ($cve['epss'] ?? null) !== null ? (string)$cve['epss'] : '',
                    ($cve['percentile'] ?? null) !== null ? (string)$cve['percentile'] : '',
                    !empty($cve['kev']) ? 'Sí' : 'No',
                    (string)($cve['kev_date'] ?? ''),
                    (string)($cve['kev_due'] ?? ''),
                    (string)($cve['kev_ransomware'] ?? ''),
                    (string)($cve['published_at'] ?? ''),
                    (string)($cve['first_seen_at'] ?? ''),
                    (string)($cve['version_match'] ?? ''),
                    (string)($cve['matched_cpe'] ?? ''),
                    implode('; ', array_map('strval', $versions)),
                    (string)($cve['description'] ?? ''),
                    (string)($cve['kev_action'] ?? ''),
                    (string)($cve['nvd_url'] ?? ''),
                ];
                fputcsv($out, array_map([$this, 'csvSafe'], $row), ',', '"', '');
            }
        }

        fclose($out);
        exit;
    }

    public function createScheduledReport(array $input): array
    {
        return $this->createReport($input, null);
    }

    // ============================================================
    // Informes de CVE con IA (formato SploitScan)
    // ============================================================

    public function startAiReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = json_decode((string)$raw, true);
            if (!is_array($input)) {
                $input = $_POST;
            }

            $ids = CveReportAi::normalizeCveIds($input['cve_ids'] ?? '');
            if ($ids === []) {
                json_response([
                    'success' => false,
                    'error'   => 'Introduce al menos un CVE válido con formato CVE-AAAA-NNNN.',
                ], 400);
            }

            $found = [];
            $missing = [];
            foreach ($ids as $cveId) {
                $row = CveDatabase::fetchOne("SELECT cve_id FROM cve_catalog WHERE cve_id = ?", [$cveId]);
                if ($row === null) {
                    $missing[] = $cveId;
                } else {
                    $found[] = $cveId;
                }
            }
            if ($missing !== []) {
                json_response([
                    'success' => false,
                    'error'   => 'No están en el catálogo local: ' . implode(', ', $missing)
                        . '. Sincroniza el catálogo NVD o revisa los identificadores.',
                ], 400);
            }

            $noAi = !empty($input['no_ai']);
            $profileId = (int)($input['profile_id'] ?? 0);
            if ($profileId <= 0) {
                $profileId = (int)(llm_task_profile('cve_report') ?? 0);
            }
            if (!$noAi) {
                $llm = class_exists('Module_Llm') ? new Module_Llm() : null;
                if ($llm === null || !$llm->isConfigured($profileId > 0 ? $profileId : null)) {
                    json_response([
                        'success' => false,
                        'error'   => 'La IA no está configurada. Añade un perfil en Admin → APIs o marca «Solo datos locales».',
                    ], 400);
                }
            }

            $result = $this->queueAiReport($found, $profileId, $noAi);
            app_log('info', 'cve_ai', 'Informe IA creado', [
                'id'     => (int)$result['report_id'],
                'cves'   => $found,
                'no_ai'  => $noAi,
                'profile'=> $profileId,
            ]);
            log_activity('cve.ai_report_created', [
                'report_id' => (int)$result['report_id'],
                'cves'      => $found,
            ]);
            json_response($result);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error creando el informe', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 400);
        }
    }

    /**
     * Ejecuta el informe en la propia petición HTTP (sin worker ni loopback).
     * El navegador espera la respuesta y, si el proxy la corta, el trabajo
     * continúa gracias a ignore_user_abort() y el JS cae a polling.
     */
    public function runAiReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($params['id'] ?? 0);
        if ($id <= 0) {
            json_response(['success' => false, 'error' => 'Informe no válido.'], 400);
        }

        // La llamada a la IA puede tardar: liberar la sesión y ampliar el límite.
        if (function_exists('release_session_lock')) {
            release_session_lock();
        }
        @set_time_limit(0);
        @ignore_user_abort(true);

        try {
            $result = CveReportAi::runById($id);
            $result['url'] = base_url('modules/cve/report-ai/' . $id);
            json_response($result);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error ejecutando el informe', ['id' => $id, 'error' => $e->getMessage()]);
            json_response([
                'success' => false,
                'id'      => $id,
                'status'  => 'error',
                'error'   => $e->getMessage(),
                'url'     => base_url('modules/cve/report-ai/' . $id),
            ], 500);
        }
    }

    public function retryAiReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $id = (int)($params['id'] ?? 0);
            $row = $id > 0 ? CveDatabase::fetchOne("SELECT * FROM cve_ai_reports WHERE id = ?", [$id]) : null;
            if ($row === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            $ids = safe_json_decode((string)($row['cve_ids'] ?? ''), []);
            if (!is_array($ids) || $ids === []) {
                json_response(['success' => false, 'error' => 'El informe no tiene CVEs válidos.'], 400);
            }

            $token = bin2hex(random_bytes(24));
            CveDatabase::update(
                "UPDATE cve_ai_reports
                 SET status = 'pending', token = ?, ai_error = NULL, finished_at = NULL, started_at = NULL
                 WHERE id = ?",
                [$token, $id]
            );
            app_log('info', 'cve_ai', 'Informe reencolado', ['id' => $id]);

            json_response([
                'success'   => true,
                'report_id' => $id,
                'status'    => 'pending',
                'url'       => base_url('modules/cve/report-ai/' . $id),
            ]);
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 400);
        }
    }

    public function aiReportStatus(array $params = []): void
    {
        // Nunca redirigir a HTML: el cliente espera JSON.
        if (!Auth::check()) {
            json_response(['success' => false, 'error' => 'Sesión caducada. Recarga la página.'], 401);
        }

        try {
            $id = (int)($params['id'] ?? 0);
            $row = $id > 0
                ? CveDatabase::fetchOne(
                    "SELECT id, status, ai_error, created_at, started_at FROM cve_ai_reports WHERE id = ?",
                    [$id]
                )
                : null;
            if ($row === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            // Autosalud: un informe «running» atascado no debe quedarse eterno.
            if ((string)$row['status'] === 'running') {
                $ref = (string)($row['started_at'] ?? '');
                if ($ref === '') {
                    $ref = (string)($row['created_at'] ?? '');
                }
                $started = strtotime(str_contains($ref, 'Z') ? $ref : $ref . ' UTC');
                if ($started !== false && (time() - $started) > 1800) {
                    $message = 'La generación no terminó a tiempo (30 minutos). Puedes reintentarlo.';
                    CveDatabase::query(
                        "UPDATE cve_ai_reports
                         SET status = 'error', ai_error = ?, token = NULL, finished_at = datetime('now')
                         WHERE id = ? AND status = 'running'",
                        [$message, $id]
                    );
                    $row['status'] = 'error';
                    $row['ai_error'] = $message;
                }
            }

            json_response([
                'success'   => true,
                'report_id' => $id,
                'status'    => (string)$row['status'],
                'error'     => (string)($row['ai_error'] ?? ''),
                'url'       => base_url('modules/cve/report-ai/' . $id),
            ]);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error consultando el estado', [
                'id'    => $params['id'] ?? null,
                'error' => $e->getMessage(),
            ]);
            json_response(['success' => false, 'error' => 'Error interno: ' . $e->getMessage()], 500);
        }
    }

    public function aiReportView(array $params = []): void
    {
        Auth::require();

        $id = (int)($params['id'] ?? 0);
        $report = $id > 0 ? CveDatabase::fetchOne("SELECT * FROM cve_ai_reports WHERE id = ?", [$id]) : null;
        if ($report === null) {
            http_response_code(404);
        }

        echo $this->page('ai_report', [
            'report'   => $report,
            'profiles' => llm_profile_list(),
        ]);
    }

    public function aiReportTxt(array $params = []): void
    {
        Auth::require();

        $id = (int)($params['id'] ?? 0);
        $report = $id > 0
            ? CveDatabase::fetchOne("SELECT id, title, content_text FROM cve_ai_reports WHERE id = ?", [$id])
            : null;
        if ($report === null || trim((string)($report['content_text'] ?? '')) === '') {
            http_response_code(404);
            echo 'Informe no disponible.';
            return;
        }

        $filename = 'informe-cve-ia-' . $id . '-' . date('Ymd-His') . '.txt';
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Cache-Control: no-store, no-cache, must-revalidate');

        echo "\xEF\xBB\xBF" . (string)$report['content_text'];
        exit;
    }

    /**
     * Crea el informe en estado «pending». La ejecución la lanza el navegador
     * contra reports/ai-run/{id} (sin loopback ni worker).
     */
    private function queueAiReport(array $cveIds, int $profileId, bool $noAi = false): array
    {
        $token = bin2hex(random_bytes(24));
        $title = 'Informe CVE IA · '
            . (count($cveIds) === 1 ? $cveIds[0] : count($cveIds) . ' CVEs')
            . ' · ' . date('d/m/Y H:i');

        $id = CveDatabase::insert(
            "INSERT INTO cve_ai_reports (cve_ids, title, status, token, ai_profile_id, generated_by, no_ai)
             VALUES (?, ?, 'pending', ?, ?, ?, ?)",
            [
                $this->encodeJson($cveIds),
                $title,
                $token,
                $profileId > 0 ? $profileId : null,
                Auth::id(),
                $noAi ? 1 : 0,
            ]
        );

        return [
            'success'   => true,
            'report_id' => $id,
            'status'    => 'pending',
            'no_ai'     => $noAi,
            'url'       => base_url('modules/cve/report-ai/' . $id),
        ];
    }

    private function listAiReports(int $limit = 30): array
    {
        $limit = max(1, min(200, $limit));
        return CveDatabase::fetchAll(
            "SELECT id, cve_ids, title, status, ai_model, ai_error, no_ai, created_at, finished_at
             FROM cve_ai_reports
             ORDER BY created_at DESC, id DESC
             LIMIT ?",
            [$limit]
        );
    }

    private function createReport(array $input, ?int $generatedBy = null): array
    {
        $filters = $this->normalizeReportFilters($input);

        $scopeLabel = 'Todo el inventario';
        if ($filters['scope'] === 'group') {
            $group = $this->getGroup((int)$filters['group_id']);
            if ($group === null) {
                throw new RuntimeException('El grupo seleccionado no existe.');
            }
            $scopeLabel = 'Grupo: ' . (string)$group['name'];
        } elseif ($filters['scope'] === 'software') {
            $software = $this->getSoftware((int)$filters['software_id']);
            if ($software === null) {
                throw new RuntimeException('El software seleccionado no existe.');
            }
            $scopeLabel = trim((string)$software['name'] . ' ' . (string)($software['version'] ?? ''));
        }

        $period = $this->reportPeriod((string)$filters['period']);
        $data = $this->buildReportData($filters, $period);
        $title = 'Informe CVE · ' . $scopeLabel . ' · ' . $period['label'];

        $dataJson = $this->encodeJson($data);
        $summaryJson = $this->encodeJson($data['summary']);
        $filtersJson = $this->encodeJson($filters);

        $reportId = CveDatabase::insert(
            "INSERT INTO cve_reports
             (title, report_type, period_start, period_end, filters, summary_json, data, generated_by)
             VALUES (?, 'cve_software', ?, ?, ?, ?, ?, ?)",
            [
                $title,
                $period['start'],
                $period['end'],
                $filtersJson,
                $summaryJson,
                $dataJson,
                $generatedBy ?? Auth::id(),
            ]
        );

        return [
            'success'   => true,
            'report_id' => $reportId,
            'title'     => $title,
            'url'       => base_url('modules/cve/report/' . $reportId),
            'summary'   => $data['summary'],
        ];
    }

    private function buildReportData(array $filters, array $period): array
    {
        $where = ['1 = 1'];
        $params = [];

        if ($filters['scope'] === 'software' && (int)$filters['software_id'] > 0) {
            $where[] = 'w.id = ?';
            $params[] = (int)$filters['software_id'];
        } elseif ($filters['scope'] === 'group' && (int)$filters['group_id'] > 0) {
            $groupIds = $this->descendantGroupIds((int)$filters['group_id']);
            if (empty($groupIds)) {
                $where[] = '1 = 0';
            } else {
                $placeholders = implode(',', array_fill(0, count($groupIds), '?'));
                $where[] = "w.group_id IN ($placeholders)";
                foreach ($groupIds as $groupId) {
                    $params[] = $groupId;
                }
            }
        }

        if (!empty($filters['new_only']) && !empty($period['start'])) {
            $where[] = "(datetime(c.published_at) >= datetime(?) OR datetime(m.first_seen_at) >= datetime(?))";
            $params[] = $period['start'];
            $params[] = $period['start'];
        }
        if ((string)$filters['severity'] !== '') {
            $where[] = 'c.severity = ?';
            $params[] = (string)$filters['severity'];
        }
        if (!empty($filters['only_kev'])) {
            $where[] = 'k.cve_id IS NOT NULL';
        }
        if ($filters['epss_min'] !== null) {
            $where[] = 'e.epss >= ?';
            $params[] = (float)$filters['epss_min'];
        }

        $maxRows = defined('CVE_REPORT_MAX_ROWS') ? max(100, (int)CVE_REPORT_MAX_ROWS) : 5000;
        $whereSql = implode(' AND ', $where);
        $params[] = $maxRows + 1;

        $rows = CveDatabase::fetchAll(
            "SELECT w.id AS watchlist_id, w.name AS software_name, w.version, w.environment,
                    w.criticality, w.asset_count, g.name AS group_name,
                    c.cve_id, c.description, c.severity, c.cvss_v3_score, c.cvss_v2_score,
                    c.published_at, c.nvd_url,
                    k.cve_id AS kev_id, k.date_added AS kev_date, k.due_date AS kev_due,
                    k.known_ransomware, k.required_action,
                    e.epss, e.percentile,
                    m.version_match, m.matched_cpe, m.affected_versions, m.first_seen_at
             FROM software_watchlist w
             JOIN cve_watchlist_match m ON m.watchlist_id = w.id
             JOIN cve_catalog c ON c.cve_id = m.cve_id
             LEFT JOIN software_groups g ON g.id = w.group_id
             LEFT JOIN cve_kev k ON k.cve_id = m.cve_id
             LEFT JOIN cve_epss e ON e.cve_id = m.cve_id
             WHERE $whereSql
             ORDER BY w.name ASC, (k.cve_id IS NOT NULL) DESC, e.epss DESC,
                      COALESCE(c.cvss_v3_score, c.cvss_v2_score) DESC, c.cve_id ASC
             LIMIT ?",
            $params
        );

        $truncated = count($rows) > $maxRows;
        if ($truncated) {
            $rows = array_slice($rows, 0, $maxRows);
        }

        $sections = [];
        $uniqueCves = [];
        $uniqueKev = [];
        $uniqueEpssHigh = [];
        $uniqueCritical = [];
        $uniqueHigh = [];

        foreach ($rows as $row) {
            $watchlistId = (int)$row['watchlist_id'];
            if (!isset($sections[$watchlistId])) {
                $sections[$watchlistId] = [
                    'id'          => $watchlistId,
                    'name'        => (string)$row['software_name'],
                    'version'     => (string)($row['version'] ?? ''),
                    'environment' => (string)($row['environment'] ?? ''),
                    'criticality' => (string)($row['criticality'] ?? ''),
                    'asset_count' => $row['asset_count'] !== null ? (int)$row['asset_count'] : null,
                    'group'       => (string)($row['group_name'] ?? ''),
                    'counts'      => ['total' => 0, 'kev' => 0, 'epss_high' => 0, 'critical' => 0, 'high' => 0],
                    'cves'        => [],
                ];
            }

            $cveId = (string)$row['cve_id'];
            $isKev = !empty($row['kev_id']);
            $epss = $row['epss'] !== null ? (float)$row['epss'] : null;
            $cvss = $row['cvss_v3_score'] !== null
                ? (float)$row['cvss_v3_score']
                : ($row['cvss_v2_score'] !== null ? (float)$row['cvss_v2_score'] : null);
            $severity = (string)($row['severity'] ?? '');
            $isEpssHigh = $epss !== null && $epss >= 0.1;
            $affectedVersions = safe_json_decode($row['affected_versions'] ?? '[]', []);
            if (!is_array($affectedVersions)) {
                $affectedVersions = [];
            }
            $affectedVersions = array_values(array_filter(
                array_map(static fn($value): string => is_scalar($value) ? (string)$value : '', $affectedVersions),
                static fn(string $value): bool => $value !== ''
            ));
            $nvdUrl = (string)($row['nvd_url'] ?? '');
            if (!preg_match('#^https?://#i', $nvdUrl)) {
                $nvdUrl = 'https://nvd.nist.gov/vuln/detail/' . rawurlencode($cveId);
            }

            $sections[$watchlistId]['cves'][] = [
                'cve_id'            => $cveId,
                'description'       => (string)($row['description'] ?? ''),
                'severity'          => $severity,
                'cvss'              => $cvss,
                'epss'              => $epss,
                'percentile'        => $row['percentile'] !== null ? (float)$row['percentile'] : null,
                'kev'               => $isKev,
                'kev_date'          => $row['kev_date'] ?? null,
                'kev_due'           => $row['kev_due'] ?? null,
                'kev_ransomware'    => (string)($row['known_ransomware'] ?? ''),
                'kev_action'        => (string)($row['required_action'] ?? ''),
                'published_at'      => $row['published_at'] ?? null,
                'first_seen_at'     => $row['first_seen_at'] ?? null,
                'version_match'     => (string)($row['version_match'] ?? ''),
                'matched_cpe'       => (string)($row['matched_cpe'] ?? ''),
                'affected_versions' => $affectedVersions,
                'nvd_url'           => $nvdUrl,
            ];

            $sections[$watchlistId]['counts']['total']++;
            if ($isKev) {
                $sections[$watchlistId]['counts']['kev']++;
                $uniqueKev[$cveId] = true;
            }
            if ($isEpssHigh) {
                $sections[$watchlistId]['counts']['epss_high']++;
                $uniqueEpssHigh[$cveId] = true;
            }
            if (strcasecmp($severity, 'Critical') === 0) {
                $sections[$watchlistId]['counts']['critical']++;
                $uniqueCritical[$cveId] = true;
            } elseif (strcasecmp($severity, 'High') === 0) {
                $sections[$watchlistId]['counts']['high']++;
                $uniqueHigh[$cveId] = true;
            }
            $uniqueCves[$cveId] = true;
        }

        $sections = array_values($sections);
        usort($sections, static function (array $a, array $b): int {
            $cmp = $b['counts']['kev'] <=> $a['counts']['kev'];
            if ($cmp !== 0) return $cmp;
            $cmp = $b['counts']['epss_high'] <=> $a['counts']['epss_high'];
            if ($cmp !== 0) return $cmp;
            $cmp = $b['counts']['total'] <=> $a['counts']['total'];
            if ($cmp !== 0) return $cmp;
            return strcasecmp($a['name'] . ' ' . $a['version'], $b['name'] . ' ' . $b['version']);
        });

        $summary = [
            'unique_cves'   => count($uniqueCves),
            'total_rows'    => count($rows),
            'software_count'=> count($sections),
            'kev'           => count($uniqueKev),
            'epss_high'     => count($uniqueEpssHigh),
            'critical'      => count($uniqueCritical),
            'high'          => count($uniqueHigh),
            'truncated'     => $truncated,
            'max_rows'      => $maxRows,
        ];

        return [
            'summary'   => $summary,
            'software'  => $sections,
            'period'    => $period,
            'filters'   => $filters,
            'truncated' => $truncated,
            'max_rows'  => $maxRows,
        ];
    }

    private function normalizeReportFilters(array $input): array
    {
        $scope = (string)($input['scope'] ?? 'all');
        if (!in_array($scope, ['all', 'group', 'software'], true)) {
            $scope = 'all';
        }

        $period = (string)($input['period'] ?? '30d');
        if (!in_array($period, ['7d', '30d', '90d', 'all'], true)) {
            $period = '30d';
        }

        $severity = trim((string)($input['severity'] ?? ''));
        if (!in_array($severity, ['', 'Critical', 'High', 'Medium', 'Low', 'None'], true)) {
            $severity = '';
        }

        $epssMin = null;
        $epssRaw = trim((string)($input['epss_min'] ?? ''));
        if ($epssRaw !== '' && is_numeric($epssRaw)) {
            $epssMin = max(0.0, min(1.0, (float)$epssRaw));
        }

        return [
            'scope'       => $scope,
            'group_id'    => $scope === 'group' ? (int)($input['group_id'] ?? 0) : 0,
            'software_id' => $scope === 'software' ? (int)($input['software_id'] ?? 0) : 0,
            'period'      => $period,
            'new_only'    => !empty($input['new_only']) && $period !== 'all',
            'severity'    => $severity,
            'only_kev'    => !empty($input['only_kev']),
            'epss_min'    => $epssMin,
        ];
    }

    private function reportPeriod(string $period): array
    {
        $days = ['7d' => 7, '30d' => 30, '90d' => 90];
        $labels = ['7d' => 'Últimos 7 días', '30d' => 'Últimos 30 días', '90d' => 'Últimos 90 días', 'all' => 'Todo el histórico'];
        $end = gmdate('Y-m-d\TH:i:s\Z');
        $start = isset($days[$period]) ? gmdate('Y-m-d\TH:i:s\Z', time() - ($days[$period] * 86400)) : null;

        return [
            'type'  => $period,
            'start' => $start,
            'end'   => $end,
            'label' => $labels[$period] ?? $labels['30d'],
        ];
    }

    private function listReports(int $limit = 30): array
    {
        $limit = max(1, min(200, $limit));
        return CveDatabase::fetchAll(
            "SELECT id, title, report_type, period_start, period_end, summary_json, generated_by, generated_at
             FROM cve_reports
             ORDER BY generated_at DESC, id DESC
             LIMIT ?",
            [$limit]
        );
    }

    private function getReport(int $id): ?array
    {
        $row = CveDatabase::fetchOne("SELECT * FROM cve_reports WHERE id = ?", [$id]);
        if ($row === null) {
            return null;
        }
        $row['summary'] = safe_json_decode($row['summary_json'] ?? '{}', []);
        $row['filters'] = safe_json_decode($row['filters'] ?? '{}', []);
        $row['data'] = safe_json_decode($row['data'] ?? '{}', []);
        return $row;
    }

    private function encodeJson(mixed $value): string
    {
        $json = json_encode(
            $value,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );
        if ($json === false) {
            throw new RuntimeException('No se pudo serializar el informe.');
        }
        return $json;
    }

    private function csvSafe(string $value): string
    {
        $value = str_replace(["\r\n", "\r"], "\n", $value);
        if (preg_match('/^[=+\-@\t]/', $value)) {
            return "'" . $value;
        }
        return $value;
    }

    // ============================================================
    // Consultas internas
    // ============================================================

    private function emptyStats(): array
    {
        return [
            'groups'     => 0,
            'software'   => 0,
            'catalog'    => 0,
            'critical'   => 0,
            'high'       => 0,
            'products'   => 0,
            'kev'        => 0,
            'epss'       => 0,
            'epss_high'  => 0,
            'matches'    => 0,
            'matched_cves'=> 0,
            'my_kev'      => 0,
            'my_epss_high'=> 0,
            'db_size'    => 0,
            'last_sync'  => null,
        ];
    }

    private function stats(): array
    {
        $stats = $this->emptyStats();
        $stats['groups']   = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM software_groups")['c'] ?? 0);
        $stats['software'] = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM software_watchlist")['c'] ?? 0);
        $stats['catalog']  = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_catalog")['c'] ?? 0);
        $stats['critical'] = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_catalog WHERE severity = 'Critical'")['c'] ?? 0);
        $stats['high']     = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_catalog WHERE severity = 'High'")['c'] ?? 0);
        $stats['products'] = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_product")['c'] ?? 0);
        $stats['kev']      = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_kev")['c'] ?? 0);
        $stats['epss']     = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_epss")['c'] ?? 0);
        $stats['epss_high']= (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_epss e JOIN cve_catalog c ON c.cve_id = e.cve_id WHERE e.epss >= 0.1")['c'] ?? 0);
        $stats['matches']  = (int)(CveDatabase::fetchOne("SELECT COUNT(*) AS c FROM cve_watchlist_match")['c'] ?? 0);
        $stats['matched_cves'] = (int)(CveDatabase::fetchOne("SELECT COUNT(DISTINCT cve_id) AS c FROM cve_watchlist_match")['c'] ?? 0);
        $stats['my_kev'] = (int)(CveDatabase::fetchOne(
            "SELECT COUNT(DISTINCT m.cve_id) AS c FROM cve_watchlist_match m JOIN cve_kev k ON k.cve_id = m.cve_id"
        )['c'] ?? 0);
        $stats['my_epss_high'] = (int)(CveDatabase::fetchOne(
            "SELECT COUNT(DISTINCT m.cve_id) AS c FROM cve_watchlist_match m JOIN cve_epss e ON e.cve_id = m.cve_id WHERE e.epss >= 0.1"
        )['c'] ?? 0);
        $stats['db_size']  = is_file(CVE_DB_PATH) ? (int)filesize(CVE_DB_PATH) : 0;

        $state = CveDatabase::fetchOne("SELECT last_success_at, status, updated_at FROM cve_sync_state WHERE id = 1");
        $stats['last_sync'] = $state['last_success_at'] ?? null;
        $stats['sync_status'] = $state['status'] ?? 'idle';
        $stats['sync_updated'] = $state['updated_at'] ?? null;

        return $stats;
    }

    /**
     * Árbol plano de grupos con profundidad, para renderizar y para selects.
     */
    private function groupTree(): array
    {
        $rows = CveDatabase::fetchAll(
            "SELECT g.*, (SELECT COUNT(*) FROM software_watchlist w WHERE w.group_id = g.id) AS software_count
             FROM software_groups g
             ORDER BY g.position ASC, g.name ASC"
        );
        if (empty($rows)) {
            return [];
        }

        $byParent = [];
        foreach ($rows as $row) {
            $parent = (int)($row['parent_id'] ?? 0);
            $byParent[$parent][] = $row;
        }

        $out = [];
        $walk = function (int $parent, int $depth) use (&$walk, &$out, $byParent): void {
            foreach ($byParent[$parent] ?? [] as $row) {
                $row['depth'] = $depth;
                $out[] = $row;
                $walk((int)$row['id'], $depth + 1);
            }
        };
        $walk(0, 0);

        // Grupos huérfanos (padre borrado o datos importados): mostrarlos al final.
        if (count($out) < count($rows)) {
            $seen = [];
            foreach ($out as $row) {
                $seen[(int)$row['id']] = true;
            }
            foreach ($rows as $row) {
                if (!isset($seen[(int)$row['id']])) {
                    $row['depth'] = 0;
                    $out[] = $row;
                }
            }
        }

        return $out;
    }

    private function descendantGroupIds(int $groupId): array
    {
        if ($groupId <= 0) {
            return [];
        }
        $rows = CveDatabase::fetchAll(
            "WITH RECURSIVE grp(id) AS (
                SELECT id FROM software_groups WHERE id = ?
                UNION
                SELECT g.id FROM software_groups g JOIN grp ON g.parent_id = grp.id
             )
             SELECT id FROM grp",
            [$groupId]
        );
        return array_map(static fn(array $r): int => (int)$r['id'], $rows);
    }

    private function listSoftware(int $groupId, string $q): array
    {
        $where = [];
        $params = [];

        if ($groupId > 0) {
            $ids = $this->descendantGroupIds($groupId);
            if (empty($ids)) {
                return [];
            }
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $where[] = "w.group_id IN ($placeholders)";
            foreach ($ids as $id) {
                $params[] = $id;
            }
        }

        if ($q !== '') {
            $like = '%' . $q . '%';
            $where[] = '(w.name LIKE ? OR w.vendor LIKE ? OR w.product LIKE ? OR w.version LIKE ? OR c.cpe_name LIKE ?)';
            array_push($params, $like, $like, $like, $like, $like);
        }

        $whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

        return CveDatabase::fetchAll(
            "SELECT w.*, g.name AS group_name, c.cpe_name,
                    (SELECT COUNT(*) FROM software_cpe c2 WHERE c2.watchlist_id = w.id) AS cpe_count,
                    (SELECT COUNT(*) FROM cve_watchlist_match m2 WHERE m2.watchlist_id = w.id) AS match_count,
                    (SELECT COUNT(*) FROM cve_watchlist_match m3
                     JOIN cve_kev k3 ON k3.cve_id = m3.cve_id
                     WHERE m3.watchlist_id = w.id) AS kev_count,
                    (SELECT COUNT(*) FROM cve_watchlist_match m4
                     JOIN cve_epss e4 ON e4.cve_id = m4.cve_id
                     WHERE m4.watchlist_id = w.id AND e4.epss >= 0.1) AS epss_high_count
             FROM software_watchlist w
             LEFT JOIN software_groups g ON g.id = w.group_id
             LEFT JOIN software_cpe c ON c.watchlist_id = w.id AND c.is_primary = 1
             $whereSql
             ORDER BY kev_count DESC, epss_high_count DESC, match_count DESC, g.name ASC, w.name ASC, w.version ASC",
            $params
        );
    }

    private function listCatalog(array $filters, int $page, int $perPage = 50): array
    {
        $where = [];
        $params = [];

        $q = trim((string)($filters['q'] ?? ''));
        if ($q !== '') {
            $like = '%' . $q . '%';
            $where[] = '(c.cve_id LIKE ? OR c.description LIKE ?)';
            array_push($params, $like, $like);
        }

        $severity = trim((string)($filters['severity'] ?? ''));
        if ($severity !== '') {
            $where[] = 'c.severity = ?';
            $params[] = $severity;
        }

        $product = trim((string)($filters['product'] ?? ''));
        if ($product !== '') {
            $like = '%' . $product . '%';
            $where[] = 'EXISTS (SELECT 1 FROM cve_product p WHERE p.cve_id = c.cve_id AND (p.vendor LIKE ? OR p.product LIKE ?))';
            array_push($params, $like, $like);
        }

        if (!empty($filters['kev'])) {
            $where[] = 'k.cve_id IS NOT NULL';
        }

        $epssMin = trim((string)($filters['epss_min'] ?? ''));
        if ($epssMin !== '' && is_numeric($epssMin)) {
            $where[] = 'e.epss >= ?';
            $params[] = (float)$epssMin;
        }

        $softwareId = (int)($filters['software_id'] ?? 0);
        if ($softwareId > 0) {
            $where[] = 'EXISTS (SELECT 1 FROM cve_watchlist_match mw WHERE mw.cve_id = c.cve_id AND mw.watchlist_id = ?)';
            $params[] = $softwareId;
        }

        $groupId = (int)($filters['group'] ?? 0);
        if ($groupId > 0) {
            $groupIds = $this->descendantGroupIds($groupId);
            if (empty($groupIds)) {
                $where[] = '1 = 0';
            } else {
                $placeholders = implode(',', array_fill(0, count($groupIds), '?'));
                $where[] = "EXISTS (
                    SELECT 1 FROM cve_watchlist_match mw
                    JOIN software_watchlist sw ON sw.id = mw.watchlist_id
                    WHERE mw.cve_id = c.cve_id AND sw.group_id IN ($placeholders)
                )";
                foreach ($groupIds as $gid) {
                    $params[] = $gid;
                }
            }
        }

        if (!empty($filters['mine']) && $softwareId <= 0 && $groupId <= 0) {
            $where[] = 'EXISTS (SELECT 1 FROM cve_watchlist_match mw WHERE mw.cve_id = c.cve_id)';
        }

        $sort = (string)($filters['sort'] ?? 'published');
        $orderSql = match ($sort) {
            'cvss' => 'COALESCE(c.cvss_v3_score, c.cvss_v2_score) DESC, c.published_at DESC',
            'epss' => 'e.epss DESC, c.cvss_v3_score DESC, c.published_at DESC',
            'kev'  => '(k.cve_id IS NOT NULL) DESC, e.epss DESC, c.cvss_v3_score DESC, c.published_at DESC',
            default => 'c.published_at DESC, c.cve_id DESC',
        };

        $whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';
        $joins = "LEFT JOIN cve_kev k ON k.cve_id = c.cve_id
                  LEFT JOIN cve_epss e ON e.cve_id = c.cve_id";
        $total = (int)(CveDatabase::fetchOne(
            "SELECT COUNT(*) AS c FROM cve_catalog c $joins $whereSql",
            $params
        )['c'] ?? 0);

        $perPage = max(10, min(100, $perPage));
        $page = max(1, $page);
        $offset = ($page - 1) * $perPage;
        $params[] = $perPage;
        $params[] = $offset;

        $rows = CveDatabase::fetchAll(
            "SELECT c.*, k.cve_id AS kev_id, k.date_added AS kev_date,
                    k.known_ransomware AS kev_ransomware,
                    e.epss AS epss, e.percentile AS epss_percentile, e.score_date AS epss_date,
                    (SELECT GROUP_CONCAT(DISTINCT sw2.name)
                     FROM cve_watchlist_match mw2
                     JOIN software_watchlist sw2 ON sw2.id = mw2.watchlist_id
                     WHERE mw2.cve_id = c.cve_id) AS matched_software
             FROM cve_catalog c
             $joins
             $whereSql
             ORDER BY $orderSql
             LIMIT ? OFFSET ?",
            $params
        );

        return [
            'data'       => $rows,
            'total'      => $total,
            'page'       => $page,
            'perPage'    => $perPage,
            'totalPages' => (int)ceil($total / $perPage),
        ];
    }

    private function getCatalogCve(string $cveId): ?array
    {
        $row = CveDatabase::fetchOne("SELECT * FROM cve_catalog WHERE cve_id = ?", [$cveId]);
        return $row ?: null;
    }

    private function getSoftware(int $id): ?array
    {
        if ($id <= 0) {
            return null;
        }
        $row = CveDatabase::fetchOne(
            "SELECT w.*, c.cpe_name
             FROM software_watchlist w
             LEFT JOIN software_cpe c ON c.watchlist_id = w.id AND c.is_primary = 1
             WHERE w.id = ?",
            [$id]
        );
        if (!$row) {
            return null;
        }
        $cpes = CveDatabase::fetchAll(
            "SELECT cpe_name FROM software_cpe WHERE watchlist_id = ? ORDER BY is_primary DESC, id ASC",
            [$id]
        );
        $row['cpe_list'] = implode("\n", array_map(
            static fn(array $c): string => (string)$c['cpe_name'],
            $cpes
        ));
        return $row;
    }

    private function getGroup(int $id): ?array
    {
        if ($id <= 0) {
            return null;
        }
        $row = CveDatabase::fetchOne("SELECT * FROM software_groups WHERE id = ?", [$id]);
        return $row ?: null;
    }

    private function textLength(string $value): int
    {
        return function_exists('mb_strlen') ? mb_strlen($value) : strlen($value);
    }
}
