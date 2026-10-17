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
            ['method' => 'POST', 'pattern' => 'sync',            'handler' => [$this, 'triggerSync']],
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
        $tab = (($_GET['tab'] ?? 'catalog') === 'software') ? 'software' : 'catalog';
        $selectedGroup = (int)($_GET['group'] ?? 0);
        $q = trim((string)($_GET['q'] ?? ''));

        $groups = [];
        $software = [];
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
            $input = json_decode((string)$raw, true);
            $mode = null;
            if (is_array($input) && isset($input['mode'])) {
                $mode = (string)$input['mode'];
            } elseif (isset($_POST['mode'])) {
                $mode = (string)$_POST['mode'];
            }
            json_response((new CveSync())->start($mode));
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
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
            $sync = new CveSync();
            $state = $sync->state();
            if (!$state || !in_array((string)$state['status'], ['queued', 'running'], true) || empty($state['token'])) {
                json_response(['success' => false, 'error' => 'No hay una sincronización activa.']);
            }
            $result = $sync->runChunk((string)$state['token']);
            unset($result['token'], $result['base_url']);
            if (isset($result['state']) && is_array($result['state'])) {
                $result['state'] = $sync->publicState($result['state']);
            }
            json_response([
                'success' => empty($result['error']),
                'result'  => $result,
            ]);
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
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
