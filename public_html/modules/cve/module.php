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
            ['method' => 'GET',  'pattern' => 'detail/{cveId}/panel', 'handler' => [$this, 'detailPanel']],
            ['method' => 'GET',  'pattern' => 'detail/{cveId}',  'handler' => [$this, 'detail']],
            ['method' => 'POST', 'pattern' => 'exploits/refresh', 'handler' => [$this, 'refreshExploits']],
            ['method' => 'GET',  'pattern' => 'status',          'handler' => [$this, 'syncStatus']],
            ['method' => 'GET',  'pattern' => 'active',          'handler' => [$this, 'syncActive']],
            ['method' => 'GET',  'pattern' => 'cpe-search',      'handler' => [$this, 'cpeSearch']],
            ['method' => 'POST', 'pattern' => 'reports/generate', 'handler' => [$this, 'generateReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-start', 'handler' => [$this, 'startAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-run/{id}', 'handler' => [$this, 'runAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-cancel/{id}', 'handler' => [$this, 'cancelAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-delete/{id}', 'handler' => [$this, 'deleteAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-delete-bulk', 'handler' => [$this, 'deleteAiReportsBulk']],
            ['method' => 'POST', 'pattern' => 'reports/ai-assign-bulk', 'handler' => [$this, 'assignAiReportsBulk']],
            ['method' => 'POST', 'pattern' => 'reports/ai-split/{id}', 'handler' => [$this, 'splitAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-unassign-cve', 'handler' => [$this, 'unassignAiCve']],
            ['method' => 'POST', 'pattern' => 'reports/ai-generate', 'handler' => [$this, 'startAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-retry/{id}', 'handler' => [$this, 'retryAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-refresh/{id}', 'handler' => [$this, 'refreshAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-assign/{id}', 'handler' => [$this, 'assignAiReport']],
            ['method' => 'POST', 'pattern' => 'reports/ai-item-tags', 'handler' => [$this, 'updateAiItemTags']],
            ['method' => 'POST', 'pattern' => 'reports/ai-assign-items', 'handler' => [$this, 'assignAiReportItems']],
            ['method' => 'POST', 'pattern' => 'reports/ai-retry-item/{id}/{itemId}', 'handler' => [$this, 'retryAiReportItem']],
            ['method' => 'GET',  'pattern' => 'reports/ai-tag-suggestions', 'handler' => [$this, 'aiTagSuggestions']],
            ['method' => 'GET',  'pattern' => 'reports/defender-list', 'handler' => [$this, 'defenderList']],
            ['method' => 'POST', 'pattern' => 'reports/ai-start-defender', 'handler' => [$this, 'startAiReportDefender']],
            ['method' => 'POST', 'pattern' => 'reports/ai-scheduled-defender', 'handler' => [$this, 'runScheduledDefenderReport']],
            ['method' => 'GET',  'pattern' => 'reports/ai-status/{id}', 'handler' => [$this, 'aiReportStatus']],
            ['method' => 'GET',  'pattern' => 'report/{id}/csv',  'handler' => [$this, 'reportCsv']],
            ['method' => 'GET',  'pattern' => 'report-ai/{id}/panel', 'handler' => [$this, 'aiReportPanel']],
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
        $assignedCves = [];
        $reports = [];
        $aiReports = [];
        $selectedAiId = 0;
        $selectedAiData = null;
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
        $catalogFilters = ['q' => '', 'severity' => '', 'product' => '', 'kev' => false, 'epss_min' => '', 'group' => 0, 'software_id' => 0, 'mine' => false, 'sort' => 'published', 'cves' => ''];
        $cvesMissing = [];
        $softwareOptions = [];
        $syncState = null;
        $newCves = '';

        try {
            $groups = $this->groupTree();
            if ($tab === 'software') {
                $software = $this->listSoftware($selectedGroup, $q);
                $assignedCves = $this->listAssignedCves($selectedGroup);
            } elseif ($tab === 'reports') {
                $softwareOptions = $this->listSoftware(0, '');
                $reports = $this->listReports(30);
                $aiReports = $this->listAiReports(100);
                if (!$isAdmin) {
                    // Los informes con exposición de Defender solo los ve un admin.
                    $aiReports = array_values(array_filter(
                        $aiReports,
                        static fn(array $row): bool => empty($row['has_defender'])
                    ));
                }
                $llmProfiles = llm_profile_list();
                $llmConfigured = class_exists('Module_Llm') && (new Module_Llm())->isConfigured();
                // CVEs enviados desde Catálogo para abrir el formulario ya relleno.
                $newCves = $isAdmin
                    ? implode(',', CveReportAi::normalizeCveIds((string)($_GET['new_cves'] ?? '')))
                    : '';
                $selectedAiId = max(0, (int)($_GET['report'] ?? 0));
                if ($selectedAiId > 0) {
                    $selectedAiData = $this->aiReportPayload($selectedAiId);
                    if ($selectedAiData === null) {
                        $selectedAiId = 0;
                    }
                }
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
                    'cves'        => trim((string)($_GET['cves'] ?? '')),
                ];
                $softwareOptions = $this->listSoftware(0, '');
                $catalogPage = max(1, (int)($_GET['page'] ?? 1));
                // Con una lista pegada mostramos hasta 100 por página.
                $catalogResult = $this->listCatalog(
                    $catalogFilters,
                    $catalogPage,
                    $catalogFilters['cves'] !== '' ? 100 : 50
                );
                $catalog = $catalogResult['data'];
                $catalogTotal = $catalogResult['total'];
                $catalogPages = $catalogResult['totalPages'];
                $cvesMissing = $catalogResult['missing'] ?? [];
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
                    $kindParam = (string)($_GET['kind'] ?? 'application');
                    $editGroup['kind'] = $kindParam === 'company' ? 'company' : 'application';
                    $parentParam = (int)($_GET['parent'] ?? 0);
                    if ($parentParam > 0) {
                        $editGroup['parent_id'] = $parentParam;
                    }
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
            'assignedCves'  => $assignedCves,
            'reports'       => $reports,
            'aiReports'     => $aiReports,
            'selectedAiId'  => $selectedAiId,
            'selectedAiData'=> $selectedAiData,
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
            'cvesMissing'   => $cvesMissing,
            'newCves'       => $newCves,
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
        $kind = strtolower(trim((string)($_POST['kind'] ?? 'application')));
        $companyId = (int)($_POST['company_id'] ?? 0);

        $existingGroup = $id > 0 ? $this->getGroup($id) : null;
        if ($existingGroup !== null) {
            // El tipo se fija al crear: una empresa no se convierte en grupo
            // de aplicaciones (ni al contrario) para no romper asignaciones.
            $kind = (string)($existingGroup['kind'] ?? 'application');
        }
        if (!in_array($kind, ['company', 'application'], true)) {
            $kind = 'application';
        }

        if ($name === '') {
            flash('error', 'El nombre del grupo es obligatorio.');
            redirect(base_url('modules/cve?tab=software'));
        }
        if ($this->textLength($name) > 120) {
            flash('error', 'El nombre del grupo es demasiado largo (máximo 120 caracteres).');
            redirect(base_url('modules/cve?tab=software'));
        }

        if ($kind === 'company') {
            // Las empresas son una lista plana y no se vinculan a otra empresa.
            $parentId = 0;
            $companyId = 0;
        } else {
            if ($parentId > 0) {
                if ($parentId === $id) {
                    flash('error', 'Un grupo no puede ser su propio padre.');
                    redirect(base_url('modules/cve?tab=software'));
                }
                $parent = $this->getGroup($parentId);
                if ($parent === null || (string)($parent['kind'] ?? '') !== 'application') {
                    flash('error', 'El grupo padre debe ser un grupo de aplicaciones.');
                    redirect(base_url('modules/cve?tab=software'));
                }
                if ($id > 0 && in_array($parentId, $this->descendantGroupIds($id), true)) {
                    flash('error', 'No se puede mover un grupo dentro de uno de sus descendientes.');
                    redirect(base_url('modules/cve?tab=software'));
                }
            }
            if ($companyId > 0) {
                $company = $this->getGroup($companyId);
                if ($company === null || (string)($company['kind'] ?? '') !== 'company') {
                    flash('error', 'La empresa vinculada no existe.');
                    redirect(base_url('modules/cve?tab=software'));
                }
            } elseif ($parentId > 0) {
                $parent = $this->getGroup($parentId);
                $companyId = (int)($parent['company_id'] ?? 0);
            }
        }

        try {
            if ($id > 0) {
                CveDatabase::update(
                    "UPDATE software_groups
                     SET name = ?, parent_id = ?, position = ?, kind = ?, company_id = ?, updated_at = datetime('now')
                     WHERE id = ?",
                    [$name, $parentId > 0 ? $parentId : null, $position, $kind, $companyId > 0 ? $companyId : null, $id]
                );
                flash('success', $kind === 'company' ? 'Empresa actualizada.' : 'Grupo actualizado.');
            } else {
                $id = CveDatabase::insert(
                    "INSERT INTO software_groups (name, parent_id, position, kind, company_id) VALUES (?, ?, ?, ?, ?)",
                    [$name, $parentId > 0 ? $parentId : null, $position, $kind, $companyId > 0 ? $companyId : null]
                );
                flash('success', $kind === 'company' ? 'Empresa creada.' : 'Grupo creado.');
            }
            log_activity('cve.group_saved', [
                'id'         => $id,
                'name'       => $name,
                'parent_id'  => $parentId,
                'kind'       => $kind,
                'company_id' => $companyId,
            ]);
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
            $group = $this->getGroup($id);
            $isCompany = $group !== null && (string)($group['kind'] ?? '') === 'company';
            try {
                CveDatabase::query("DELETE FROM software_groups WHERE id = ?", [$id]);
                log_activity('cve.group_deleted', ['id' => $id]);
                flash('success', $isCompany
                    ? 'Empresa eliminada. Sus grupos vinculados se conservan sin empresa.'
                    : 'Grupo eliminado. Sus subgrupos y software quedan sin grupo.');
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
        if ($groupId > 0) {
            $selectedGroup = $this->getGroup($groupId);
            if ($selectedGroup === null) {
                flash('error', 'El grupo seleccionado no existe.');
                redirect(base_url('modules/cve?tab=software'));
            }
            if (!in_array((string)($selectedGroup['kind'] ?? 'application'), ['company', 'application'], true)) {
                flash('error', 'El grupo seleccionado no es válido.');
                redirect(base_url('modules/cve?tab=software'));
            }
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

        if ($cve !== null) {
            $sourceDescription = (string)($cve['description'] ?? '');
            $cachedEs = trim((string)($cve['description_es'] ?? ''));
            if ($cachedEs !== '' && hash_equals((string)($cve['description_es_hash'] ?? ''), sha1($sourceDescription))) {
                $cve['description_display'] = $cachedEs;
                $cve['description_display_lang'] = 'es';
            } else {
                $cve['description_display'] = $sourceDescription;
                $cve['description_display_lang'] = (string)($cve['description_lang'] ?? 'en');
            }
        }

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

    /**
     * Panel compacto de un CVE para insertarlo bajo la fila de CVEs asignados.
     */
    public function detailPanel(array $params = []): void
    {
        Auth::require();

        $cveId = strtoupper(rawurldecode((string)($params['cveId'] ?? '')));
        $valid = (bool)preg_match('/^CVE-\d{4}-\d{4,}$/', $cveId);
        $cve = $valid ? $this->getCatalogCve($cveId) : null;

        if ($cve === null) {
            http_response_code(404);
            echo '<div class="p-4 text-sm text-gray-500">No hay datos para este CVE en el catálogo local.</div>';
            return;
        }

        $products = CveDatabase::fetchAll(
            "SELECT vendor, product FROM cve_product WHERE cve_id = ? ORDER BY vendor ASC, product ASC",
            [$cveId]
        );
        $references = safe_json_decode($cve['references_json'] ?? '[]', []);
        $cwes = safe_json_decode($cve['cwe_ids'] ?? '[]', []);
        $references = is_array($references) ? $references : [];
        $cwes = is_array($cwes) ? $cwes : [];
        $kev = CveDatabase::fetchOne("SELECT * FROM cve_kev WHERE cve_id = ?", [$cveId]);
        $epss = CveDatabase::fetchOne("SELECT * FROM cve_epss WHERE cve_id = ?", [$cveId]);
        $exploits = CveExploit::getForCve($cveId);

        $sourceDescription = (string)($cve['description'] ?? '');
        $cachedEs = trim((string)($cve['description_es'] ?? ''));
        if ($cachedEs !== '' && hash_equals((string)($cve['description_es_hash'] ?? ''), sha1($sourceDescription))) {
            $cve['description_display'] = $cachedEs;
            $cve['description_display_lang'] = 'es';
        } else {
            $cve['description_display'] = $sourceDescription;
            $cve['description_display_lang'] = (string)($cve['description_lang'] ?? 'en');
        }

        $isAdmin = Auth::isAdmin();
        require __DIR__ . '/views/_cve_inline_panel.php';
    }

    /**
     * Busca exploits solo para un CVE concreto (botón «Buscar ahora»).
     */
    public function refreshExploits(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = json_decode((string)$raw, true);
            if (!is_array($input)) {
                $input = $_POST;
            }

            $ids = CveReportAi::normalizeCveIds($input['cve_id'] ?? '', 1);
            $cveId = (string)($ids[0] ?? '');
            if ($cveId === '') {
                json_response(['success' => false, 'error' => 'CVE no válido.'], 400);
            }

            $stats = CveExploit::enrich([$cveId]);
            $counts = CveExploit::countsByCve([$cveId]);
            $data = $counts[$cveId] ?? ['total' => 0, 'sources' => []];

            json_response([
                'success'  => true,
                'cve_id'   => $cveId,
                'stats'    => $stats,
                'total'    => (int)($data['total'] ?? 0),
                'sources'  => $data['sources'] ?? [],
            ]);
        } catch (Throwable $e) {
            app_log('error', 'cve_exploit', 'Error buscando exploits de un CVE', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Cuerpo de un informe para el panel inline de CVEs asignados.
     */
    public function aiReportPanel(array $params = []): void
    {
        Auth::require();

        $id = (int)($params['id'] ?? 0);
        $payload = $id > 0 ? $this->aiReportPayload($id) : null;
        if ($payload === null) {
            http_response_code(404);
            echo '<div class="p-4 text-sm text-gray-500">Informe no encontrado o sin acceso.</div>';
            return;
        }

        $report = $payload['report'];
        $items = $payload['items'];
        $aiText = $payload['aiText'];
        $sections = $payload['sections'];
        $defender = $payload['defender'] ?? null;
        $perItemMode = !empty($payload['perItemMode']);
        $interactive = false;
        $isAdmin = Auth::isAdmin();

        echo '<div class="no-print mb-3 flex items-center justify-between gap-2">'
            . '<span class="text-xs text-gray-500">Informe #' . (int)$id . '</span>'
            . '<a href="' . e(base_url('modules/cve/report-ai/' . (int)$id)) . '" class="text-xs text-brand-600 dark:text-brand-400 hover:underline">Abrir informe completo</a>'
            . '</div>';
        require __DIR__ . '/views/_ai_report_body.php';
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
            $tags = CveReportAi::normalizeTags($input['tags'] ?? []);
            $mode = ((string)($input['mode'] ?? 'extended')) === 'summary' ? 'summary' : 'extended';
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

            // Un informe independiente por CVE: cada uno se puede mover a su
            // empresa/grupo y la lista muestra una entrada por CVE.
            $reportIds = CveDatabase::transaction(function () use ($found, $profileId, $noAi, $tags, $mode): array {
                $ids = [];
                foreach ($found as $cveId) {
                    $created = $this->queueAiReport([$cveId], $profileId, $noAi, null, $tags, $mode);
                    $ids[] = (int)$created['report_id'];
                }
                return $ids;
            });
            $firstId = (int)($reportIds[0] ?? 0);
            $result = [
                'success'    => true,
                'report_id'  => $firstId,
                'report_ids' => $reportIds,
                'count'      => count($reportIds),
                'status'     => 'pending',
                'no_ai'      => $noAi,
                'defender'   => false,
                'url'        => base_url('modules/cve/report-ai/' . $firstId),
            ];
            app_log('info', 'cve_ai', 'Informes individuales creados', [
                'ids'    => $reportIds,
                'cves'   => $found,
                'no_ai'  => $noAi,
                'profile'=> $profileId,
            ]);
            log_activity('cve.ai_report_created', [
                'report_id'  => $firstId,
                'report_ids' => $reportIds,
                'cves'       => $found,
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

        app_log('info', 'cve_ai', 'Petición de ejecución recibida', [
            'id'      => $id,
            'ajax'    => is_ajax(),
            'request' => ($_SERVER['REQUEST_METHOD'] ?? '') . ' ' . ($_SERVER['REQUEST_URI'] ?? ''),
        ]);

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
                 SET status = 'pending', token = ?, ai_error = NULL, finished_at = NULL, started_at = NULL,
                     processed_items = 0
                 WHERE id = ?",
                [$token, $id]
            );
            // Reintentar solo los análisis que no terminaron; los «done» se conservan.
            CveDatabase::query(
                "UPDATE cve_ai_report_items
                 SET status = 'pending', ai_error = NULL
                 WHERE report_id = ? AND status IN ('error','running','pending')",
                [$id]
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
                    "SELECT id, status, ai_error, created_at, started_at, defender_json,
                            mode, processed_items, total_items
                     FROM cve_ai_reports WHERE id = ?",
                    [$id]
                )
                : null;
            if ($row === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }
            if (!empty($row['defender_json']) && !Auth::isAdmin()) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            // Autosalud: ni «pending» ni «running» deben quedarse eternos.
            $currentStatus = (string)$row['status'];
            if (in_array($currentStatus, ['pending', 'running'], true)) {
                $ref = $currentStatus === 'running' && !empty($row['started_at'])
                    ? (string)$row['started_at']
                    : (string)($row['created_at'] ?? '');
                $started = strtotime(str_contains($ref, 'Z') ? $ref : $ref . ' UTC');
                $limit = $currentStatus === 'running'
                    ? (((string)($row['mode'] ?? 'extended')) === 'extended' ? 3600 : 1800)
                    : 600;

                if ($started !== false && (time() - $started) > $limit) {
                    $message = $currentStatus === 'running'
                        ? 'La generación no terminó a tiempo. Puedes reintentarlo.'
                        : 'El informe no llegó a ejecutarse (10 minutos en cola). Pulsa Reintentar.';
                    CveDatabase::query(
                        "UPDATE cve_ai_reports
                         SET status = 'error', ai_error = ?, token = NULL, finished_at = datetime('now')
                         WHERE id = ? AND status = ?",
                        [$message, $id, $currentStatus]
                    );
                    $row['status'] = 'error';
                    $row['ai_error'] = $message;
                    app_log('warning', 'cve_ai', 'Informe atascado marcado como error', [
                        'id'     => $id,
                        'status' => $currentStatus,
                        'min'    => (int)round((time() - $started) / 60),
                    ]);
                }
            }

            $failedItems = (int)(CveDatabase::fetchOne(
                "SELECT COUNT(*) AS c FROM cve_ai_report_items WHERE report_id = ? AND status = 'error'",
                [$id]
            )['c'] ?? 0);
            $totalItems = (int)($row['total_items'] ?? 0);
            $processedItems = (int)($row['processed_items'] ?? 0);

            json_response([
                'success'   => true,
                'report_id' => $id,
                'status'    => (string)$row['status'],
                'error'     => (string)($row['ai_error'] ?? ''),
                'mode'      => (string)($row['mode'] ?? 'extended'),
                'processed' => $processedItems,
                'total'     => $totalItems,
                'failed'    => $failedItems,
                'progress'  => $totalItems > 0 ? min(100, (int)round($processedItems * 100 / $totalItems)) : 0,
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
        $data = $this->aiReportPayload($id);
        if ($data !== null) {
            $data['isAdmin'] = Auth::isAdmin();
        }

        if (!empty($_GET['partial'])) {
            // Documento aislado para inyectarlo en el panel derecho del workspace.
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store, no-cache, must-revalidate');
            if ($data === null) {
                http_response_code(404);
                echo '<div class="p-6 text-sm text-red-600">Informe no encontrado.</div>';
                return;
            }
            extract($data);
            $interactive = true;
            require __DIR__ . '/views/_ai_report_body.php';
            return;
        }

        if ($data === null) {
            http_response_code(404);
            $data = [
                'report'      => null,
                'items'       => [],
                'aiText'      => '',
                'sections'    => [],
                'defender'    => null,
                'perItemMode' => false,
                'isAdmin'     => Auth::isAdmin(),
            ];
        }

        echo $this->page('ai_report', $data);
    }

    public function cancelAiReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $id = (int)($params['id'] ?? 0);
            $row = $id > 0 ? CveDatabase::fetchOne("SELECT id, status FROM cve_ai_reports WHERE id = ?", [$id]) : null;
            if ($row === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            $updated = CveDatabase::update(
                "UPDATE cve_ai_reports
                 SET status = 'canceled', token = NULL, finished_at = datetime('now'),
                     ai_error = 'Cancelado por el usuario.'
                 WHERE id = ? AND status IN ('pending','running')",
                [$id]
            );

            if ($updated === 0) {
                json_response([
                    'success' => false,
                    'id'      => $id,
                    'status'  => (string)$row['status'],
                    'error'   => 'El informe ya había terminado (' . (string)$row['status'] . ').',
                ], 409);
            }

            app_log('info', 'cve_ai', 'Informe cancelado', ['id' => $id]);
            json_response(['success' => true, 'id' => $id, 'status' => 'canceled']);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error cancelando el informe', [
                'id'    => $params['id'] ?? null,
                'error' => $e->getMessage(),
            ]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    public function deleteAiReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $id = (int)($params['id'] ?? 0);
            $row = $id > 0
                ? CveDatabase::fetchOne("SELECT id, status, cve_ids FROM cve_ai_reports WHERE id = ?", [$id])
                : null;
            if ($row === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            // Si sigue en curso, invalidar el resultado antes de borrar.
            CveDatabase::query(
                "UPDATE cve_ai_reports SET status = 'canceled', token = NULL
                 WHERE id = ? AND status IN ('pending','running')",
                [$id]
            );
            CveDatabase::query("DELETE FROM cve_ai_reports WHERE id = ?", [$id]);

            app_log('info', 'cve_ai', 'Informe eliminado', [
                'id'     => $id,
                'status' => (string)$row['status'],
                'cves'   => (string)($row['cve_ids'] ?? ''),
            ]);

            json_response(['success' => true, 'id' => $id]);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error eliminando el informe', [
                'id'    => $params['id'] ?? null,
                'error' => $e->getMessage(),
            ]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Elimina varios informes con IA de una vez.
     */
    public function deleteAiReportsBulk(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = json_decode((string)$raw, true);
            if (!is_array($input)) {
                $input = $_POST;
            }

            $ids = $this->normalizeItemIds($input['ids'] ?? []);
            if ($ids === []) {
                json_response(['success' => false, 'error' => 'Selecciona al menos un informe.'], 400);
            }

            $deleted = 0;
            $skipped = 0;
            foreach ($ids as $id) {
                $row = CveDatabase::fetchOne(
                    "SELECT id, status, cve_ids FROM cve_ai_reports WHERE id = ?",
                    [$id]
                );
                if ($row === null) {
                    $skipped++;
                    continue;
                }

                // Si sigue en curso, invalidar el resultado antes de borrar.
                CveDatabase::query(
                    "UPDATE cve_ai_reports SET status = 'canceled', token = NULL
                     WHERE id = ? AND status IN ('pending','running')",
                    [$id]
                );
                CveDatabase::query("DELETE FROM cve_ai_reports WHERE id = ?", [$id]);
                $deleted++;
            }

            app_log('info', 'cve_ai', 'Informes eliminados en lote', [
                'ids'     => $ids,
                'deleted' => $deleted,
                'skipped' => $skipped,
            ]);
            log_activity('cve.ai_reports_deleted_bulk', [
                'ids'     => $ids,
                'deleted' => $deleted,
            ]);

            json_response([
                'success' => true,
                'deleted' => $deleted,
                'skipped' => $skipped,
            ]);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error eliminando informes en lote', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Actualiza los datos del informe desde el catálogo local y, si han
     * cambiado, incrementa la revisión y lo vuelve a encolar.
     */
    public function refreshAiReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $id = (int)($params['id'] ?? 0);
            $row = $id > 0 ? CveDatabase::fetchOne("SELECT * FROM cve_ai_reports WHERE id = ?", [$id]) : null;
            if ($row === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            $status = (string)($row['status'] ?? '');
            if (in_array($status, ['pending', 'running'], true)) {
                json_response([
                    'success' => false,
                    'error'   => 'El informe está en curso. Espera a que termine o cancélalo.',
                ], 409);
            }

            $ids = safe_json_decode((string)($row['cve_ids'] ?? ''), []);
            if (!is_array($ids) || $ids === []) {
                json_response(['success' => false, 'error' => 'El informe no tiene CVEs válidos.'], 400);
            }

            try {
                CveExploit::enrich($ids);
            } catch (Throwable $e) {
                app_log('warning', 'cve_exploit', 'No se pudieron actualizar los exploits', [
                    'id'    => $id,
                    'error' => $e->getMessage(),
                ]);
            }

            $items = CveReportAi::buildData($ids);
            if ($items === []) {
                json_response(['success' => false, 'error' => 'Ninguno de los CVEs está en el catálogo local.'], 400);
            }

            // Traducir descripciones/acciones KEV pendientes antes de comparar:
            // así «Actualizar» incorpora la traducción a informes antiguos.
            if (empty($row['no_ai'])) {
                $profileId = (int)($row['ai_profile_id'] ?? 0);
                $llm = class_exists('Module_Llm') ? new Module_Llm() : null;
                if ($llm !== null && $llm->isConfigured($profileId > 0 ? $profileId : null)) {
                    CveReportAi::ensureSpanishTexts($items, $profileId > 0 ? $profileId : null);
                }
            }

            $newJson = json_encode($items, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            if ($newJson === false) {
                json_response(['success' => false, 'error' => 'No se pudieron serializar los datos.'], 500);
            }

            $changed = ((string)($row['data_json'] ?? '')) !== $newJson;

            // Exposición de Defender: se recalcula y también cuenta como cambio.
            $defenderSave = $row['defender_json'] ?? null;
            if (!empty($row['defender_json'])) {
                $oldDefender = safe_json_decode((string)$row['defender_json'], []);
                if (!is_array($oldDefender)) {
                    $oldDefender = [];
                }
                $newDefender = $this->buildDefenderContext(
                    $ids,
                    (int)($oldDefender['tenant_id'] ?? 0),
                    (string)($oldDefender['tenant_name'] ?? '')
                );
                $newDefenderJson = json_encode(
                    $newDefender,
                    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
                );
                if ($newDefenderJson !== false) {
                    $oldCves = is_array($oldDefender['cves'] ?? null) ? $oldDefender['cves'] : [];
                    if ($this->encodeJson($newDefender['cves']) !== $this->encodeJson($oldCves)) {
                        $changed = true;
                        $defenderSave = $newDefenderJson;
                    }
                }
            }

            // Sin cambios y ya está listo: no se gasta ninguna llamada a la IA.
            if (!$changed && $status === 'done') {
                json_response([
                    'success'  => true,
                    'id'       => $id,
                    'changed'  => false,
                    'status'   => 'done',
                    'revision' => (int)($row['revision'] ?? 1),
                    'message'  => 'Sin cambios desde la última versión.',
                ]);
            }

            $token = bin2hex(random_bytes(24));

            if ($changed) {
                CveDatabase::update(
                    "UPDATE cve_ai_reports
                     SET data_json = ?, defender_json = ?, status = 'pending', token = ?, ai_error = NULL,
                         started_at = NULL, finished_at = NULL, updated_at = NULL,
                         processed_items = 0, revision = revision + 1
                     WHERE id = ?",
                    [$newJson, $defenderSave, $token, $id]
                );
            } else {
                // Mismos datos (error/cancelado): reintento sin subir revisión.
                CveDatabase::update(
                    "UPDATE cve_ai_reports
                     SET status = 'pending', token = ?, ai_error = NULL,
                         started_at = NULL, finished_at = NULL, processed_items = 0
                     WHERE id = ?",
                    [$token, $id]
                );
            }

            // Actualizar implica recalcular los análisis individuales.
            CveDatabase::query(
                "UPDATE cve_ai_report_items
                 SET status = 'pending', ai_error = NULL, sections_json = NULL, ai_text = NULL
                 WHERE report_id = ?",
                [$id]
            );

            app_log('info', 'cve_ai', 'Informe actualizado desde el catálogo', [
                'id'      => $id,
                'changed' => $changed,
                'cves'    => $ids,
            ]);

            json_response([
                'success'  => true,
                'id'       => $id,
                'changed'  => $changed,
                'status'   => 'pending',
                'revision' => $changed ? (int)($row['revision'] ?? 1) + 1 : (int)($row['revision'] ?? 1),
                'message'  => $changed
                    ? 'Datos actualizados; se regenerará el análisis.'
                    : 'Sin cambios en los datos; se regenerará el análisis.',
            ]);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error actualizando el informe', [
                'id'    => $params['id'] ?? null,
                'error' => $e->getMessage(),
            ]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Resuelve el destino de un informe: un grupo existente o uno nuevo.
     * Devuelve ['id' => int, 'name' => string]. El id 0 significa «sin grupo».
     *
     * @return array{id:int,name:string}
     */
    private function resolveReportGroup(
        int $groupId,
        string $newName,
        string $newKind = 'application',
        string $source = 'report'
    ): array {
        $newKind = strtolower(trim($newKind));
        if (!in_array($newKind, ['company', 'application'], true)) {
            $newKind = 'application';
        }

        if ($newName !== '') {
            if ($this->textLength($newName) > 120) {
                throw new InvalidArgumentException('El nombre del grupo es demasiado largo (máximo 120).');
            }
            $existing = CveDatabase::fetchOne(
                "SELECT id, name FROM software_groups
                 WHERE lower(name) = lower(?) AND kind = ?
                 ORDER BY id LIMIT 1",
                [$newName, $newKind]
            );
            if ($existing !== null) {
                return ['id' => (int)$existing['id'], 'name' => (string)$existing['name']];
            }
            $id = CveDatabase::insert(
                "INSERT INTO software_groups (name, parent_id, position, kind, company_id)
                 VALUES (?, NULL, 0, ?, NULL)",
                [$newName, $newKind]
            );
            log_activity('cve.group_created', [
                'id'     => $id,
                'name'   => $newName,
                'kind'   => $newKind,
                'from'   => $source,
            ]);
            return ['id' => $id, 'name' => $newName];
        }

        if ($groupId > 0) {
            $group = CveDatabase::fetchOne("SELECT id, name, kind FROM software_groups WHERE id = ?", [$groupId]);
            if ($group === null) {
                throw new InvalidArgumentException('El grupo seleccionado no existe.');
            }
            if (!in_array((string)($group['kind'] ?? 'application'), ['company', 'application'], true)) {
                throw new InvalidArgumentException('El grupo seleccionado no es válido.');
            }
            return ['id' => (int)$group['id'], 'name' => (string)$group['name']];
        }

        return ['id' => 0, 'name' => ''];
    }

    /**
     * Asigna el informe a una empresa o a un grupo de aplicaciones (lo crea si no existe).
     */
    public function assignAiReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = json_decode((string)$raw, true);
            if (!is_array($input)) {
                $input = $_POST;
            }

            $id = (int)($params['id'] ?? 0);
            $row = $id > 0
                ? CveDatabase::fetchOne("SELECT id, group_id FROM cve_ai_reports WHERE id = ?", [$id])
                : null;
            if ($row === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            $oldGroupId = (int)($row['group_id'] ?? 0);
            // Informes antiguos: asegurar las filas por CVE antes de asignar.
            CveReportAi::ensureReportItems($id);

            $groupId = (int)($input['group_id'] ?? 0);
            $newName = trim((string)($input['new_group'] ?? ''));
            $newKind = (string)($input['new_group_kind'] ?? 'application');

            app_log('info', 'cve_ai', 'Asignación de grupo solicitada', [
                'id'             => $id,
                'group_id'       => $groupId,
                'new_group'      => $newName,
                'new_group_kind' => $newKind,
            ]);

            $target = $this->resolveReportGroup($groupId, $newName, $newKind, 'report');
            $groupId = $target['id'];
            $groupName = $target['name'];

            CveDatabase::update(
                "UPDATE cve_ai_reports SET group_id = ? WHERE id = ?",
                [$groupId > 0 ? $groupId : null, $id]
            );
            if ($groupId > 0) {
                if ($oldGroupId > 0 && $oldGroupId !== $groupId) {
                    // Mueve los CVEs que heredaban el grupo anterior; conserva
                    // los que tenían un grupo propio distinto.
                    CveDatabase::query(
                        "UPDATE cve_ai_report_items SET group_id = ?, updated_at = datetime('now')
                         WHERE report_id = ? AND (group_id IS NULL OR group_id = ?)",
                        [$groupId, $id, $oldGroupId]
                    );
                } else {
                    // Los CVEs sin grupo propio heredan el grupo del informe.
                    CveDatabase::query(
                        "UPDATE cve_ai_report_items SET group_id = ?, updated_at = datetime('now')
                         WHERE report_id = ? AND group_id IS NULL",
                        [$groupId, $id]
                    );
                }
            } elseif ($oldGroupId > 0) {
                // El informe pasa a «sin grupo»: se limpia el grupo heredado.
                CveDatabase::query(
                    "UPDATE cve_ai_report_items SET group_id = NULL, updated_at = datetime('now')
                     WHERE report_id = ? AND group_id = ?",
                    [$id, $oldGroupId]
                );
            }

            app_log('info', 'cve_ai', 'Informe asignado a grupo', [
                'id'    => $id,
                'group' => $groupName,
            ]);

            json_response([
                'success'    => true,
                'id'         => $id,
                'group_id'   => $groupId,
                'group_name' => $groupName,
            ]);
        } catch (InvalidArgumentException $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 400);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error asignando el informe', [
                'id'    => $params['id'] ?? null,
                'error' => $e->getMessage(),
            ]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Aplica tags a los CVEs seleccionados de un informe.
     */
    public function updateAiItemTags(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = json_decode((string)$raw, true);
            if (!is_array($input)) {
                $input = $_POST;
            }

            $reportId = (int)($input['report_id'] ?? 0);
            $report = $reportId > 0
                ? CveDatabase::fetchOne("SELECT id FROM cve_ai_reports WHERE id = ?", [$reportId])
                : null;
            if ($report === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            $itemIds = $this->normalizeItemIds($input['item_ids'] ?? []);
            if ($itemIds === []) {
                json_response(['success' => false, 'error' => 'Selecciona al menos un CVE.'], 400);
            }

            $tags = CveReportAi::normalizeTags($input['tags'] ?? []);
            $append = !empty($input['append']);
            $updated = 0;

            foreach ($itemIds as $itemId) {
                $item = CveDatabase::fetchOne(
                    "SELECT id, tags FROM cve_ai_report_items WHERE id = ? AND report_id = ?",
                    [$itemId, $reportId]
                );
                if ($item === null) {
                    continue;
                }
                $newTags = $append
                    ? array_merge(CveReportAi::decodeTags((string)($item['tags'] ?? '')), $tags)
                    : $tags;
                CveDatabase::update(
                    "UPDATE cve_ai_report_items SET tags = ?, updated_at = datetime('now')
                     WHERE id = ? AND report_id = ?",
                    [CveReportAi::tagsJson($newTags), $itemId, $reportId]
                );
                $updated++;
            }

            log_activity('cve.ai_report_items_tagged', [
                'report_id' => $reportId,
                'items'     => $itemIds,
                'tags'      => $tags,
            ]);

            json_response([
                'success' => true,
                'updated' => $updated,
                'tags'    => $tags,
            ]);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error etiquetando CVEs', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Envía los CVEs seleccionados de un informe a un grupo de aplicaciones.
     */
    public function assignAiReportItems(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = json_decode((string)$raw, true);
            if (!is_array($input)) {
                $input = $_POST;
            }

            $reportId = (int)($input['report_id'] ?? 0);
            $report = $reportId > 0
                ? CveDatabase::fetchOne("SELECT id FROM cve_ai_reports WHERE id = ?", [$reportId])
                : null;
            if ($report === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            $itemIds = $this->normalizeItemIds($input['item_ids'] ?? []);
            if ($itemIds === []) {
                json_response(['success' => false, 'error' => 'Selecciona al menos un CVE.'], 400);
            }

            $groupId = (int)($input['group_id'] ?? 0);
            $newName = trim((string)($input['new_group'] ?? ''));
            $newKind = (string)($input['new_group_kind'] ?? 'application');

            app_log('info', 'cve_ai', 'Asignación de grupo a CVEs solicitada', [
                'report_id'      => $reportId,
                'items'          => $itemIds,
                'group_id'       => $groupId,
                'new_group'      => $newName,
                'new_group_kind' => $newKind,
            ]);

            $target = $this->resolveReportGroup($groupId, $newName, $newKind, 'report_items');
            $groupId = $target['id'];
            $groupName = $target['name'];

            $updated = 0;
            foreach ($itemIds as $itemId) {
                $updated += CveDatabase::update(
                    "UPDATE cve_ai_report_items SET group_id = ?, updated_at = datetime('now')
                     WHERE id = ? AND report_id = ?",
                    [$groupId > 0 ? $groupId : null, $itemId, $reportId]
                );
            }

            app_log('info', 'cve_ai', 'CVEs enviados a grupo', [
                'report_id' => $reportId,
                'items'     => $itemIds,
                'group'     => $groupName,
            ]);

            json_response([
                'success'    => true,
                'group_id'   => $groupId,
                'group_name' => $groupName,
                'updated'    => $updated,
            ]);
        } catch (InvalidArgumentException $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 400);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error enviando CVEs a grupo', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Asigna varios informes completos (y todos sus CVEs) a una empresa o
     * a un grupo de aplicaciones, sin abrir cada informe.
     */
    public function assignAiReportsBulk(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = json_decode((string)$raw, true);
            if (!is_array($input)) {
                $input = $_POST;
            }

            $ids = $this->normalizeItemIds($input['ids'] ?? []);
            if ($ids === []) {
                json_response(['success' => false, 'error' => 'Selecciona al menos un informe.'], 400);
            }

            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $rows = CveDatabase::fetchAll(
                "SELECT id, status FROM cve_ai_reports WHERE id IN ($placeholders)",
                $ids
            );
            if ($rows === []) {
                json_response(['success' => false, 'error' => 'No se encontraron los informes seleccionados.'], 404);
            }

            $eligible = [];
            $skipped = [];
            foreach ($rows as $row) {
                $reportId = (int)$row['id'];
                if (in_array((string)($row['status'] ?? ''), ['pending', 'running'], true)) {
                    $skipped[] = $reportId;
                    continue;
                }
                $eligible[] = $reportId;
            }
            if ($eligible === []) {
                json_response([
                    'success' => false,
                    'error'   => 'Los informes seleccionados están en curso. Espera a que terminen.',
                    'skipped' => $skipped,
                ], 400);
            }

            // Informes antiguos: reconstruir sus CVEs antes de asignar.
            foreach ($eligible as $reportId) {
                CveReportAi::ensureReportItems($reportId);
            }

            $groupId = (int)($input['group_id'] ?? 0);
            $newName = trim((string)($input['new_group'] ?? ''));
            $newKind = (string)($input['new_group_kind'] ?? 'application');

            app_log('info', 'cve_ai', 'Asignación masiva de informes solicitada', [
                'reports'        => $eligible,
                'skipped'        => $skipped,
                'group_id'       => $groupId,
                'new_group'      => $newName,
                'new_group_kind' => $newKind,
            ]);

            $target = $this->resolveReportGroup($groupId, $newName, $newKind, 'reports_bulk');
            $targetId = $target['id'];
            $groupName = $target['name'];

            $reportCount = 0;
            $itemCount = 0;
            CveDatabase::transaction(function (PDO $db) use ($eligible, $targetId, &$reportCount, &$itemCount): void {
                $updateReport = $db->prepare(
                    "UPDATE cve_ai_reports SET group_id = ?, updated_at = datetime('now') WHERE id = ?"
                );
                $updateItems = $db->prepare(
                    "UPDATE cve_ai_report_items SET group_id = ?, updated_at = datetime('now') WHERE report_id = ?"
                );
                foreach ($eligible as $reportId) {
                    $updateReport->execute([$targetId > 0 ? $targetId : null, $reportId]);
                    $reportCount += $updateReport->rowCount();
                    $updateItems->execute([$targetId > 0 ? $targetId : null, $reportId]);
                    $itemCount += $updateItems->rowCount();
                }
            });

            $cveCount = 0;
            if ($eligible !== []) {
                $placeholders = implode(',', array_fill(0, count($eligible), '?'));
                $cveCount = (int)(CveDatabase::fetchOne(
                    "SELECT COUNT(DISTINCT cve_id) AS c
                     FROM cve_ai_report_items
                     WHERE report_id IN ($placeholders)",
                    $eligible
                )['c'] ?? 0);
            }

            log_activity('cve.reports_assigned_bulk', [
                'reports' => $eligible,
                'group'   => $groupName,
                'items'   => $itemCount,
                'cves'    => $cveCount,
            ]);

            json_response([
                'success'      => true,
                'group_id'     => $targetId,
                'group_name'   => $groupName,
                'reports'      => $reportCount,
                'items'        => $itemCount,
                'cves'         => $cveCount,
                'skipped'      => $skipped,
            ]);
        } catch (InvalidArgumentException $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 400);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error asignando informes en lote', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Separa un informe agrupado en un informe individual por CVE.
     */
    public function splitAiReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $id = (int)($params['id'] ?? 0);
            $result = CveReportSplit::splitReport($id);
            json_response([
                'success'    => true,
                'id'         => $id,
                'report_ids' => $result['report_ids'],
                'pending'    => (int)$result['pending'],
                'count'      => count($result['report_ids']),
            ]);
        } catch (InvalidArgumentException $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 400);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error separando un informe', [
                'id'    => $params['id'] ?? null,
                'error' => $e->getMessage(),
            ]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Quita un CVE de una empresa/grupo concreto sin borrar el informe.
     */
    public function unassignAiCve(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $groupId = (int)($_POST['group_id'] ?? 0);
        $cveIds = CveReportAi::normalizeCveIds((string)($_POST['cve_id'] ?? ''), 1);
        $cveId = (string)($cveIds[0] ?? '');
        $backUrl = base_url('modules/cve?tab=software' . ($groupId > 0 ? '&group=' . $groupId : ''));

        if ($groupId <= 0 || $cveId === '') {
            flash('error', 'No se pudo identificar el CVE o el grupo.');
            redirect($backUrl);
        }

        $group = $this->getGroup($groupId);
        if ($group === null) {
            flash('error', 'La empresa o grupo ya no existe.');
            redirect(base_url('modules/cve?tab=software'));
        }

        try {
            $affected = 0;
            CveDatabase::transaction(function (PDO $db) use ($groupId, $cveId, &$affected): void {
                $reportsStmt = $db->prepare(
                    "SELECT DISTINCT report_id
                     FROM cve_ai_report_items
                     WHERE group_id = ? AND cve_id = ?"
                );
                $reportsStmt->execute([$groupId, $cveId]);
                $reportIds = array_map(
                    static fn(array $row): int => (int)$row['report_id'],
                    $reportsStmt->fetchAll()
                );

                $update = $db->prepare(
                    "UPDATE cve_ai_report_items
                     SET group_id = NULL, updated_at = datetime('now')
                     WHERE group_id = ? AND cve_id = ?"
                );
                $update->execute([$groupId, $cveId]);
                $affected = $update->rowCount();

                $remaining = $db->prepare(
                    "SELECT COUNT(*) AS c
                     FROM cve_ai_report_items
                     WHERE report_id = ? AND group_id = ?"
                );
                $clearReport = $db->prepare(
                    "UPDATE cve_ai_reports
                     SET group_id = NULL, updated_at = datetime('now')
                     WHERE id = ? AND group_id = ?"
                );
                foreach ($reportIds as $reportId) {
                    $remaining->execute([$reportId, $groupId]);
                    if ((int)($remaining->fetch()['c'] ?? 0) === 0) {
                        $clearReport->execute([$reportId, $groupId]);
                    }
                }
            });

            log_activity('cve.cve_unassigned', [
                'group_id' => $groupId,
                'cve_id'   => $cveId,
                'items'    => $affected,
            ]);

            flash('success', $affected > 0
                ? 'CVE ' . $cveId . ' quitado de «' . (string)$group['name'] . '».'
                : 'El CVE no estaba asignado a esta empresa/grupo.');
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error quitando un CVE del grupo', [
                'group_id' => $groupId,
                'cve_id'   => $cveId,
                'error'    => $e->getMessage(),
            ]);
            flash('error', 'No se pudo quitar el CVE: ' . $e->getMessage());
        }

        redirect($backUrl);
    }

    /**
     * Sugerencias de tags y grupos para los CVEs seleccionados.
     */
    public function aiTagSuggestions(array $params = []): void
    {
        if (!Auth::check()) {
            json_response(['success' => false, 'error' => 'Sesión caducada. Recarga la página.'], 401);
        }

        try {
            $reportId = (int)($_GET['report_id'] ?? 0);
            $report = $reportId > 0
                ? CveDatabase::fetchOne("SELECT id, tags, defender_json FROM cve_ai_reports WHERE id = ?", [$reportId])
                : null;
            if ($report === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }
            if (!empty($report['defender_json']) && !Auth::isAdmin()) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }

            $itemIds = $this->normalizeItemIds($_GET['item_ids'] ?? []);
            $where = 'report_id = ?';
            $sqlParams = [$reportId];
            if ($itemIds !== []) {
                $ph = implode(',', array_fill(0, count($itemIds), '?'));
                $where .= " AND id IN ($ph)";
                $sqlParams = array_merge($sqlParams, $itemIds);
            }

            $rows = CveDatabase::fetchAll(
                "SELECT cve_id, tags FROM cve_ai_report_items WHERE $where ORDER BY position, id",
                $sqlParams
            );

            $cveIds = [];
            $tags = CveReportAi::decodeTags((string)($report['tags'] ?? ''));
            foreach ($rows as $row) {
                $cveIds[] = (string)$row['cve_id'];
                $tags = array_merge($tags, CveReportAi::decodeTags((string)($row['tags'] ?? '')));
            }
            $cveIds = array_values(array_unique(array_filter($cveIds)));

            // Vocabulario de tags ya usado en este informe (aunque no esté seleccionado).
            foreach (CveDatabase::fetchAll(
                "SELECT tags FROM cve_ai_report_items WHERE report_id = ? AND tags IS NOT NULL",
                [$reportId]
            ) as $row) {
                $tags = array_merge($tags, CveReportAi::decodeTags((string)$row['tags']));
            }

            $groups = [];
            if ($cveIds !== []) {
                $ph = implode(',', array_fill(0, count($cveIds), '?'));
                $groupRows = CveDatabase::fetchAll(
                    "SELECT DISTINCT g.name
                     FROM cve_watchlist_match m
                     JOIN software_watchlist w ON w.id = m.watchlist_id
                     JOIN software_groups g ON g.id = w.group_id
                     WHERE m.cve_id IN ($ph)
                     ORDER BY g.name
                     LIMIT 50",
                    $cveIds
                );
                foreach ($groupRows as $row) {
                    $name = trim((string)($row['name'] ?? ''));
                    if ($name !== '') {
                        $groups[] = $name;
                    }
                }
            }

            json_response([
                'success' => true,
                'tags'    => CveReportAi::normalizeTags($tags, 50),
                'groups'  => array_values(array_unique($groups)),
            ]);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error obteniendo sugerencias de tags', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Reintenta el análisis de un único CVE.
     */
    public function retryAiReportItem(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $reportId = (int)($params['id'] ?? 0);
            $itemId = (int)($params['itemId'] ?? 0);
            $report = $reportId > 0
                ? CveDatabase::fetchOne("SELECT id, status, mode FROM cve_ai_reports WHERE id = ?", [$reportId])
                : null;
            if ($report === null) {
                json_response(['success' => false, 'error' => 'Informe no encontrado.'], 404);
            }
            if (in_array((string)$report['status'], ['pending', 'running'], true)) {
                json_response(['success' => false, 'error' => 'El informe está en curso.'], 409);
            }
            if ((string)($report['mode'] ?? 'extended') === 'summary') {
                json_response(['success' => false, 'error' => 'Este informe usa análisis global; reintenta el informe completo.'], 400);
            }

            $item = CveDatabase::fetchOne(
                "SELECT id FROM cve_ai_report_items WHERE id = ? AND report_id = ?",
                [$itemId, $reportId]
            );
            if ($item === null) {
                json_response(['success' => false, 'error' => 'CVE no encontrado en el informe.'], 404);
            }

            $token = bin2hex(random_bytes(24));
            CveDatabase::update(
                "UPDATE cve_ai_reports
                 SET status = 'pending', token = ?, ai_error = NULL, started_at = NULL, finished_at = NULL
                 WHERE id = ?",
                [$token, $reportId]
            );
            CveDatabase::update(
                "UPDATE cve_ai_report_items
                 SET status = 'pending', ai_error = NULL, sections_json = NULL, ai_text = NULL
                 WHERE id = ? AND report_id = ?",
                [$itemId, $reportId]
            );

            $result = CveReportAi::runById($reportId);
            $result['url'] = base_url('modules/cve/report-ai/' . $reportId);
            json_response($result);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error reintentando un CVE', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Normaliza IDs de cve_ai_report_items recibidos como array o texto.
     *
     * @return int[]
     */
    private function normalizeItemIds(mixed $raw): array
    {
        $parts = is_array($raw) ? $raw : preg_split('/[\s,;]+/', (string)$raw);
        $ids = [];
        foreach ($parts ?: [] as $part) {
            if (!is_scalar($part)) {
                continue;
            }
            $id = (int)$part;
            if ($id > 0) {
                $ids[$id] = true;
            }
            if (count($ids) >= 200) {
                break;
            }
        }
        return array_keys($ids);
    }

    /**
     * Crea un informe a partir de la exposición real de Defender for Endpoint.
     */
    public function startAiReportDefender(array $params = []): void
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
                json_response(['success' => false, 'error' => 'Selecciona al menos un CVE.'], 400);
            }

            $missing = [];
            foreach ($ids as $cveId) {
                if (CveDatabase::fetchOne("SELECT cve_id FROM cve_catalog WHERE cve_id = ?", [$cveId]) === null) {
                    $missing[] = $cveId;
                }
            }

            if ($missing !== []) {
                if (count($missing) > 10) {
                    json_response([
                        'success' => false,
                        'error'   => 'Como máximo se pueden descargar 10 CVEs nuevos por informe. Reduce la selección o sincroniza el catálogo.',
                    ], 400);
                }

                @set_time_limit(0);
                $sync = new CveSync();
                $failed = [];
                foreach ($missing as $cveId) {
                    try {
                        $sync->fetchAndStoreCve($cveId);
                        app_log('info', 'cve_ai', 'CVE descargado para el informe', ['cve' => $cveId]);
                    } catch (Throwable $e) {
                        $failed[] = $cveId . ' (' . $e->getMessage() . ')';
                    }
                }
                if ($failed !== []) {
                    json_response([
                        'success' => false,
                        'error'   => 'No se pudieron descargar de NVD: ' . implode('; ', $failed)
                            . '. Revisa la API key y el límite de peticiones en Admin → APIs.',
                    ], 400);
                }
            }

            $tenantId = max(0, (int)($input['tenant_id'] ?? 0));
            $tenantName = '';
            if ($tenantId > 0) {
                $tenant = Database::fetchOne("SELECT name FROM tenants WHERE id = ?", [$tenantId]);
                if ($tenant === null) {
                    json_response(['success' => false, 'error' => 'El tenant seleccionado no existe.'], 400);
                }
                $tenantName = (string)$tenant['name'];
            }

            $noAi = !empty($input['no_ai']);
            $tags = CveReportAi::normalizeTags($input['tags'] ?? []);
            $mode = ((string)($input['mode'] ?? 'extended')) === 'summary' ? 'summary' : 'extended';
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

            $defender = $this->buildDefenderContext($ids, $tenantId, $tenantName);
            $defenderJson = json_encode(
                $defender,
                JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
            );
            if ($defenderJson === false) {
                json_response(['success' => false, 'error' => 'No se pudo serializar la exposición de Defender.'], 500);
            }

            $result = $this->queueAiReport($ids, $profileId, $noAi, $defenderJson, $tags, $mode);
            app_log('info', 'cve_ai', 'Informe creado desde Defender', [
                'id'       => (int)$result['report_id'],
                'cves'     => $ids,
                'tenant'   => $tenantName,
                'no_ai'    => $noAi,
            ]);
            log_activity('cve.ai_report_created', [
                'report_id' => (int)$result['report_id'],
                'cves'      => $ids,
                'source'    => 'defender',
            ]);

            json_response($result);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error creando el informe desde Defender', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Lista agregada de CVEs expuestos según Defender, con filtros.
     */
    public function defenderList(array $params = []): void
    {
        Auth::requireAdmin();

        try {
            $tenantId = max(0, (int)($_GET['tenant_id'] ?? 0));
            $epssRaw = trim((string)($_GET['epss_min'] ?? ''));

            $out = $this->defenderEnrichedRows($tenantId, trim((string)($_GET['q'] ?? '')), 800, [
                'severity'     => strtoupper(trim((string)($_GET['severity'] ?? ''))),
                'exploited'    => !empty($_GET['exploited']),
                'kev'          => !empty($_GET['kev']),
                'epss_min'     => $epssRaw !== '' && is_numeric($epssRaw) ? max(0.0, min(1.0, (float)$epssRaw)) : null,
                'min_machines' => max(0, (int)($_GET['min_machines'] ?? 0)),
            ]);

            $out = array_slice($out, 0, 200);
            $missingCatalog = count(array_filter($out, static fn($r) => empty($r['in_catalog'])));

            $tenants = Database::fetchAll("SELECT id, name FROM tenants ORDER BY name");
            $nvdKey = false;
            try {
                $nvdKey = CveClient::fromSettings()->hasApiKey();
            } catch (Throwable $e) {
                $nvdKey = false;
            }

            json_response([
                'success'         => true,
                'cves'            => $out,
                'total'           => count($out),
                'missing_catalog' => $missingCatalog,
                'tenants'         => $tenants,
                'nvd_key'         => $nvdKey,
            ]);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error listando vulnerabilidades de Defender', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Agrega, enriquece (catálogo/KEV), filtra y ordena las vulnerabilidades de Defender.
     *
     * @param array{severity?:string,exploited?:bool,kev?:bool,epss_min?:float|null,min_machines?:int} $filters
     */
    private function defenderEnrichedRows(int $tenantId, string $q, int $limit = 800, array $filters = []): array
    {
        $rows = $this->aggregateDefenderVulns($tenantId, $q, $limit);
        $ids = array_values(array_unique(array_map(static fn($r) => (string)$r['cve_id'], $rows)));

        $inCatalog = [];
        $inKev = [];
        if ($ids !== []) {
            $ph = implode(',', array_fill(0, count($ids), '?'));
            foreach (CveDatabase::fetchAll("SELECT cve_id FROM cve_catalog WHERE cve_id IN ($ph)", $ids) as $r) {
                $inCatalog[(string)$r['cve_id']] = true;
            }
            foreach (CveDatabase::fetchAll("SELECT cve_id FROM cve_kev WHERE cve_id IN ($ph)", $ids) as $r) {
                $inKev[(string)$r['cve_id']] = true;
            }
        }

        $severity = strtoupper((string)($filters['severity'] ?? ''));
        $exploited = !empty($filters['exploited']);
        $kevOnly = !empty($filters['kev']);
        $epssMin = array_key_exists('epss_min', $filters) ? $filters['epss_min'] : null;
        $minMachines = (int)($filters['min_machines'] ?? 0);

        $out = [];
        foreach ($rows as $row) {
            $cveId = (string)$row['cve_id'];
            $isKev = isset($inKev[$cveId]);
            $isCatalog = isset($inCatalog[$cveId]);

            if ($severity !== '' && strtoupper((string)$row['severity']) !== $severity) {
                continue;
            }
            if ($exploited && empty($row['public_exploit'])) {
                continue;
            }
            if ($kevOnly && !$isKev) {
                continue;
            }
            if ($epssMin !== null && (float)$row['epss'] < (float)$epssMin) {
                continue;
            }
            if ($minMachines > 0 && (int)$row['machine_count'] < $minMachines) {
                continue;
            }

            $out[] = [
                'cve_id'           => $cveId,
                'severity'         => (string)$row['severity'],
                'cvss'             => $row['cvss'] !== null ? (float)$row['cvss'] : null,
                'epss'             => $row['epss'] !== null ? (float)$row['epss'] : null,
                'public_exploit'   => !empty($row['public_exploit']),
                'exploit_verified' => !empty($row['exploit_verified']),
                'exposed_machines' => (int)($row['exposed_machines'] ?? 0),
                'machine_count'    => (int)($row['machine_count'] ?? 0),
                'products'         => is_array($row['products']) ? $row['products'] : [],
                'vendors'          => is_array($row['vendors']) ? $row['vendors'] : [],
                'tenants'          => is_array($row['tenants']) ? $row['tenants'] : [],
                'in_catalog'       => $isCatalog,
                'in_kev'           => $isKev,
            ];
        }

        usort($out, static function (array $a, array $b): int {
            foreach (['exploit_verified', 'public_exploit', 'in_kev', 'cvss', 'epss', 'machine_count'] as $key) {
                $av = $a[$key] ?? 0;
                $bv = $b[$key] ?? 0;
                if ($av == $bv) {
                    continue;
                }
                return $bv <=> $av;
            }
            return strcmp($a['cve_id'], $b['cve_id']);
        });

        return $out;
    }

    /**
     * Genera el informe automático desde Defender (cron o «Generar ahora»).
     * Selecciona los N CVEs de mayor riesgo, descarga los que falten y lo ejecuta.
     */
    public function createScheduledDefenderReport(array $options = []): array
    {
        $limit = max(1, min(50, (int)($options['limit'] ?? 10)));
        $tenantId = max(0, (int)($options['tenant_id'] ?? 0));
        $groupId = max(0, (int)($options['group_id'] ?? 0));
        $noAi = !empty($options['no_ai']);
        $dryRun = !empty($options['dry_run']);

        $rows = $this->defenderEnrichedRows($tenantId, '', 800, [
            'severity'  => (string)($options['severity'] ?? ''),
            'exploited' => !empty($options['exploited']),
            'kev'       => !empty($options['kev']),
        ]);
        $rows = array_slice($rows, 0, $limit);

        if ($rows === []) {
            return [
                'success' => true,
                'created' => false,
                'cves'    => [],
                'message' => 'Sin CVEs de Defender que cumplan los filtros.',
            ];
        }

        $cveIds = array_values(array_map(static fn($row) => (string)$row['cve_id'], $rows));

        if ($dryRun) {
            return [
                'success'  => true,
                'dry_run'  => true,
                'count'    => count($cveIds),
                'cves'     => $cveIds,
            ];
        }

        $tenantName = '';
        if ($tenantId > 0) {
            $tenant = Database::fetchOne("SELECT name FROM tenants WHERE id = ?", [$tenantId]);
            if ($tenant === null) {
                return ['success' => false, 'error' => 'El tenant configurado no existe.'];
            }
            $tenantName = (string)$tenant['name'];
        }

        if (!$noAi) {
            $llm = class_exists('Module_Llm') ? new Module_Llm() : null;
            if ($llm === null || !$llm->isConfigured()) {
                return [
                    'success' => false,
                    'error'   => 'La IA no está configurada. Configura un perfil en Admin → APIs o activa «solo datos locales».',
                ];
            }
        }

        @set_time_limit(0);
        $sync = new CveSync();
        $available = [];
        $fetched = [];
        $failed = [];

        foreach ($cveIds as $cveId) {
            if (CveDatabase::fetchOne("SELECT cve_id FROM cve_catalog WHERE cve_id = ?", [$cveId]) !== null) {
                $available[] = $cveId;
                continue;
            }
            try {
                $sync->fetchAndStoreCve($cveId);
                $available[] = $cveId;
                $fetched[] = $cveId;
            } catch (Throwable $e) {
                $failed[] = $cveId . ' (' . $e->getMessage() . ')';
            }
        }

        if ($available === []) {
            return [
                'success' => false,
                'error'   => 'No se pudo descargar ninguno de los CVEs seleccionados.',
                'failed'  => $failed,
            ];
        }

        $defender = $this->buildDefenderContext($available, $tenantId, $tenantName);
        $defenderJson = $this->encodeJson($defender);
        $scheduledTags = ['Defender'];
        if ($tenantName !== '') {
            $scheduledTags[] = $tenantName;
        }
        $queued = $this->queueAiReport($available, 0, $noAi, $defenderJson, $scheduledTags, 'extended');
        $id = (int)$queued['report_id'];

        if ($groupId > 0) {
            $group = CveDatabase::fetchOne("SELECT id FROM software_groups WHERE id = ?", [$groupId]);
            if ($group !== null) {
                CveDatabase::update("UPDATE cve_ai_reports SET group_id = ? WHERE id = ?", [$groupId, $id]);
            }
        }

        $run = CveReportAi::runById($id);

        app_log('info', 'cve_ai', 'Informe automático desde Defender', [
            'id'       => $id,
            'cves'     => $available,
            'fetched'  => $fetched,
            'failed'   => $failed,
            'status'   => (string)($run['status'] ?? ''),
            'group_id' => $groupId,
        ]);

        return [
            'success'   => (string)($run['status'] ?? '') === 'done',
            'created'   => true,
            'report_id' => $id,
            'url'       => base_url('modules/cve/report-ai/' . $id),
            'status'    => (string)($run['status'] ?? ''),
            'cves'      => $available,
            'fetched'   => $fetched,
            'failed'    => $failed,
            'error'     => $run['error'] ?? null,
        ];
    }

    /**
     * Endpoint «Generar ahora» con la configuración guardada.
     */
    public function runScheduledDefenderReport(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        try {
            $result = $this->createScheduledDefenderReport([
                'limit'     => (int)setting_get('cve_def_report_limit', '10'),
                'tenant_id' => (int)setting_get('cve_def_report_tenant', '0'),
                'group_id'  => (int)setting_get('cve_def_report_group', '0'),
                'severity'  => (string)setting_get('cve_def_report_severity', ''),
                'exploited' => setting_get('cve_def_report_exploited', '0') === '1',
                'kev'       => setting_get('cve_def_report_kev', '0') === '1',
                'no_ai'     => setting_get('cve_def_report_no_ai', '0') === '1',
            ]);
            json_response($result);
        } catch (Throwable $e) {
            app_log('error', 'cve_ai', 'Error en el informe automático de Defender', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    /**
     * Agrega las vulnerabilidades de Defender por CVE (BBDD principal).
     */
    private function aggregateDefenderVulns(int $tenantId, string $q, int $limit = 500): array
    {
        $where = [];
        $params = [];
        if ($tenantId > 0) {
            $where[] = 'v.tenant_id = ?';
            $params[] = $tenantId;
        }
        if ($q !== '') {
            $where[] = 'v.cve_id LIKE ?';
            $params[] = '%' . strtoupper($q) . '%';
        }
        $whereSql = $where !== [] ? 'WHERE ' . implode(' AND ', $where) : '';
        $limit = max(1, min(1000, $limit));

        $rows = Database::fetchAll(
            "SELECT v.cve_id,
                    MAX(CASE UPPER(COALESCE(v.severity, ''))
                        WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) AS sev_rank,
                    MAX(v.cvss_v3) AS cvss,
                    MAX(v.epss) AS epss,
                    MAX(v.public_exploit) AS public_exploit,
                    MAX(v.exploit_verified) AS exploit_verified,
                    MAX(v.exposed_machines) AS exposed_machines,
                    COUNT(DISTINCT v.machine_id) AS machine_count,
                    GROUP_CONCAT(DISTINCT v.product_name) AS products,
                    GROUP_CONCAT(DISTINCT v.product_vendor) AS vendors,
                    GROUP_CONCAT(DISTINCT t.name) AS tenants
             FROM vulnerabilities v
             LEFT JOIN machines m ON m.id = v.machine_id
             LEFT JOIN tenants t ON t.id = v.tenant_id
             $whereSql
             GROUP BY v.cve_id
             ORDER BY public_exploit DESC, exploit_verified DESC, cvss DESC, epss DESC, machine_count DESC
             LIMIT $limit",
            $params
        );

        $labels = [4 => 'Critical', 3 => 'High', 2 => 'Medium', 1 => 'Low', 0 => ''];
        foreach ($rows as &$row) {
            $row['severity'] = $labels[(int)$row['sev_rank']] ?? '';
            $row['products'] = $this->splitCommaList((string)($row['products'] ?? ''));
            $row['vendors'] = $this->splitCommaList((string)($row['vendors'] ?? ''));
            $row['tenants'] = $this->splitCommaList((string)($row['tenants'] ?? ''));
            unset($row['sev_rank']);
        }
        unset($row);

        return $rows;
    }

    /**
     * Construye la foto de exposición (equipos, productos y tenants) por CVE.
     */
    private function buildDefenderContext(array $cveIds, int $tenantId = 0, string $tenantName = ''): array
    {
        $cveIds = array_values(array_filter(array_map('strval', $cveIds)));
        $context = [
            'generated_at' => date('c'),
            'tenant_id'    => $tenantId,
            'tenant_name'  => $tenantName,
            'cves'         => [],
        ];
        if ($cveIds === []) {
            return $context;
        }

        foreach ($cveIds as $cveId) {
            $context['cves'][$cveId] = [
                'machine_total'    => 0,
                'exposed_machines' => 0,
                'public_exploit'   => false,
                'exploit_verified' => false,
                'products'         => [],
                'machines'         => [],
                'tenants'          => [],
            ];
        }

        $ph = implode(',', array_fill(0, count($cveIds), '?'));
        $params = $cveIds;
        $tenantSql = '';
        if ($tenantId > 0) {
            $tenantSql = ' AND v.tenant_id = ?';
            $params[] = $tenantId;
        }

        $rows = Database::fetchAll(
            "SELECT v.cve_id, v.product_vendor, v.product_name, v.product_version, v.fixing_kb_id,
                    v.public_exploit, v.exploit_verified, v.exposed_machines,
                    m.machine_id, m.computer_dns_name, m.os_platform, m.os_version,
                    m.exposure_level, m.risk_score, m.last_seen, m.last_ip_address,
                    t.name AS tenant_name
             FROM vulnerabilities v
             LEFT JOIN machines m ON m.id = v.machine_id
             LEFT JOIN tenants t ON t.id = v.tenant_id
             WHERE v.cve_id IN ($ph)$tenantSql
             ORDER BY v.cve_id, m.exposure_level DESC, m.risk_score DESC
             LIMIT 5000",
            $params
        );

        $seenMachines = [];
        $seenProducts = [];

        foreach ($rows as $row) {
            $cveId = (string)$row['cve_id'];
            if (!isset($context['cves'][$cveId])) {
                continue;
            }

            $context['cves'][$cveId]['public_exploit'] = $context['cves'][$cveId]['public_exploit'] || !empty($row['public_exploit']);
            $context['cves'][$cveId]['exploit_verified'] = $context['cves'][$cveId]['exploit_verified'] || !empty($row['exploit_verified']);
            $context['cves'][$cveId]['exposed_machines'] = max(
                (int)$context['cves'][$cveId]['exposed_machines'],
                (int)($row['exposed_machines'] ?? 0)
            );

            if (!empty($row['tenant_name'])) {
                $tenantLabel = (string)$row['tenant_name'];
                if (!in_array($tenantLabel, $context['cves'][$cveId]['tenants'], true)) {
                    $context['cves'][$cveId]['tenants'][] = $tenantLabel;
                }
            }

            $machineKey = $cveId . '|' . (string)($row['machine_id'] ?? '');
            if (!isset($seenMachines[$machineKey])) {
                $seenMachines[$machineKey] = true;
                $context['cves'][$cveId]['machine_total']++;
                if (count($context['cves'][$cveId]['machines']) < 50) {
                    $context['cves'][$cveId]['machines'][] = [
                        'name'      => (string)($row['computer_dns_name'] ?? ''),
                        'os'        => trim((string)($row['os_platform'] ?? '') . ' ' . (string)($row['os_version'] ?? '')),
                        'exposure'  => (string)($row['exposure_level'] ?? ''),
                        'risk'      => (string)($row['risk_score'] ?? ''),
                        'last_seen' => (string)($row['last_seen'] ?? ''),
                        'ip'        => (string)($row['last_ip_address'] ?? ''),
                        'tenant'    => (string)($row['tenant_name'] ?? ''),
                    ];
                }
            }

            $productLabel = trim((string)($row['product_vendor'] ?? '') . ' ' . (string)($row['product_name'] ?? ''));
            if (!empty($row['product_version'])) {
                $productLabel .= ' ' . (string)$row['product_version'];
            }
            if (!empty($row['fixing_kb_id'])) {
                $productLabel .= ' (KB ' . (string)$row['fixing_kb_id'] . ')';
            }
            if ($productLabel === '') {
                continue;
            }

            $productKey = $cveId . '|' . $productLabel;
            if (!isset($seenProducts[$productKey])) {
                $seenProducts[$productKey] = true;
                if (count($context['cves'][$cveId]['products']) < 20) {
                    $context['cves'][$cveId]['products'][] = $productLabel;
                }
            }
        }

        return $context;
    }

    /**
     * @return string[]
     */
    private function splitCommaList(string $value): array
    {
        $parts = array_map('trim', explode(',', $value));
        return array_values(array_filter($parts, static fn($item) => $item !== ''));
    }

    /**
     * Datos completos de un informe para la página y para el panel derecho.
     */
    private function aiReportPayload(int $id): ?array
    {
        if ($id <= 0) {
            return null;
        }

        $report = CveDatabase::fetchOne("SELECT * FROM cve_ai_reports WHERE id = ?", [$id]);
        if ($report === null) {
            return null;
        }

        // Los informes con exposición de Defender contienen equipos: solo admins.
        if (!empty($report['defender_json']) && !Auth::isAdmin()) {
            return null;
        }

        $items = safe_json_decode((string)($report['data_json'] ?? ''), []);
        if (!is_array($items)) {
            $items = [];
        }

        $report['tags_array'] = CveReportAi::decodeTags((string)($report['tags'] ?? ''));
        $itemTags = [];
        $itemGroups = [];
        $itemMap = [];
        $itemRows = CveDatabase::fetchAll(
            "SELECT i.*, g.name AS group_name, g.kind AS group_kind
             FROM cve_ai_report_items i
             LEFT JOIN software_groups g ON g.id = i.group_id
             WHERE i.report_id = ?
             ORDER BY i.position, i.id",
            [$id]
        );
        foreach ($itemRows as $itemRow) {
            $cveId = (string)$itemRow['cve_id'];
            $tags = CveReportAi::decodeTags((string)($itemRow['tags'] ?? ''));
            $sections = safe_json_decode((string)($itemRow['sections_json'] ?? ''), []);
            if (!is_array($sections)) {
                $sections = [];
            }
            if ($sections === []) {
                $sections = CveReportAi::parseAiSections((string)($itemRow['ai_text'] ?? ''));
            }
            $groupName = (string)($itemRow['group_name'] ?? '');
            $itemMap[$cveId] = [
                'item_id'     => (int)$itemRow['id'],
                'tags'        => $tags,
                'group_id'    => (int)($itemRow['group_id'] ?? 0),
                'group_name'  => $groupName,
                'group_kind'  => (string)($itemRow['group_kind'] ?? ''),
                'ai_status'   => (string)($itemRow['status'] ?? ''),
                'ai_text'     => (string)($itemRow['ai_text'] ?? ''),
                'ai_sections' => $sections,
                'ai_model'    => (string)($itemRow['ai_model'] ?? ''),
                'ai_error'    => (string)($itemRow['ai_error'] ?? ''),
            ];
            foreach ($tags as $tag) {
                $itemTags[$tag] = true;
            }
            if ($groupName !== '') {
                $itemGroups[$groupName] = true;
            }
        }
        foreach ($items as &$item) {
            $cveId = (string)($item['cve_id'] ?? '');
            if (isset($itemMap[$cveId])) {
                $item = array_merge($item, $itemMap[$cveId]);
            } else {
                $item['tags'] = $report['tags_array'];
                $item['ai_sections'] = [];
                $item['ai_status'] = '';
            }
        }
        unset($item);
        $report['item_tags'] = array_keys($itemTags);
        $report['item_groups'] = array_keys($itemGroups);

        $aiText = trim((string)($report['ai_text'] ?? ''));
        if ($aiText === '' && empty($report['no_ai'])) {
            // Compatibilidad: informes antiguos guardados en formato ASCII.
            $aiText = CveReportAi::extractAiTextFromContent((string)($report['content_text'] ?? ''));
        }

        $report['group_name'] = '';
        $report['group_kind'] = '';
        if (!empty($report['group_id'])) {
            $group = CveDatabase::fetchOne(
                "SELECT name, kind FROM software_groups WHERE id = ?",
                [(int)$report['group_id']]
            );
            $report['group_name'] = (string)($group['name'] ?? '');
            $report['group_kind'] = (string)($group['kind'] ?? '');
        }

        $defender = null;
        if (!empty($report['defender_json'])) {
            $decodedDefender = safe_json_decode((string)$report['defender_json'], null);
            if (is_array($decodedDefender)) {
                $defender = $decodedDefender;
            }
        }

        return [
            'report'      => $report,
            'items'       => $items,
            'aiText'      => $aiText,
            'sections'    => CveReportAi::parseAiSections($aiText),
            'defender'    => $defender,
            'perItemMode' => $itemRows !== [],
        ];
    }

    /**
     * Crea el informe en estado «pending». La ejecución la lanza el navegador
     * contra reports/ai-run/{id} (sin loopback ni worker).
     */
    private function queueAiReport(
        array $cveIds,
        int $profileId,
        bool $noAi = false,
        ?string $defenderJson = null,
        array $tags = [],
        string $mode = 'extended'
    ): array {
        $token = bin2hex(random_bytes(24));
        $title = 'Informe CVE IA' . ($defenderJson !== null ? ' · Defender' : '') . ' · '
            . (count($cveIds) === 1 ? $cveIds[0] : count($cveIds) . ' CVEs')
            . ' · ' . date('d/m/Y H:i');
        $tagsJson = CveReportAi::tagsJson($tags);
        $mode = $mode === 'summary' ? 'summary' : 'extended';

        $id = CveDatabase::insert(
            "INSERT INTO cve_ai_reports
             (cve_ids, title, status, token, ai_profile_id, generated_by, no_ai, defender_json,
              mode, tags, total_items)
             VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                $this->encodeJson($cveIds),
                $title,
                $token,
                $profileId > 0 ? $profileId : null,
                Auth::id(),
                $noAi ? 1 : 0,
                $defenderJson,
                $mode,
                $tagsJson,
                count($cveIds),
            ]
        );

        return [
            'success'   => true,
            'report_id' => $id,
            'status'    => 'pending',
            'no_ai'     => $noAi,
            'defender'  => $defenderJson !== null,
            'url'       => base_url('modules/cve/report-ai/' . $id),
        ];
    }

    private function listAiReports(int $limit = 30): array
    {
        $limit = max(1, min(200, $limit));
        return CveDatabase::fetchAll(
            "SELECT r.id, r.cve_ids, r.title, r.status, r.ai_model, r.ai_error, r.no_ai,
                    r.revision, r.updated_at, r.group_id, g.name AS group_name, g.kind AS group_kind,
                    r.mode, r.tags, r.processed_items, r.total_items,
                    CASE WHEN r.defender_json IS NOT NULL AND r.defender_json <> '' THEN 1 ELSE 0 END AS has_defender,
                    (SELECT GROUP_CONCAT(DISTINCT g2.name)
                     FROM cve_ai_report_items i2
                     JOIN software_groups g2 ON g2.id = i2.group_id
                     WHERE i2.report_id = r.id) AS item_groups,
                    r.created_at, r.finished_at
             FROM cve_ai_reports r
             LEFT JOIN software_groups g ON g.id = r.group_id
             WHERE COALESCE(r.archived, 0) = 0
             ORDER BY r.created_at DESC, r.id DESC
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
            'companies'  => 0,
            'application_groups' => 0,
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
        $stats['companies'] = (int)(CveDatabase::fetchOne(
            "SELECT COUNT(*) AS c FROM software_groups WHERE kind = 'company'"
        )['c'] ?? 0);
        $stats['application_groups'] = (int)(CveDatabase::fetchOne(
            "SELECT COUNT(*) AS c FROM software_groups WHERE kind = 'application'"
        )['c'] ?? 0);
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
            "SELECT g.*,
                    (SELECT COUNT(*) FROM software_watchlist w WHERE w.group_id = g.id) AS software_count,
                    (SELECT COUNT(DISTINCT i.cve_id)
                     FROM cve_ai_report_items i
                     WHERE i.group_id = g.id) AS assigned_cve_count
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

    /**
     * CVEs asignados directamente a una empresa/grupo desde informes.
     * No incluye los CVEs detectados por software inventariado ni los de subgrupos.
     */
    private function listAssignedCves(int $groupId): array
    {
        if ($groupId <= 0) {
            return [];
        }

        $rows = CveDatabase::fetchAll(
            "SELECT i.cve_id, i.report_id, i.tags, i.updated_at AS item_updated_at,
                    r.title AS report_title, r.created_at AS report_created_at,
                    c.severity, c.cvss_v3_score, c.cvss_v2_score, c.description, c.published_at,
                    k.cve_id AS kev_id, k.date_added AS kev_date,
                    e.epss, e.percentile AS epss_percentile
             FROM cve_ai_report_items i
             JOIN cve_ai_reports r ON r.id = i.report_id
             LEFT JOIN cve_catalog c ON c.cve_id = i.cve_id
             LEFT JOIN cve_kev k ON k.cve_id = i.cve_id
             LEFT JOIN cve_epss e ON e.cve_id = i.cve_id
             WHERE i.group_id = ?
             ORDER BY CASE c.severity
                          WHEN 'Critical' THEN 0
                          WHEN 'High' THEN 1
                          WHEN 'Medium' THEN 2
                          WHEN 'Low' THEN 3
                          ELSE 4
                      END ASC,
                      COALESCE(c.cvss_v3_score, c.cvss_v2_score) DESC,
                      i.cve_id ASC,
                      r.created_at DESC",
            [$groupId]
        );

        $out = [];
        foreach ($rows as $row) {
            $cveId = (string)$row['cve_id'];
            if (!isset($out[$cveId])) {
                $out[$cveId] = [
                    'cve_id'       => $cveId,
                    'severity'     => (string)($row['severity'] ?? ''),
                    'cvss_v3_score'=> $row['cvss_v3_score'],
                    'cvss_v2_score'=> $row['cvss_v2_score'],
                    'description'  => (string)($row['description'] ?? ''),
                    'published_at' => $row['published_at'] ?? null,
                    'kev_id'       => $row['kev_id'] ?? null,
                    'kev_date'     => $row['kev_date'] ?? null,
                    'epss'         => $row['epss'] ?? null,
                    'epss_percentile' => $row['epss_percentile'] ?? null,
                    'assigned_at'  => (string)($row['item_updated_at'] ?? $row['report_created_at'] ?? ''),
                    'tags'         => [],
                    'reports'      => [],
                ];
            }

            $reportId = (int)$row['report_id'];
            $out[$cveId]['reports'][$reportId] = [
                'id'         => $reportId,
                'title'      => (string)($row['report_title'] ?? ''),
                'created_at' => (string)($row['report_created_at'] ?? ''),
            ];

            $assignedAt = (string)($row['item_updated_at'] ?? $row['report_created_at'] ?? '');
            if ($assignedAt > (string)$out[$cveId]['assigned_at']) {
                $out[$cveId]['assigned_at'] = $assignedAt;
            }

            foreach (CveReportAi::decodeTags((string)($row['tags'] ?? '')) as $tag) {
                $out[$cveId]['tags'][$tag] = true;
            }
        }

        $exploitCounts = CveExploit::countsByCve(array_keys($out));
        foreach ($out as $cveId => &$cve) {
            $cve['tags'] = array_keys($cve['tags']);
            $cve['reports'] = array_values($cve['reports']);
            $cve['exploit_total'] = (int)($exploitCounts[$cveId]['total'] ?? 0);
            $cve['exploit_sources'] = $exploitCounts[$cveId]['sources'] ?? [];
        }
        unset($cve);

        return array_values($out);
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
            "SELECT w.*, g.name AS group_name, g.kind AS group_kind, cg.name AS company_name, c.cpe_name,
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
             LEFT JOIN software_groups cg
                    ON cg.id = CASE WHEN g.kind = 'company' THEN g.id ELSE g.company_id END
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

        // Lista de CVEs pegada en Catálogo (máximo 200 para la vista).
        $cvesRaw = trim((string)($filters['cves'] ?? ''));
        $cvesList = $cvesRaw !== '' ? CveReportAi::normalizeCveIds($cvesRaw, 200) : [];
        if ($cvesList !== []) {
            $placeholders = implode(',', array_fill(0, count($cvesList), '?'));
            $where[] = "c.cve_id IN ($placeholders)";
            foreach ($cvesList as $cveId) {
                $params[] = $cveId;
            }
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
                     WHERE mw2.cve_id = c.cve_id) AS matched_software,
                    (SELECT GROUP_CONCAT(DISTINCT cg3.name)
                     FROM cve_watchlist_match mw3
                     JOIN software_watchlist sw3 ON sw3.id = mw3.watchlist_id
                     JOIN software_groups ag3 ON ag3.id = sw3.group_id
                     LEFT JOIN software_groups cg3
                            ON cg3.id = CASE WHEN ag3.kind = 'company' THEN ag3.id ELSE ag3.company_id END
                     WHERE mw3.cve_id = c.cve_id AND cg3.name IS NOT NULL) AS matched_companies,
                    (SELECT GROUP_CONCAT(DISTINCT ag4.name)
                     FROM cve_watchlist_match mw4
                     JOIN software_watchlist sw4 ON sw4.id = mw4.watchlist_id
                     JOIN software_groups ag4 ON ag4.id = sw4.group_id
                     WHERE mw4.cve_id = c.cve_id AND ag4.kind = 'application') AS matched_groups
             FROM cve_catalog c
             $joins
             $whereSql
             ORDER BY $orderSql
             LIMIT ? OFFSET ?",
            $params
        );

        $missing = [];
        if ($cvesList !== []) {
            $placeholders = implode(',', array_fill(0, count($cvesList), '?'));
            $foundRows = CveDatabase::fetchAll(
                "SELECT cve_id FROM cve_catalog WHERE cve_id IN ($placeholders)",
                $cvesList
            );
            $found = array_map('strval', array_column($foundRows, 'cve_id'));
            $missing = array_values(array_diff($cvesList, $found));
        }

        return [
            'data'       => $rows,
            'total'      => $total,
            'page'       => $page,
            'perPage'    => $perPage,
            'totalPages' => (int)ceil($total / $perPage),
            'requested'  => count($cvesList),
            'missing'    => $missing,
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
