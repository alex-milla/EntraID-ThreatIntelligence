<?php
/**
 * Módulo: Remediación.
 *
 * Gestión de tareas de remediación por organización (tenant de Graph o manual),
 * con SLA, parcheo, evidencia y asistente IA para dudas de implementación,
 * controles, verificación y rollback.
 */

declare(strict_types=1);

class Module_Remediation extends BaseModule
{
    public function key(): string { return 'remediation'; }
    public function name(): string { return 'Remediación'; }
    public function description(): string { return 'Tareas de remediación, SLA y asistente IA'; }
    public function version(): string { return '0.1.0'; }

    public function requiredPermissions(): array { return []; }
    public function isSyncable(): bool { return false; }
    public function sync(int $tenantId): array { return ['success' => true, 'records' => 0, 'skipped' => true]; }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Remediación',
            'url'   => base_url('modules/remediation'),
            'icon'  => 'shield',
            'group' => 'Seguridad',
            'after' => 'cve',
        ];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',              'handler' => [$this, 'index']],
            ['method' => 'GET',  'pattern' => 'cve-search',    'handler' => [$this, 'cveSearch']],
            ['method' => 'POST', 'pattern' => 'orgs/save',     'handler' => [$this, 'saveOrg']],
            ['method' => 'POST', 'pattern' => 'orgs/delete',   'handler' => [$this, 'deleteOrg']],
            ['method' => 'POST', 'pattern' => 'tasks/save',    'handler' => [$this, 'saveTask']],
            ['method' => 'POST', 'pattern' => 'tasks/delete',  'handler' => [$this, 'deleteTask']],
            ['method' => 'POST', 'pattern' => 'tasks/import',  'handler' => [$this, 'importTasks']],
            ['method' => 'POST', 'pattern' => 'tasks/plan',    'handler' => [$this, 'savePlan']],
            ['method' => 'POST', 'pattern' => 'ask',           'handler' => [$this, 'ask']],
            ['method' => 'POST', 'pattern' => 'chats/delete',  'handler' => [$this, 'deleteChat']],
            ['method' => 'POST', 'pattern' => 'settings/save', 'handler' => [$this, 'saveSettings']],
        ];
    }

    // ============================================================
    // Página principal
    // ============================================================

    public function index(array $params = []): void
    {
        Auth::require();

        $isAdmin = Auth::isAdmin();
        $tab = (string)($_GET['tab'] ?? 'tasks');
        if (!in_array($tab, ['tasks', 'assistant', 'metrics', 'settings'], true)) {
            $tab = 'tasks';
        }
        if ($tab === 'settings' && !$isAdmin) {
            $tab = 'tasks';
        }

        $orgs = $this->orgs();
        if ($orgs === []) {
            Database::query(
                "INSERT OR IGNORE INTO remediation_orgs (name, kind, created_by) VALUES (?, 'manual', ?)",
                ['Mi organización', Auth::id()]
            );
            $orgs = $this->orgs();
        }

        $selectedOrgId = (int)($_GET['org'] ?? 0);
        if ($selectedOrgId <= 0 || $this->getOrg($selectedOrgId) === null) {
            $selectedOrgId = (int)($orgs[0]['id'] ?? 0);
        }
        $org = $this->getOrg($selectedOrgId);

        $filters = [
            'status'   => (string)($_GET['status'] ?? ''),
            'severity' => (string)($_GET['severity'] ?? ''),
            'overdue'  => !empty($_GET['overdue']),
            'q'        => trim((string)($_GET['q'] ?? '')),
        ];

        $tasks = $this->listTasks($selectedOrgId, $filters);
        $taskId = (int)($_GET['task'] ?? 0);
        $selectedTask = $taskId > 0 ? $this->getTask($taskId) : null;
        if ($selectedTask !== null && (int)$selectedTask['org_id'] !== $selectedOrgId) {
            $selectedTask = null;
        }

        $chats = $this->listChats($selectedOrgId);
        $chatId = (int)($_GET['chat'] ?? 0);
        $chat = $chatId > 0 ? $this->getChat($chatId) : null;
        if ($chat !== null && (int)($chat['org_id'] ?? 0) !== $selectedOrgId) {
            $chat = null;
        }
        $messages = $chat !== null ? $this->messages((int)$chat['id']) : [];

        $stats = $this->stats($selectedOrgId);
        $sla = $this->slaSettings();
        $llmConfigured = class_exists('Module_Llm') && (new Module_Llm())->isConfigured();
        $profiles = llm_profile_list();
        $cveQuery = strtoupper(trim((string)($_GET['cve'] ?? '')));
        if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveQuery)) {
            $cveQuery = '';
        }
        $cveData = $selectedTask !== null ? $this->cveData((string)$selectedTask['cve_id']) : null;
        $cveContext = $cveData !== null ? $cveData : ($cveQuery !== '' ? $this->cveData($cveQuery) : null);
        if ($selectedTask === null && $cveQuery !== '') {
            $cveData = $cveContext;
        }

        echo $this->page('index', [
            'isAdmin'        => $isAdmin,
            'tab'            => $tab,
            'orgs'           => $orgs,
            'org'            => $org,
            'selectedOrgId'  => $selectedOrgId,
            'tenants'        => Database::fetchAll("SELECT id, name FROM tenants ORDER BY name"),
            'tasks'          => $tasks,
            'filters'        => $filters,
            'selectedTask'   => $selectedTask,
            'cveData'        => $cveData,
            'cveQuery'       => $cveQuery,
            'cveContext'     => $cveContext,
            'chats'          => $chats,
            'chat'           => $chat,
            'messages'       => $messages,
            'stats'          => $stats,
            'sla'            => $sla,
            'llmConfigured'  => $llmConfigured,
            'profiles'       => $profiles,
            'taskProfileId'  => (int)(llm_task_profile('remediation_assistant') ?? 0),
        ]);
    }

    // ============================================================
    // Organizaciones
    // ============================================================

    public function saveOrg(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        $name = trim((string)($_POST['name'] ?? ''));
        $kind = (string)($_POST['kind'] ?? 'manual');
        $tenantId = (int)($_POST['tenant_id'] ?? 0);
        $notes = trim((string)($_POST['notes'] ?? ''));

        if ($name === '') {
            flash('error', 'El nombre de la organización es obligatorio.');
            redirect(base_url('modules/remediation'));
        }
        if (!in_array($kind, ['manual', 'tenant'], true)) {
            $kind = 'manual';
        }
        if ($kind === 'tenant') {
            $tenant = $tenantId > 0 ? Database::fetchOne("SELECT id FROM tenants WHERE id = ?", [$tenantId]) : null;
            if ($tenant === null) {
                flash('error', 'Selecciona un tenant válido para la organización.');
                redirect(base_url('modules/remediation'));
            }
        } else {
            $tenantId = 0;
        }

        try {
            if ($id > 0) {
                Database::update(
                    "UPDATE remediation_orgs
                     SET name = ?, kind = ?, tenant_id = ?, notes = ?, updated_at = datetime('now')
                     WHERE id = ?",
                    [$name, $kind, $tenantId > 0 ? $tenantId : null, $notes !== '' ? $notes : null, $id]
                );
                flash('success', 'Organización actualizada.');
            } else {
                $id = Database::insert(
                    "INSERT INTO remediation_orgs (name, kind, tenant_id, notes, created_by)
                     VALUES (?, ?, ?, ?, ?)",
                    [$name, $kind, $tenantId > 0 ? $tenantId : null, $notes !== '' ? $notes : null, Auth::id()]
                );
                flash('success', 'Organización creada.');
            }
            log_activity('remediation.org_saved', ['id' => $id, 'name' => $name, 'kind' => $kind]);
        } catch (Throwable $e) {
            $message = str_contains($e->getMessage(), 'UNIQUE')
                ? 'Ya existe una organización con ese nombre.'
                : 'No se pudo guardar la organización: ' . $e->getMessage();
            flash('error', $message);
        }

        redirect(base_url('modules/remediation?org=' . $id));
    }

    public function deleteOrg(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            Database::query("DELETE FROM remediation_orgs WHERE id = ?", [$id]);
            log_activity('remediation.org_deleted', ['id' => $id]);
            flash('success', 'Organización eliminada, junto con sus tareas y conversaciones.');
        }
        redirect(base_url('modules/remediation'));
    }

    // ============================================================
    // Tareas
    // ============================================================

    public function saveTask(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        $orgId = (int)($_POST['org_id'] ?? 0);
        $org = $this->getOrg($orgId);
        if ($org === null) {
            flash('error', 'La organización no existe.');
            redirect(base_url('modules/remediation'));
        }

        $status = (string)($_POST['status'] ?? 'open');
        if (!in_array($status, self::statuses(), true)) {
            $status = 'open';
        }
        $owner = trim((string)($_POST['owner'] ?? ''));
        $dueAt = trim((string)($_POST['due_at'] ?? ''));
        $patchKb = trim((string)($_POST['patch_kb'] ?? ''));
        $fixedVersion = trim((string)($_POST['fixed_version'] ?? ''));
        $evidence = trim((string)($_POST['evidence'] ?? ''));
        $notes = trim((string)($_POST['notes'] ?? ''));
        $exceptionUntil = trim((string)($_POST['exception_until'] ?? ''));

        if ($id > 0) {
            $task = $this->getTask($id);
            if ($task === null || (int)$task['org_id'] !== $orgId) {
                flash('error', 'La tarea no existe.');
                redirect(base_url('modules/remediation?org=' . $orgId));
            }

            $resolvedAt = $task['resolved_at'];
            if (in_array($status, self::resolvedStatuses(), true)) {
                if (empty($resolvedAt)) {
                    $resolvedAt = date('Y-m-d H:i:s');
                }
            } else {
                // Reabrir una tarea limpia la fecha de resolución (MTTR real).
                $resolvedAt = null;
            }

            Database::update(
                "UPDATE remediation_tasks
                 SET status = ?, owner = ?, due_at = ?, resolved_at = ?, patch_kb = ?,
                     fixed_version = ?, evidence = ?, notes = ?, exception_until = ?,
                     updated_at = datetime('now')
                 WHERE id = ?",
                [
                    $status,
                    $owner !== '' ? $owner : null,
                    $dueAt !== '' ? $dueAt : null,
                    $resolvedAt,
                    $patchKb !== '' ? $patchKb : null,
                    $fixedVersion !== '' ? $fixedVersion : null,
                    $evidence !== '' ? $evidence : null,
                    $notes !== '' ? $notes : null,
                    $exceptionUntil !== '' ? $exceptionUntil : null,
                    $id,
                ]
            );
            log_activity('remediation.task_updated', ['id' => $id, 'status' => $status]);
            flash('success', 'Tarea actualizada.');
            redirect(base_url('modules/remediation?org=' . $orgId . '&task=' . $id));
        }

        $cveId = strtoupper(trim((string)($_POST['cve_id'] ?? '')));
        if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId)) {
            flash('error', 'Introduce un CVE válido (CVE-AAAA-NNNN).');
            redirect(base_url('modules/remediation?org=' . $orgId));
        }

        $existing = Database::fetchOne(
            "SELECT id FROM remediation_tasks WHERE org_id = ? AND cve_id = ?",
            [$orgId, $cveId]
        );
        if ($existing !== null) {
            flash('info', 'Ese CVE ya tiene una tarea en esta organización.');
            redirect(base_url('modules/remediation?org=' . $orgId . '&task=' . (int)$existing['id']));
        }

        $data = $this->cveData($cveId);
        if ($data === null) {
            try {
                @set_time_limit(0);
                (new CveSync())->fetchAndStoreCve($cveId);
                $data = $this->cveData($cveId);
            } catch (Throwable $e) {
                app_log('warning', 'remediation', 'No se pudo descargar el CVE', ['cve' => $cveId, 'error' => $e->getMessage()]);
            }
        }
        if ($data === null) {
            flash('error', 'No se pudo obtener el CVE del catálogo. Sincroniza NVD o usa «Importar desde Defender».');
            redirect(base_url('modules/remediation?org=' . $orgId));
        }

        $catalog = $data['catalog'];
        $kevDue = (string)($data['kev']['due_date'] ?? '');
        if ($dueAt === '') {
            $dueAt = $this->computeDue((string)($catalog['severity'] ?? ''), $kevDue);
        }

        $machines = $this->parseMachines((string)($_POST['machines'] ?? ''));
        $title = trim((string)($catalog['description'] ?? ''));
        $title = $title !== '' ? truncate($title, 90) : ('Remediación de ' . $cveId);

        $newId = Database::insert(
            "INSERT INTO remediation_tasks
             (org_id, cve_id, title, severity, cvss, epss, kev, status, owner, due_at, resolved_at,
              patch_kb, fixed_version, evidence, notes, exception_until, machine_count, machines_json,
              source, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual', ?)",
            [
                $orgId,
                $cveId,
                $title,
                (string)($catalog['severity'] ?? ''),
                $catalog['cvss_v3_score'] !== null ? (float)$catalog['cvss_v3_score'] : null,
                ($data['epss'] !== null && $data['epss']['epss'] !== null) ? (float)$data['epss']['epss'] : null,
                $data['kev'] !== null ? 1 : 0,
                $status,
                $owner !== '' ? $owner : null,
                $dueAt !== '' ? $dueAt : null,
                in_array($status, self::resolvedStatuses(), true) ? date('Y-m-d H:i:s') : null,
                $patchKb !== '' ? $patchKb : null,
                $fixedVersion !== '' ? $fixedVersion : null,
                $evidence !== '' ? $evidence : null,
                $notes !== '' ? $notes : null,
                $exceptionUntil !== '' ? $exceptionUntil : null,
                count($machines),
                $machines !== [] ? json_encode($machines, JSON_UNESCAPED_UNICODE) : null,
                Auth::id(),
            ]
        );

        log_activity('remediation.task_created', ['id' => $newId, 'org' => $orgId, 'cve' => $cveId]);
        flash('success', 'Tarea creada.');
        redirect(base_url('modules/remediation?org=' . $orgId . '&task=' . $newId));
    }

    public function deleteTask(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        $orgId = (int)($_POST['org_id'] ?? 0);
        if ($id > 0) {
            Database::query("DELETE FROM remediation_tasks WHERE id = ? AND org_id = ?", [$id, $orgId]);
            log_activity('remediation.task_deleted', ['id' => $id, 'org' => $orgId]);
            flash('success', 'Tarea eliminada.');
        }
        redirect(base_url('modules/remediation?org=' . $orgId));
    }

    public function importTasks(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $orgId = (int)($_POST['org_id'] ?? 0);
        $org = $this->getOrg($orgId);
        if ($org === null || $org['kind'] !== 'tenant' || empty($org['tenant_id'])) {
            flash('error', 'Solo se puede importar desde Defender en organizaciones vinculadas a un tenant.');
            redirect(base_url('modules/remediation?org=' . $orgId));
        }

        $severity = strtoupper(trim((string)($_POST['severity'] ?? '')));
        $exploited = !empty($_POST['exploited']);
        $minMachines = max(0, (int)($_POST['min_machines'] ?? 0));
        $limit = max(1, min(200, (int)($_POST['limit'] ?? 50)));

        $where = ['v.tenant_id = ?'];
        $paramsSql = [(int)$org['tenant_id']];
        if (in_array($severity, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], true)) {
            $where[] = 'UPPER(v.severity) = ?';
            $paramsSql[] = $severity;
        }
        if ($exploited) {
            $where[] = 'v.public_exploit = 1';
        }

        $rows = Database::fetchAll(
            "SELECT v.cve_id,
                    MAX(v.cvss_v3) AS cvss,
                    MAX(v.epss) AS epss,
                    MAX(v.fixing_kb_id) AS fixing_kb,
                    MAX(CASE UPPER(COALESCE(v.severity, ''))
                        WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) AS sev_rank,
                    MAX(v.public_exploit) AS public_exploit,
                    MAX(v.exploit_verified) AS exploit_verified,
                    COUNT(DISTINCT v.machine_id) AS machine_count
             FROM vulnerabilities v
             WHERE " . implode(' AND ', $where) . "
             GROUP BY v.cve_id
             HAVING COUNT(DISTINCT v.machine_id) >= CAST(? AS INTEGER)
             ORDER BY sev_rank DESC, public_exploit DESC, cvss DESC, epss DESC, machine_count DESC
             LIMIT " . $limit,
            array_merge($paramsSql, [$minMachines])
        );

        $labels = [4 => 'Critical', 3 => 'High', 2 => 'Medium', 1 => 'Low', 0 => ''];
        $imported = 0;
        $skipped = 0;

        foreach ($rows as $row) {
            $cveId = strtoupper((string)$row['cve_id']);
            $existing = Database::fetchOne(
                "SELECT id FROM remediation_tasks WHERE org_id = ? AND cve_id = ?",
                [$orgId, $cveId]
            );
            if ($existing !== null) {
                $skipped++;
                continue;
            }

            $kev = CveDatabase::fetchOne("SELECT due_date FROM cve_kev WHERE cve_id = ?", [$cveId]);
            $machines = Database::fetchAll(
                "SELECT m.computer_dns_name, m.os_platform, m.os_version, m.exposure_level
                 FROM vulnerabilities v
                 JOIN machines m ON m.id = v.machine_id
                 WHERE v.tenant_id = ? AND v.cve_id = ?
                 GROUP BY m.id
                 ORDER BY m.exposure_level DESC, m.computer_dns_name
                 LIMIT 50",
                [(int)$org['tenant_id'], $cveId]
            );
            $machineList = [];
            foreach ($machines as $machine) {
                $machineList[] = [
                    'name'     => (string)($machine['computer_dns_name'] ?? ''),
                    'os'       => trim((string)($machine['os_platform'] ?? '') . ' ' . (string)($machine['os_version'] ?? '')),
                    'exposure' => (string)($machine['exposure_level'] ?? ''),
                ];
            }

            $severityLabel = $labels[(int)$row['sev_rank']] ?? '';
            $dueAt = $this->computeDue($severityLabel, $kev !== null ? (string)($kev['due_date'] ?? '') : '');

            Database::insert(
                "INSERT INTO remediation_tasks
                 (org_id, cve_id, title, severity, cvss, epss, kev, status, due_at, patch_kb,
                  machine_count, machines_json, source, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, 'defender', ?)",
                [
                    $orgId,
                    $cveId,
                    'Remediación de ' . $cveId,
                    $severityLabel,
                    $row['cvss'] !== null ? (float)$row['cvss'] : null,
                    $row['epss'] !== null ? (float)$row['epss'] : null,
                    $kev !== null ? 1 : 0,
                    $dueAt,
                    !empty($row['fixing_kb']) ? (string)$row['fixing_kb'] : null,
                    (int)$row['machine_count'],
                    $machineList !== [] ? json_encode($machineList, JSON_UNESCAPED_UNICODE) : null,
                    Auth::id(),
                ]
            );
            $imported++;
        }

        log_activity('remediation.tasks_imported', ['org' => $orgId, 'imported' => $imported, 'skipped' => $skipped]);
        flash('success', 'Importación completada: ' . $imported . ' tareas nuevas, ' . $skipped . ' ya existentes.');
        redirect(base_url('modules/remediation?org=' . $orgId));
    }

    // ============================================================
    // Asistente IA
    // ============================================================

    public function ask(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        try {
            $raw = file_get_contents('php://input');
            $input = json_decode((string)$raw, true);
            if (!is_array($input)) {
                $input = $_POST;
            }

            if (!class_exists('Module_Llm')) {
                json_response(['success' => false, 'error' => 'El módulo de IA no está activo. Actívalo en Admin → Módulos.'], 400);
            }
            $llm = new Module_Llm();
            $profileId = (int)($input['profile_id'] ?? 0);
            if ($profileId <= 0) {
                $profileId = (int)(llm_task_profile('remediation_assistant') ?? 0);
            }
            if (!$llm->isConfigured($profileId > 0 ? $profileId : null)) {
                json_response(['success' => false, 'error' => 'La IA no está configurada. Revisa Admin → APIs.'], 400);
            }

            $question = trim((string)($input['question'] ?? ''));
            if ($question === '' || mb_strlen($question, 'UTF-8') > 4000) {
                json_response(['success' => false, 'error' => 'La pregunta está vacía o supera los 4.000 caracteres.'], 400);
            }

            $orgId = (int)($input['org_id'] ?? 0);
            $org = $this->getOrg($orgId);
            if ($org === null) {
                json_response(['success' => false, 'error' => 'Selecciona una organización.'], 400);
            }

            $taskId = (int)($input['task_id'] ?? 0);
            $task = $taskId > 0 ? $this->getTask($taskId) : null;
            if ($task !== null && (int)$task['org_id'] !== $orgId) {
                $task = null;
            }

            $cveId = $task !== null ? (string)$task['cve_id'] : strtoupper(trim((string)($input['cve_id'] ?? '')));
            if ($cveId !== '' && !preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId)) {
                $cveId = '';
            }
            $cve = $cveId !== '' ? $this->cveData($cveId) : null;

            $chatId = (int)($input['chat_id'] ?? 0);
            $chat = $chatId > 0 ? $this->getChat($chatId) : null;
            if ($chat !== null && (int)($chat['org_id'] ?? 0) !== $orgId) {
                $chat = null;
            }

            [$system, $userPrompt] = $this->buildAiPrompt($org, $task, $cve, $question);

            $result = $llm->chat(
                $system,
                $userPrompt,
                ['max_tokens' => 1500, 'temperature' => 0.2],
                $profileId > 0 ? $profileId : null
            );

            if (empty($result['success'])) {
                json_response(['success' => false, 'error' => (string)($result['error'] ?? 'Error del proveedor de IA.')], 502);
            }

            $content = trim((string)($result['content'] ?? ''));
            if ($content === '') {
                json_response(['success' => false, 'error' => 'La IA devolvió una respuesta vacía.'], 502);
            }

            if ($chat === null) {
                $chatId = Database::insert(
                    "INSERT INTO remediation_chats (org_id, user_id, context_type, context_ref, title)
                     VALUES (?, ?, ?, ?, ?)",
                    [
                        $orgId,
                        Auth::id(),
                        $task !== null ? 'task' : ($cveId !== '' ? 'cve' : 'general'),
                        $task !== null ? (string)$task['id'] : $cveId,
                        truncate($question, 90),
                    ]
                );
            }

            Database::insert(
                "INSERT INTO remediation_messages (chat_id, role, content) VALUES (?, 'user', ?)",
                [$chatId, $question]
            );
            Database::insert(
                "INSERT INTO remediation_messages (chat_id, role, content, model) VALUES (?, 'assistant', ?, ?)",
                [$chatId, $content, (string)($result['model'] ?? '')]
            );
            Database::update(
                "UPDATE remediation_chats SET updated_at = datetime('now') WHERE id = ?",
                [$chatId]
            );

            app_log('info', 'remediation', 'Consulta IA', [
                'chat' => $chatId,
                'org'  => $orgId,
                'cve'  => $cveId,
            ]);

            json_response([
                'success'      => true,
                'chat_id'      => $chatId,
                'content'      => $content,
                'content_html' => (string)($result['content_html'] ?? ''),
                'model'        => (string)($result['model'] ?? ''),
            ]);
        } catch (Throwable $e) {
            app_log('error', 'remediation', 'Error en la consulta IA', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    public function savePlan(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        try {
            $input = json_decode((string)file_get_contents('php://input'), true);
            if (!is_array($input)) {
                $input = $_POST;
            }
            $taskId = (int)($input['task_id'] ?? 0);
            $content = trim((string)($input['content'] ?? ''));
            $task = $taskId > 0 ? $this->getTask($taskId) : null;
            if ($task === null) {
                json_response(['success' => false, 'error' => 'Tarea no encontrada.'], 404);
            }
            if ($content === '') {
                json_response(['success' => false, 'error' => 'No hay contenido para guardar.'], 400);
            }

            $plan = trim((string)($task['plan'] ?? ''));
            $plan = $plan !== '' ? $plan . "\n\n---\n\n" . $content : $content;

            Database::update(
                "UPDATE remediation_tasks SET plan = ?, updated_at = datetime('now') WHERE id = ?",
                [truncate($plan, 20000), $taskId]
            );
            log_activity('remediation.plan_saved', ['id' => $taskId]);

            json_response(['success' => true]);
        } catch (Throwable $e) {
            json_response(['success' => false, 'error' => $e->getMessage()], 500);
        }
    }

    public function deleteChat(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $id = (int)($_POST['id'] ?? 0);
        $chat = $id > 0 ? $this->getChat($id) : null;
        if ($chat !== null) {
            Database::query("DELETE FROM remediation_chats WHERE id = ?", [$id]);
            log_activity('remediation.chat_deleted', ['id' => $id]);
            flash('success', 'Conversación eliminada.');
        }
        redirect(base_url('modules/remediation?tab=assistant&org=' . (int)($chat['org_id'] ?? 0)));
    }

    // ============================================================
    // Ajustes y utilidades
    // ============================================================

    public function saveSettings(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        foreach (['critical' => 7, 'high' => 30, 'medium' => 90, 'low' => 180] as $key => $default) {
            $value = max(1, min(365, (int)($_POST['sla_' . $key] ?? $default)));
            setting_set('remediation_sla_' . $key, (string)$value);
        }
        flash('success', 'Ajustes de SLA guardados.');
        redirect(base_url('modules/remediation?tab=settings&org=' . (int)($_POST['org_id'] ?? 0)));
    }

    public function cveSearch(array $params = []): void
    {
        Auth::require();

        $q = trim((string)($_GET['q'] ?? ''));
        if ($q === '') {
            json_response(['success' => true, 'results' => []]);
        }

        $like = '%' . $q . '%';
        $rows = CveDatabase::fetchAll(
            "SELECT cve_id, severity, cvss_v3_score, description
             FROM cve_catalog
             WHERE cve_id LIKE ? OR description LIKE ?
             ORDER BY published_at DESC
             LIMIT 20",
            [$like, $like]
        );

        $results = [];
        foreach ($rows as $row) {
            $results[] = [
                'cve_id'   => (string)$row['cve_id'],
                'severity' => (string)($row['severity'] ?? ''),
                'cvss'     => $row['cvss_v3_score'] !== null ? (float)$row['cvss_v3_score'] : null,
                'summary'  => truncate((string)($row['description'] ?? ''), 120),
            ];
        }

        json_response(['success' => true, 'results' => $results]);
    }

    private function orgs(): array
    {
        return Database::fetchAll(
            "SELECT o.*, t.name AS tenant_name
             FROM remediation_orgs o
             LEFT JOIN tenants t ON t.id = o.tenant_id
             ORDER BY o.name"
        );
    }

    private function getOrg(int $id): ?array
    {
        if ($id <= 0) {
            return null;
        }
        return Database::fetchOne(
            "SELECT o.*, t.name AS tenant_name
             FROM remediation_orgs o
             LEFT JOIN tenants t ON t.id = o.tenant_id
             WHERE o.id = ?",
            [$id]
        );
    }

    private function listTasks(int $orgId, array $filters = []): array
    {
        $where = ['org_id = ?'];
        $params = [$orgId];

        if (!empty($filters['status']) && in_array($filters['status'], self::statuses(), true)) {
            $where[] = 'status = ?';
            $params[] = (string)$filters['status'];
        }
        if (!empty($filters['severity'])) {
            $where[] = 'severity = ?';
            $params[] = (string)$filters['severity'];
        }
        if (!empty($filters['overdue'])) {
            $where[] = "due_at IS NOT NULL AND due_at < date('now') AND status NOT IN ('patched','mitigated','accepted','false_positive')";
        }
        if (!empty($filters['q'])) {
            $where[] = '(cve_id LIKE ? OR title LIKE ? OR owner LIKE ?)';
            $like = '%' . $filters['q'] . '%';
            $params[] = $like;
            $params[] = $like;
            $params[] = $like;
        }

        return Database::fetchAll(
            "SELECT * FROM remediation_tasks WHERE " . implode(' AND ', $where) . "
             ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
                      due_at IS NULL, due_at ASC, id DESC
             LIMIT 300",
            $params
        );
    }

    private function getTask(int $id): ?array
    {
        if ($id <= 0) {
            return null;
        }
        return Database::fetchOne("SELECT * FROM remediation_tasks WHERE id = ?", [$id]);
    }

    private function listChats(int $orgId): array
    {
        return Database::fetchAll(
            "SELECT id, org_id, title, context_type, context_ref, updated_at
             FROM remediation_chats
             WHERE org_id = ? AND (user_id = ? OR CAST(? AS INTEGER) = 1)
             ORDER BY updated_at DESC, id DESC
             LIMIT 50",
            [$orgId, Auth::id(), Auth::isAdmin() ? 1 : 0]
        );
    }

    private function getChat(int $id): ?array
    {
        if ($id <= 0) {
            return null;
        }
        return Database::fetchOne(
            "SELECT * FROM remediation_chats WHERE id = ? AND (user_id = ? OR CAST(? AS INTEGER) = 1)",
            [$id, Auth::id(), Auth::isAdmin() ? 1 : 0]
        );
    }

    private function messages(int $chatId): array
    {
        return Database::fetchAll(
            "SELECT role, content, model, created_at FROM remediation_messages WHERE chat_id = ? ORDER BY id ASC",
            [$chatId]
        );
    }

    private function cveData(string $cveId): ?array
    {
        if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $cveId)) {
            return null;
        }
        $catalog = CveDatabase::fetchOne("SELECT * FROM cve_catalog WHERE cve_id = ?", [$cveId]);
        if ($catalog === null) {
            return null;
        }
        return [
            'catalog' => $catalog,
            'kev'     => CveDatabase::fetchOne("SELECT * FROM cve_kev WHERE cve_id = ?", [$cveId]),
            'epss'    => CveDatabase::fetchOne("SELECT * FROM cve_epss WHERE cve_id = ?", [$cveId]),
        ];
    }

    private function buildAiPrompt(array $org, ?array $task, ?array $cve, string $question): array
    {
        $system = llm_prompt(
            'remediation.assistant.system',
            'Eres un ingeniero sénior de vulnerabilidades, gestión de parches y hardening (CIS Benchmarks). '
            . 'Respondes en español, con precisión técnica y pasos concretos. Distingue siempre entre implementación, '
            . 'verificación y rollback. Mantén en inglés los términos técnicos habituales (RCE, KB, GPO, WAF, etc.). '
            . 'No inventes versiones, KB ni URLs: si falta información, dilo. No repitas el contexto; ve al grano.'
        );

        $lines = [];
        $lines[] = 'ORGANIZACIÓN: ' . (string)$org['name']
            . ' (' . ($org['kind'] === 'tenant' ? 'tenant conectado a Defender' : 'organización manual, sin Graph') . ')';
        if (!empty($org['notes'])) {
            $lines[] = 'Notas de la organización: ' . truncate((string)$org['notes'], 600);
        }

        if ($cve !== null) {
            $c = $cve['catalog'];
            $lines[] = 'CVE: ' . (string)$c['cve_id'];
            $lines[] = 'Severidad: ' . (string)($c['severity'] ?? 'desconocida');
            $lines[] = 'CVSS: ' . ($c['cvss_v3_score'] !== null ? (string)$c['cvss_v3_score'] : 'desconocido')
                . ' · Vector: ' . (string)($c['cvss_v3_vector'] ?? 'desconocido');
            $lines[] = 'Publicado: ' . (string)($c['published_at'] ?? 'desconocido');
            if ($cve['epss'] !== null && $cve['epss']['epss'] !== null) {
                $lines[] = 'EPSS: ' . number_format((float)$cve['epss']['epss'] * 100, 2, '.', '') . '%';
            }
            $lines[] = 'CISA KEV: ' . ($cve['kev'] !== null ? 'Sí' : 'No');
            if ($cve['kev'] !== null) {
                if (!empty($cve['kev']['date_added'])) {
                    $lines[] = 'KEV añadido: ' . (string)$cve['kev']['date_added'];
                }
                if (!empty($cve['kev']['required_action'])) {
                    $lines[] = 'Acción CISA: ' . truncate((string)$cve['kev']['required_action'], 800);
                }
            }
            if (!empty($c['description'])) {
                $lines[] = 'Descripción: ' . truncate((string)$c['description'], 1200);
            }
        } elseif ($task !== null) {
            $lines[] = 'CVE: ' . (string)$task['cve_id'] . ' (sin datos completos en el catálogo local)';
        }

        if ($task !== null) {
            $lines[] = 'TAREA: ' . (string)$task['cve_id']
                . ' · Estado: ' . self::statusLabel((string)$task['status'])
                . ($task['owner'] ? ' · Responsable: ' . (string)$task['owner'] : '')
                . ($task['due_at'] ? ' · Fecha límite: ' . (string)$task['due_at'] : '');
            if (!empty($task['patch_kb'])) {
                $lines[] = 'Parche/KB: ' . (string)$task['patch_kb'];
            }
            if (!empty($task['fixed_version'])) {
                $lines[] = 'Versión corregida: ' . (string)$task['fixed_version'];
            }
            if (!empty($task['evidence'])) {
                $lines[] = 'Evidencia actual: ' . truncate((string)$task['evidence'], 600);
            }
            if (!empty($task['notes'])) {
                $lines[] = 'Notas: ' . truncate((string)$task['notes'], 800);
            }
            $machines = safe_json_decode((string)($task['machines_json'] ?? ''), []);
            if (is_array($machines) && $machines !== []) {
                $names = [];
                foreach (array_slice($machines, 0, 10) as $machine) {
                    $names[] = (string)($machine['name'] ?? '') .
                        (!empty($machine['os']) ? ' (' . $machine['os'] . ')' : '');
                }
                $lines[] = 'Equipos afectados (' . (int)$task['machine_count'] . '): ' . implode(', ', array_filter($names));
            }
        }

        $user = "CONTEXTO:\n" . implode("\n", $lines) . "\n\nPREGUNTA:\n" . $question;

        return [$system, $user];
    }

    private function computeDue(string $severity, string $kevDue = ''): ?string
    {
        if ($kevDue !== '') {
            return $kevDue;
        }
        $sla = $this->slaSettings();
        $key = strtolower($severity);
        $days = $sla[$key] ?? $sla['medium'];
        return date('Y-m-d', strtotime('+' . max(1, (int)$days) . ' days'));
    }

    private function slaSettings(): array
    {
        return [
            'critical' => max(1, (int)setting_get('remediation_sla_critical', '7')),
            'high'     => max(1, (int)setting_get('remediation_sla_high', '30')),
            'medium'   => max(1, (int)setting_get('remediation_sla_medium', '90')),
            'low'      => max(1, (int)setting_get('remediation_sla_low', '180')),
        ];
    }

    private function stats(int $orgId): array
    {
        $counts = ['open' => 0, 'in_progress' => 0, 'patched' => 0, 'mitigated' => 0, 'accepted' => 0, 'false_positive' => 0];
        foreach (Database::fetchAll(
            "SELECT status, COUNT(*) AS c FROM remediation_tasks WHERE org_id = ? GROUP BY status",
            [$orgId]
        ) as $row) {
            $counts[(string)$row['status']] = (int)$row['c'];
        }

        $overdue = (int)(Database::fetchOne(
            "SELECT COUNT(*) AS c FROM remediation_tasks
             WHERE org_id = ? AND due_at IS NOT NULL AND due_at < date('now')
               AND status IN ('open','in_progress')",
            [$orgId]
        )['c'] ?? 0);

        $kevOpen = (int)(Database::fetchOne(
            "SELECT COUNT(*) AS c FROM remediation_tasks
             WHERE org_id = ? AND kev = 1 AND status IN ('open','in_progress')",
            [$orgId]
        )['c'] ?? 0);

        $mttr = Database::fetchOne(
            "SELECT AVG(julianday(resolved_at) - julianday(created_at)) AS d
             FROM remediation_tasks
             WHERE org_id = ? AND resolved_at IS NOT NULL",
            [$orgId]
        );

        $bySeverity = Database::fetchAll(
            "SELECT severity, COUNT(*) AS c FROM remediation_tasks
             WHERE org_id = ? AND status IN ('open','in_progress')
             GROUP BY severity ORDER BY c DESC",
            [$orgId]
        );

        return [
            'counts'      => $counts,
            'total'       => array_sum($counts),
            'open'        => $counts['open'] + $counts['in_progress'],
            'overdue'     => $overdue,
            'kev_open'    => $kevOpen,
            'mttr_days'   => $mttr !== null && $mttr['d'] !== null ? (float)$mttr['d'] : null,
            'by_severity' => $bySeverity,
        ];
    }

    private function parseMachines(string $raw): array
    {
        $lines = preg_split('/\r\n|\n|\r/', $raw) ?: [];
        $machines = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $machines[] = ['name' => truncate($line, 120), 'os' => '', 'exposure' => ''];
            if (count($machines) >= 100) {
                break;
            }
        }
        return $machines;
    }

    public static function statuses(): array
    {
        return ['open', 'in_progress', 'patched', 'mitigated', 'accepted', 'false_positive'];
    }

    public static function resolvedStatuses(): array
    {
        return ['patched', 'mitigated', 'accepted', 'false_positive'];
    }

    public static function statusLabel(string $status): string
    {
        $labels = [
            'open'           => 'Abierta',
            'in_progress'    => 'En curso',
            'patched'        => 'Parcheada',
            'mitigated'      => 'Mitigada',
            'accepted'       => 'Aceptada',
            'false_positive' => 'Falso positivo',
        ];
        return $labels[$status] ?? $status;
    }
}
