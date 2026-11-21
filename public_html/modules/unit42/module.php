<?php
/**
 * Módulo independiente: Unit 42 · timely threat intel.
 *
 * Publicaciones públicas descargadas del repositorio de Palo Alto Networks y
 * informes con IA generados sobre ellas. Sin dependencia de Threat Intelligence
 * ni de tenants de Graph.
 */

declare(strict_types=1);

class Module_Unit42 extends BaseModule
{
    public function key(): string { return 'unit42'; }
    public function name(): string { return 'Unit 42'; }
    public function description(): string { return 'Publicaciones de Unit 42 e informes con IA'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return [];
    }

    public function boot(): void
    {
        $this->registerRoutes();
    }

    public function isSyncable(): bool
    {
        return false;
    }

    public function sync(int $tenantId): array
    {
        return ['success' => true, 'records' => 0];
    }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Publicaciones',
            'url'   => base_url('modules/unit42'),
            'icon'  => 'public',
            'group' => 'Unit 42',
        ];
    }

    /** Segunda entrada de la sección Unit 42: sus propios informes con IA. */
    public function getExtraNavItems(): array
    {
        return [[
            'label' => 'Informes con IA',
            'url'   => base_url('modules/unit42/reports'),
            'icon'  => 'file-text',
            'group' => 'Unit 42',
            'after' => 'unit42',
        ]];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET',  'pattern' => '',                    'handler' => [$this, 'unit42Page']],
            ['method' => 'GET',  'pattern' => 'status',              'handler' => [$this, 'unit42Status']],
            ['method' => 'GET',  'pattern' => 'counts',              'handler' => [$this, 'unit42Counts']],
            ['method' => 'POST', 'pattern' => 'state',               'handler' => [$this, 'unit42SetState']],
            ['method' => 'GET',  'pattern' => 'reports',             'handler' => [$this, 'unit42ReportsPage']],
            ['method' => 'POST', 'pattern' => 'report-create',       'handler' => [$this, 'unit42ReportCreate']],
            ['method' => 'GET',  'pattern' => 'report/{id}/data',    'handler' => [$this, 'unit42ReportData']],
            ['method' => 'GET',  'pattern' => 'report/{id}',         'handler' => [$this, 'unit42ReportPage']],
            ['method' => 'GET',  'pattern' => '{id}/panel',          'handler' => [$this, 'unit42ArticlePanel']],
            ['method' => 'GET',  'pattern' => '{id}',                'handler' => [$this, 'unit42ArticlePage']],
            ['method' => 'POST', 'pattern' => 'sync',                'handler' => [$this, 'unit42Sync']],
        ];
    }
    public function unit42Page(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $search = trim((string)($_GET['q'] ?? ''));
        $page = max(1, (int)($_GET['p'] ?? 1));
        $limit = 50;
        $offset = ($page - 1) * $limit;
        $userId = (int)(Auth::id() ?? 0);

        $filters = [
            'user_id'        => $userId,
            'q'              => $search,
            'from'           => (string)($_GET['from'] ?? ''),
            'to'             => (string)($_GET['to'] ?? ''),
            'only_unread'    => !empty($_GET['only_unread']),
            'only_favorites' => !empty($_GET['only_favorites']),
            'only_iocs'      => !empty($_GET['only_iocs']),
        ];

        $articles = [];
        $status = [];
        $counts = ['total' => 0, 'unread' => 0, 'favorites' => 0, 'with_iocs' => 0];
        try {
            $articles = Unit42Feed::articles($filters, $limit, $offset);
            $status = Unit42Feed::status();
            $counts = Unit42Feed::stateCounts($userId);
        } catch (Throwable $e) {
            app_log('error', 'unit42', 'No se pudo listar los artículos', ['error' => $e->getMessage()]);
        }

        echo $this->page('unit42', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'articles'       => $articles,
            'status'         => $status,
            'counts'         => $counts,
            'filters'        => $filters,
            'q'              => $search,
            'page'           => $page,
            'hasMore'        => count($articles) === $limit,
            'llmProfiles'    => function_exists('llm_profile_list') ? llm_profile_list() : [],
        ]);
    }

    public function unit42ArticlePage(array $params = []): void
    {
        $id = (int)($params['id'] ?? 0);
        $article = Unit42Feed::article($id);
        if ($article === null) {
            http_response_code(404);
            require VIEWS_PATH . '/errors/404.php';
            return;
        }

        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));

        echo $this->page('unit42_article', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'article'        => $article,
            'iocs'           => Unit42Feed::iocs($id),
            'iocCounts'      => Unit42Feed::iocCounts($id),
            'reports'        => Unit42Feed::reportsForArticle($id, (int)(Auth::id() ?? 0)),
        ]);
    }

    /** GET unit42/{id}/panel — cuerpo del artículo para desplegar en línea. */
    public function unit42ArticlePanel(array $params = []): void
    {
        $id = (int)($params['id'] ?? 0);
        $article = Unit42Feed::article($id);
        if ($article === null) {
            http_response_code(404);
            return;
        }
        $tenants = TenantManager::getActive();
        $tenantId = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $userId = (int)(Auth::id() ?? 0);
        $state = $userId > 0 ? (Unit42Feed::statesFor($userId, [$id])[$id] ?? []) : [];

        header('Content-Type: text/html; charset=utf-8');
        echo $this->render('_unit42_panel', [
            'article'    => $article,
            'tenantId'   => $tenantId,
            'isRead'     => !empty($state['is_read']),
            'isFavorite' => !empty($state['is_favorite']),
            'reports'    => Unit42Feed::reportsForArticle($id, $userId),
            'panelMode'  => true,
        ]);
    }

    /** POST unit42/sync — comprueba o descarga los ficheros nuevos/modificados. */
    public function unit42Sync(array $params = []): void
    {
        Auth::requireAdmin();
        Csrf::validateOrFail();

        $raw = file_get_contents('php://input');
        $input = json_decode((string)$raw, true);
        if (!is_array($input)) {
            $input = $_POST;
        }

        if (!empty($input['check'])) {
            json_response(Unit42Feed::check());
            return;
        }

        $useFpm = function_exists('fastcgi_finish_request');

        if ($useFpm) {
            @ignore_user_abort(true);
            @set_time_limit(0);
            if (function_exists('release_session_lock')) {
                release_session_lock();
            }

            // El proxy no espera a la descarga: responde ya y sigue en el proceso.
            json_response_continue([
                'success' => true,
                'queued'  => true,
                'worker'  => 'fpm',
            ], 202);

            try {
                Unit42Feed::sync();
            } catch (Throwable $e) {
                app_log('error', 'unit42', 'Error descargando en segundo plano', ['error' => $e->getMessage()]);
            }
            exit;
        }

        if (function_exists('release_session_lock')) {
            release_session_lock();
        }
        @set_time_limit(0);
        @ignore_user_abort(true);

        try {
            $summary = Unit42Feed::sync();
            json_response([
                'success'    => (bool)($summary['ok'] ?? false),
                'total'      => (int)($summary['total'] ?? 0),
                'added'      => (int)($summary['added'] ?? 0),
                'updated'    => (int)($summary['updated'] ?? 0),
                'unchanged'  => (int)($summary['unchanged'] ?? 0),
                'errors'     => $summary['errors'] ?? [],
                'error'      => ($summary['errors'] ?? []) !== [] ? implode(' · ', $summary['errors']) : '',
                'worker'     => 'inline',
            ], ($summary['ok'] ?? false) ? 200 : 500);
        } catch (Throwable $e) {
            app_log('error', 'unit42', 'Error en la sincronización', ['error' => $e->getMessage()]);
            json_response(['success' => false, 'error' => Unit42Feed::friendlyError($e)], 500);
        }
    }

    /** POST unit42/state — marca leídos/favoritos de uno o varios artículos. */
    public function unit42SetState(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $raw = file_get_contents('php://input');
        $input = json_decode((string)$raw, true);
        if (!is_array($input)) {
            $input = $_POST;
        }

        /* Acepta {ids, changes:{...}} (vista) o {ids, is_read:1} (compatibilidad). */
        $changes = is_array($input['changes'] ?? null) ? $input['changes'] : $input;

        $stateChanges = [];
        if (array_key_exists('is_read', $changes)) {
            $stateChanges['is_read'] = !empty($changes['is_read']) ? 1 : 0;
        }
        if (array_key_exists('is_favorite', $changes)) {
            $stateChanges['is_favorite'] = !empty($changes['is_favorite']) ? 1 : 0;
        }
        if ($stateChanges === []) {
            json_response(['success' => false, 'error' => 'No se indicó ningún estado.'], 400);
        }

        $userId = (int)(Auth::id() ?? 0);
        if (!empty($input['all'])) {
            $filters = is_array($input['filters'] ?? null) ? $input['filters'] : [];
            $filters['user_id'] = $userId;
            $rows = Unit42Feed::articles($filters, 10000, 0);
            $ids = array_map(static fn(array $r): int => (int)$r['id'], $rows);
        } else {
            $rawIds = $input['ids'] ?? [$input['id'] ?? 0];
            if (!is_array($rawIds)) {
                $rawIds = [$rawIds];
            }
            $ids = array_values(array_filter(array_map('intval', $rawIds)));
        }

        $changed = Unit42Feed::setArticleState($userId, $ids, $stateChanges);
        json_response([
            'success' => true,
            'changed' => $changed,
            'counts'  => Unit42Feed::stateCounts($userId),
        ]);
    }

    /** GET unit42/counts — contadores de no leídos / favoritos. */
    public function unit42Counts(array $params = []): void
    {
        Auth::require();
        json_response(Unit42Feed::stateCounts((int)(Auth::id() ?? 0)));
    }

    /** GET unit42/reports — historial de informes con IA. */
    public function unit42ReportsPage(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $userId = (int)(Auth::id() ?? 0);

        echo $this->page('unit42_reports', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'reports'        => Unit42Feed::reports($userId),
            'kinds'          => Unit42Feed::reportKinds(),
        ]);
    }

    /** GET unit42/report/{id} — informe con IA terminado (o en curso). */
    public function unit42ReportPage(array $params = []): void
    {
        $id = (int)($params['id'] ?? 0);
        $report = Unit42Feed::report($id);
        if ($report === null) {
            http_response_code(404);
            require VIEWS_PATH . '/errors/404.php';
            return;
        }
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));

        echo $this->page('unit42_report', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'report'         => $report,
        ]);
    }

    /** GET unit42/report/{id}/data — estado para sondeo. */
    public function unit42ReportData(array $params = []): void
    {
        Auth::require();
        json_response(Unit42Feed::reportStatus((int)($params['id'] ?? 0)));
    }

    /** POST unit42/report-create — crea el informe y lo ejecuta. */
    public function unit42ReportCreate(array $params = []): void
    {
        Auth::require();
        Csrf::validateOrFail();

        $raw = file_get_contents('php://input');
        $input = json_decode((string)$raw, true);
        if (!is_array($input)) {
            $input = $_POST;
        }

        $ids = is_array($input['item_ids'] ?? null) ? $input['item_ids'] : [];
        $kind = (string)($input['kind'] ?? 'resumen');
        $tenantId = (int)($input['tenant_id'] ?? 0);
        $profileId = (int)($input['profile_id'] ?? 0);

        $created = Unit42Feed::createReport((int)(Auth::id() ?? 0), $ids, $kind, $tenantId, $profileId);
        if (empty($created['success'])) {
            json_response(['success' => false, 'error' => $created['error'] ?? 'No se pudo crear.'], 400);
            return;
        }
        $id = (int)$created['id'];
        $url = base_url('modules/unit42/report/' . $id);

        if (function_exists('fastcgi_finish_request')) {
            @ignore_user_abort(true);
            @set_time_limit(0);
            if (function_exists('release_session_lock')) {
                release_session_lock();
            }
            json_response_continue(['success' => true, 'queued' => true, 'worker' => 'fpm', 'id' => $id, 'url' => $url], 202);
            Unit42Feed::runReport($id);
            exit;
        }

        if (function_exists('release_session_lock')) {
            release_session_lock();
        }
        @set_time_limit(0);
        @ignore_user_abort(true);
        $res = Unit42Feed::runReport($id);
        json_response([
            'success' => (bool)$res['success'],
            'id'      => $id,
            'url'     => $url,
            'error'   => $res['error'] ?? '',
            'worker'  => 'inline',
        ], $res['success'] ? 200 : 500);
    }

    /** GET unit42/status — progreso de la descarga en curso. */
    public function unit42Status(array $params = []): void
    {
        Auth::require();
        json_response(Unit42Feed::status());
    }
}
