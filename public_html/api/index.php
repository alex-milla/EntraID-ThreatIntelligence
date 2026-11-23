<?php
/**
 * API Router — Endpoints de la API REST.
 * Autenticación por sesión (web) o token Bearer (API externa).
 * Funciona con o sin mod_rewrite (normaliza PATH_INFO a REQUEST_URI).
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/bootstrap.php';

// ============================================================
// Normalizar REQUEST_URI para funcionar sin mod_rewrite
// Si accedemos a /api/index.php/tenants, PATH_INFO = /tenants
// Reconstruimos REQUEST_URI como /api/tenants para el Router
// ============================================================

if (!empty($_SERVER['PATH_INFO']) && str_contains($_SERVER['REQUEST_URI'] ?? '', '/api/index.php')) {
    $pathInfo = $_SERVER['PATH_INFO'];
    $queryString = $_SERVER['QUERY_STRING'] ?? '';
    $_SERVER['REQUEST_URI'] = '/api' . $pathInfo . ($queryString ? '?' . $queryString : '');
}

// Verificar autenticación (sesión o token API)
function apiRequireAuth(): void
{
    if (Auth::check()) return;

    // Intentar token Bearer
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (str_starts_with($header, 'Bearer ')) {
        $token = substr($header, 7);
        $hash = hash('sha256', $token);
        $tokenRow = Database::fetchOne(
            "SELECT t.*, u.role FROM api_tokens t JOIN users u ON t.user_id = u.id
             WHERE t.token_hash = ? AND (t.expires_at IS NULL OR t.expires_at > datetime('now'))",
            [$hash]
        );
        if ($tokenRow) {
            Database::update("UPDATE api_tokens SET last_used_at = datetime('now') WHERE id = ?", [$tokenRow['id']]);
            return;
        }
    }

    json_response(['error' => 'No autorizado'], 401);
}

/* ============================================================
 * API: Seguimiento TI TF — feeds externos (v0.4.29)
 * Las rutas existentes conservan su autenticación original (sesión o Bearer).
 * Estas nuevas aceptan además X-API-Key, Basic y, si el token lo autoriza,
 * ?token= para EDLs de firewalls que no pueden enviar cabeceras propias.
 * ============================================================ */

function apiTfTokenRow(string $token): ?array
{
    $hash = hash('sha256', $token);
    $row = Database::fetchOne(
        "SELECT t.*, u.role FROM api_tokens t JOIN users u ON t.user_id = u.id
         WHERE t.token_hash = ? AND (t.expires_at IS NULL OR t.expires_at > datetime('now'))",
        [$hash]
    );
    if ($row !== null) {
        Database::update("UPDATE api_tokens SET last_used_at = datetime('now') WHERE id = ?", [$row['id']]);
    }

    return $row;
}

function apiTfAuth(): array
{
    if (Auth::check()) {
        return ['session' => true, 'token' => null];
    }

    $header = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if (str_starts_with($header, 'Bearer ')) {
        $row = apiTfTokenRow(substr($header, 7));
    } elseif (str_starts_with($header, 'Basic ')) {
        $decoded = base64_decode(substr($header, 6), true);
        $row = $decoded !== false && str_contains($decoded, ':')
            ? apiTfTokenRow(substr($decoded, strpos($decoded, ':') + 1))
            : null;
    } else {
        $key = trim((string)($_SERVER['HTTP_X_API_KEY'] ?? ''));
        $row = $key !== '' ? apiTfTokenRow($key) : null;
    }

    if ($row === null) {
        $queryToken = trim((string)($_GET['token'] ?? ''));
        if ($queryToken !== '') {
            $candidate = apiTfTokenRow($queryToken);
            if ($candidate !== null && TiTrackerFeed::allowQueryToken($candidate)) {
                $row = $candidate;
            }
        }
    }

    if ($row === null) {
        json_response(['error' => 'No autorizado'], 401);
    }

    return ['session' => false, 'token' => $row];
}

function apiTfRaw(string $content, string $mime, string $filename): void
{
    http_response_code(200);
    header('Content-Type: ' . $mime);
    header('Content-Disposition: inline; filename="' . basename($filename) . '"');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo $content;
    exit;
}

$router = new Router();

// ============================================================
// API: Tenants
// ============================================================

$router->group('/api/tenants', function (Router $r) {
    $r->get('', function () {
        apiRequireAuth();
        json_response(['tenants' => TenantManager::getAll()]);
    });

    $r->get('{id}', function ($params) {
        apiRequireAuth();
        $tenant = TenantManager::getById((int)$params['id']);
        if (!$tenant) json_response(['error' => 'No encontrado'], 404);
        // Nunca devolver el secret cifrado por API
        unset($tenant['client_secret_encrypted'], $tenant['client_secret_iv']);
        json_response(['tenant' => $tenant]);
    });

    $r->post('', function () {
        apiRequireAuth();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $result = TenantManager::create($input);
        json_response($result, $result['success'] ? 201 : 400);
    });

    $r->put('{id}', function ($params) {
        apiRequireAuth();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $result = TenantManager::update((int)$params['id'], $input);
        json_response($result, $result['success'] ? 200 : 400);
    });

    $r->delete('{id}', function ($params) {
        apiRequireAuth();
        TenantManager::delete((int)$params['id']);
        json_response(['success' => true]);
    });

    $r->post('{id}/sync', function ($params) {
        apiRequireAuth();
        $results = ModuleManager::syncAll((int)$params['id']);
        json_response(['success' => true, 'results' => $results]);
    });

    $r->get('{id}/stats', function ($params) {
        apiRequireAuth();
        json_response(['stats' => TenantManager::getStats((int)$params['id'])]);
    });
});

// ============================================================
// API: Graph (proxy seguro — nunca expone secretos)
// ============================================================

$router->group('/api/graph', function (Router $r) {
    $r->get('{tenantId}/test', function ($params) {
        apiRequireAuth();
        $module = ModuleManager::get('graph_connector');
        json_response($module->testTenantConnection((int)$params['tenantId']));
    });

    $r->get('{tenantId}/organization', function ($params) {
        apiRequireAuth();
        $module = ModuleManager::get('graph_connector');
        json_response($module->getOrganizationInfo((int)$params['tenantId']));
    });
});

// ============================================================
// API: Reportes
// ============================================================

$router->group('/api/reports', function (Router $r) {
    $r->get('', function () {
        apiRequireAuth();
        $module = ModuleManager::get('reports');
        json_response($module->getReports((int)($_GET['tenant'] ?? 0), (int)($_GET['page'] ?? 1)));
    });

    $r->post('generate', function () {
        apiRequireAuth();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $module = ModuleManager::get('reports');
        $result = $module->generateReport(
            (int)($input['tenant_id'] ?? 0),
            !empty($input['group_id']) ? (int)$input['group_id'] : null,
            $input['report_type'] ?? 'full',
            $input['period_type'] ?? 'monthly',
            $input['reference_date'] ?? null
        );
        json_response($result);
    });

    $r->get('{id}', function ($params) {
        apiRequireAuth();
        $module = ModuleManager::get('reports');
        $report = $module->getReport((int)$params['id']);
        if (!$report) json_response(['error' => 'No encontrado'], 404);
        json_response(['report' => $report]);
    });
});

// ============================================================
// API: LLM
// ============================================================

$router->group('/api/llm', function (Router $r) {
    $r->get('status', function () {
        apiRequireAuth();
        $module = ModuleManager::get('llm');
        $cfg = $module->cfg();
        json_response([
            'configured' => $module->isConfigured(),
            'provider'   => $cfg['provider'] ?: null,
            'model'      => $cfg['model'] ?: null,
        ]);
    });

    $r->post('chat', function () {
        apiRequireAuth();
        $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
        $module = ModuleManager::get('llm');
        $result = $module->chat(
            $input['system'] ?? 'Eres un asistente de ciberseguridad.',
            $input['prompt'] ?? '',
            $input['options'] ?? []
        );
        json_response($result);
    });
});

// ============================================================
// API: Módulos
// ============================================================

$router->group('/api/modules', function (Router $r) {
    $r->get('', function () {
        apiRequireAuth();
        $modules = Database::fetchAll("SELECT module_key, name, description, version, is_active FROM modules ORDER BY module_key");
        json_response(['modules' => $modules]);
    });

    $r->post('{key}/sync/{tenantId}', function ($params) {
        apiRequireAuth();
        $result = ModuleManager::syncModule($params['key'], (int)$params['tenantId']);
        json_response($result);
    });
});

// ============================================================
// API: Dashboard stats
// ============================================================

$router->get('/api/dashboard/stats', function () {
    apiRequireAuth();
    $tenants = TenantManager::getAll();
    $stats = [];
    foreach ($tenants as $t) {
        $stats[$t['id']] = [
            'name' => $t['name'],
            'data' => TenantManager::getStats($t['id']),
        ];
    }
    json_response(['tenants' => count($tenants), 'stats' => $stats]);
});

// ============================================================
// API: Seguimiento TI TF (listas de IOCs para herramientas externas)
// ============================================================

$router->group('/api/ti-tf', function (Router $r) {
    $r->get('lists', function () {
        $auth = apiTfAuth();
        $allowedIds = $auth['token'] === null ? null : TiTrackerFeed::allowedIds($auth['token']);

        json_response([
            'success' => true,
            'lists'   => TiTrackerFeed::catalog($allowedIds),
        ]);
    });

    $indicators = function () {
        $auth = apiTfAuth();
        $allowedIds = $auth['token'] === null ? null : TiTrackerFeed::allowedIds($auth['token']);

        $format = strtolower(trim((string)($_GET['format'] ?? 'json')));
        $scope  = strtolower(trim((string)($_GET['scope'] ?? 'tracked')));
        $type   = strtolower(trim((string)($_GET['type'] ?? 'all')));
        if (!in_array($format, TiTrackerFeed::FORMATS, true)) {
            json_response(['error' => 'Formato no soportado. Usa ' . implode(', ', TiTrackerFeed::FORMATS)], 400);
        }
        try {
            $since = TiTrackerFeed::normalizeSince($_GET['since'] ?? '');
        } catch (Throwable $e) {
            json_response(['error' => $e->getMessage()], 400);
        }

        try {
            $searches = TiTrackerFeed::resolveSearches($allowedIds, $_GET['lists'] ?? '');
            if ($searches === []) {
                json_response(['error' => 'No hay listas disponibles con esos filtros o permisos.'], 404);
            }
            $feed = TiTrackerFeed::collect($searches, $scope, $since, $type);
        } catch (Throwable $e) {
            json_response(['error' => $e->getMessage()], 400);
        }

        $store = new TiTrackerStore();
        foreach ($feed['lists'] as $list) {
            $store->logApiPull((int)$list['id'], (int)$list['count']);
        }

        if ($format === 'json') {
            json_response([
                'success'   => true,
                'scope'     => $scope,
                'type'      => $type,
                'since'     => $since,
                'count'     => count($feed['iocs']),
                'truncated' => $feed['truncated'],
                'lists'     => $feed['lists'],
                'iocs'      => $feed['iocs'],
            ]);
        }

        $config = [
            'tlp'        => 'green',
            'valid_days' => 365,
        ];
        $output = TiTrackerFeed::render($feed['iocs'], $format, $config);
        apiTfRaw($output['content'], $output['mime'], $output['filename']);
    };

    $r->get('indicators', $indicators);
    $r->get('feed', $indicators);
});

$router->dispatch();
