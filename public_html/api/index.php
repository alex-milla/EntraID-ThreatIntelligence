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

    /* Apache/PHP-FPM puede mover Basic a REDIRECT_HTTP_AUTHORIZATION o
       destriparlo en PHP_AUTH_PW y borrar HTTP_AUTHORIZATION (hosting
       compartido). El conector de Sentinel usa Basic: hay que aceptarlos. */
    $header = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if ($header === '' && !empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        $header = (string)$_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }
    if (str_starts_with($header, 'Bearer ')) {
        $row = apiTfTokenRow(substr($header, 7));
    } elseif (str_starts_with($header, 'Basic ')) {
        $decoded = base64_decode(substr($header, 6), true);
        $row = $decoded !== false && str_contains($decoded, ':')
            ? apiTfTokenRow(substr($decoded, strpos($decoded, ':') + 1))
            : null;
    } elseif (!empty($_SERVER['PHP_AUTH_PW'])) {
        $row = apiTfTokenRow((string)$_SERVER['PHP_AUTH_PW']);
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

/** Respuesta JSON con el media type TAXII (json_response fuerza application/json). */
function apiTaxiiJson(array $data, string $mime, int $status = 200, array $headers = []): void
{
    http_response_code($status);
    header('Content-Type: ' . $mime);
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    foreach ($headers as $name => $value) {
        header($name . ': ' . $value);
    }
    echo json_encode(
        $data,
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
    );
    exit;
}

/** Raíz HTTP de la API en la que se ha llamado (con o sin mod_rewrite). */
function apiTfTaxiiRoot(): string
{
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
    $scheme = $https ? 'https' : 'http';
    $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
    $path = (string)(parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?? '/');
    $pos = strpos($path, '/taxii2');
    if ($pos !== false) {
        $path = substr($path, 0, $pos);
    }

    return $scheme . '://' . $host . $path;
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

// ============================================================
// API: TAXII 2.1 de solo lectura para Microsoft Sentinel (v0.4.29.2/.3)
// ============================================================

$router->group('/api/taxii2', function (Router $r) {
    $mime = 'application/taxii+json;version=2.1';
    $stixMime = 'application/stix+json;version=2.1';

    $discovery = function () use ($mime) {
        apiTfAuth();
        apiTaxiiJson([
            'title'       => 'EntraID TI — Seguimiento TI TF',
            'description' => 'Feeds de indicadores de Seguimiento TI TF (solo lectura)',
            'contact'     => 'Equipo de Seguridad',
            'api_roots'   => [apiTfTaxiiRoot() . '/taxii2/ti-tf/'],
        ], $mime);
    };

    $apiRoot = function () use ($mime) {
        apiTfAuth();
        apiTaxiiJson([
            'title'              => 'Seguimiento TI TF',
            'description'        => 'Listas de IOCs publicadas desde Seguimiento TI TF',
            'versions'           => [$mime],
            'max_content_length' => 10485760,
        ], $mime);
    };

    /** Metadatos de una colección: null = la agregada «all». */
    $collectionData = static function (?array $search, string $mime, string $stixMime): array {
        if ($search === null) {
            return [
                'id'          => TiTrackerFeed::collectionId(),
                'title'       => 'Todas las listas TI TF',
                'description' => 'Unión de todas las listas publicadas permitidas al token',
                'can_read'    => true,
                'can_write'   => false,
                'media_types' => [$mime, $stixMime],
            ];
        }

        return [
            'id'          => TiTrackerFeed::collectionId((int)$search['id']),
            'title'       => (string)$search['name'],
            'description' => 'Lista ' . (string)($search['slug'] ?? '') . ' de Seguimiento TI TF',
            'can_read'    => true,
            'can_write'   => false,
            'media_types' => [$mime, $stixMime],
        ];
    };

    $collections = function () use ($mime, $stixMime, $collectionData) {
        $auth = apiTfAuth();
        $allowedIds = $auth['token'] === null ? null : TiTrackerFeed::allowedIds($auth['token']);
        $store = new TiTrackerStore();

        $items = [$collectionData(null, $mime, $stixMime)];
        foreach ($store->listApiSearches($allowedIds) as $search) {
            $items[] = $collectionData($search, $mime, $stixMime);
        }

        apiTaxiiJson(['collections' => $items], $mime);
    };

    /* El validador de alta de Sentinel pide el detalle de la colección. */
    $collection = function (array $params) use ($mime, $stixMime, $collectionData) {
        $auth = apiTfAuth();
        $allowedIds = $auth['token'] === null ? null : TiTrackerFeed::allowedIds($auth['token']);
        $id = (string)($params['id'] ?? '');
        $found = null;

        if ($id === TiTrackerFeed::collectionId()) {
            $found = $collectionData(null, $mime, $stixMime);
        } else {
            foreach ((new TiTrackerStore())->listApiSearches($allowedIds) as $search) {
                if (TiTrackerFeed::collectionId((int)$search['id']) === $id) {
                    $found = $collectionData($search, $mime, $stixMime);
                    break;
                }
            }
        }
        if ($found === null) {
            apiTaxiiJson(['error' => 'Colección no encontrada o no permitida'], $mime, 404);
        }

        apiTaxiiJson($found, $mime);
    };

    $objects = function (array $params) use ($mime) {
        $auth = apiTfAuth();
        $allowedIds = $auth['token'] === null ? null : TiTrackerFeed::allowedIds($auth['token']);
        $store = new TiTrackerStore();
        $published = $store->listApiSearches($allowedIds);
        $collectionId = (string)($params['id'] ?? '');

        $target = null;
        if ($collectionId === TiTrackerFeed::collectionId()) {
            $target = $published;
        } else {
            foreach ($published as $search) {
                if (TiTrackerFeed::collectionId((int)$search['id']) === $collectionId) {
                    $target = [$search];
                    break;
                }
            }
        }
        if ($target === null) {
            apiTaxiiJson(['error' => 'Colección no encontrada o no permitida'], $mime, 404);
        }

        try {
            $since = TiTrackerFeed::normalizeSince($_GET['added_after'] ?? '');
            $feed = TiTrackerFeed::collect($target, 'tracked', $since, 'all', $store);
        } catch (Throwable $e) {
            apiTaxiiJson(['error' => $e->getMessage()], $mime, 400);
        }

        $all = TiTrackerFeed::taxiiObjects($feed['iocs']);
        $limit = max(1, min(5000, (int)($_GET['limit'] ?? 5000)));
        $next = (string)($_GET['next'] ?? '');
        $offset = ctype_digit($next) ? (int)$next : 0;
        $page = array_slice($all, $offset, $limit);
        $more = ($offset + count($page)) < count($all);

        $response = ['more' => $more, 'objects' => $page];
        if ($more) {
            $response['next'] = (string)($offset + count($page));
        }
        foreach ($feed['lists'] as $list) {
            $store->logApiPull((int)$list['id'], (int)$list['count']);
        }

        /* Ventanas TAXII: ayudan al conector a avanzar el cursor de added_after. */
        $headers = [];
        $dates = [];
        foreach ($page as $obj) {
            $created = (string)($obj['created'] ?? '');
            if ($created !== '') {
                $dates[] = $created;
            }
        }
        if ($dates !== []) {
            sort($dates);
            $headers['X-TAXII-Date-Added-First'] = $dates[0];
            $headers['X-TAXII-Date-Added-Last'] = $dates[count($dates) - 1];
        }

        apiTaxiiJson($response, $mime, 200, $headers);
    };

    /* Canónicas: API root URL = /api/taxii2/ti-tf */
    $r->get('', $discovery);
    $r->get('ti-tf', $apiRoot);
    $r->get('ti-tf/collections', $collections);
    $r->get('ti-tf/collections/{id}', $collection);
    $r->get('ti-tf/collections/{id}/objects', $objects);

    /* Alias: API root URL = /api/taxii2 (el conector solo pide /collections/…). */
    $r->get('collections', $collections);
    $r->get('collections/{id}', $collection);
    $r->get('collections/{id}/objects', $objects);
});

$router->dispatch();
