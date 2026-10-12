<?php
/**
 * Router — Sistema de enrutamiento simple basado en patrones.
 */

declare(strict_types=1);

class Router
{
    private array $routes = [];
    private array $groupStack = [];
    private ?string $currentGroup = null;

    /**
     * Registra una ruta GET.
     */
    public function get(string $pattern, callable|array|string $handler, array $middleware = []): void
    {
        $this->addRoute('GET', $pattern, $handler, $middleware);
    }

    /**
     * Registra una ruta POST.
     */
    public function post(string $pattern, callable|array|string $handler, array $middleware = []): void
    {
        $this->addRoute('POST', $pattern, $handler, $middleware);
    }

    /**
     * Registra una ruta PUT.
     */
    public function put(string $pattern, callable|array|string $handler, array $middleware = []): void
    {
        $this->addRoute('PUT', $pattern, $handler, $middleware);
    }

    /**
     * Registra una ruta DELETE.
     */
    public function delete(string $pattern, callable|array|string $handler, array $middleware = []): void
    {
        $this->addRoute('DELETE', $pattern, $handler, $middleware);
    }

    /**
     * Registra cualquier método.
     */
    public function any(string $pattern, callable|array|string $handler, array $middleware = []): void
    {
        $this->addRoute('*', $pattern, $handler, $middleware);
    }

    /**
     * Agrupa rutas con prefijo y middleware común.
     */
    public function group(string $prefix, callable $callback, array $middleware = []): void
    {
        $this->groupStack[] = [
            'prefix'     => trim($prefix, '/'),
            'middleware' => $middleware,
        ];
        $callback($this);
        array_pop($this->groupStack);
    }

    /**
     * Añade una ruta al registro.
     */
    private function addRoute(string $method, string $pattern, callable|array|string $handler, array $middleware = []): void
    {
        // Aplicar prefijos de grupo
        $fullPattern = $pattern;
        $groupMiddleware = [];
        foreach ($this->groupStack as $group) {
            $fullPattern = trim($group['prefix'] . '/' . ltrim($fullPattern, '/'), '/');
            $groupMiddleware = array_merge($groupMiddleware, $group['middleware']);
        }

        $this->routes[] = [
            'method'     => $method,
            'pattern'    => $fullPattern === '' ? '/' : '/' . trim($fullPattern, '/'),
            'handler'    => $handler,
            'middleware' => array_merge($groupMiddleware, $middleware),
        ];
    }

    /**
     * Despacha la petición actual.
     */
    public function dispatch(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
        $uri = '/' . trim($uri, '/');
        if ($uri !== '/') {
            $uri = rtrim($uri, '/');
        }

        // Normalizar URLs en modo sin mod_rewrite:
        // /index.php/xxx -> /xxx  (estilo PATH_INFO)
        if ($uri === '/index.php') {
            $uri = '/';
        } elseif (str_starts_with($uri, '/index.php/')) {
            $uri = substr($uri, 10) ?: '/';
        }

        // Normalizar: quitar APP_URL del inicio si existe
        $appPath = parse_url(APP_URL, PHP_URL_PATH) ?? '';
        if ($appPath && $appPath !== '/' && str_starts_with($uri, $appPath)) {
            $uri = substr($uri, strlen($appPath));
            if ($uri === '') $uri = '/';
        }

        foreach ($this->routes as $route) {
            if ($route['method'] !== '*' && $route['method'] !== $method) {
                continue;
            }

            $params = $this->matchPattern($route['pattern'], $uri);
            if ($params === false) {
                continue;
            }

            // Ejecutar middleware
            foreach ($route['middleware'] as $mw) {
                if (is_callable($mw)) {
                    $mw();
                } elseif (is_string($mw) && class_exists($mw)) {
                    $mw::handle();
                }
            }

            // Ejecutar handler
            $this->callHandler($route['handler'], $params);
            return;
        }

        // No se encontró ruta
        http_response_code(404);
        if (is_ajax() || str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json')) {
            json_response(['error' => 'Ruta no encontrada', 'path' => $uri], 404);
        }
        require VIEWS_PATH . '/errors/404.php';
    }

    /**
     * Compara un patrón con una URI y extrae parámetros.
     */
    private function matchPattern(string $pattern, string $uri): array|false
    {
        // Convertir patrón a regex
        $regex = preg_replace('/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/', '(?P<$1>[^/]+)', $pattern);
        $regex = '#^' . $regex . '$#';

        if (!preg_match($regex, $uri, $matches)) {
            return false;
        }

        $params = [];
        foreach ($matches as $key => $value) {
            if (is_string($key)) {
                $params[$key] = $value;
            }
        }
        return $params;
    }

    /**
     * Ejecuta el handler de una ruta.
     */
    private function callHandler(callable|array|string $handler, array $params): void
    {
        if (is_callable($handler)) {
            $handler($params);
            return;
        }

        if (is_string($handler) && str_contains($handler, '@')) {
            [$class, $method] = explode('@', $handler, 2);
            $instance = new $class();
            $instance->$method($params);
            return;
        }

        if (is_string($handler) && file_exists($handler)) {
            extract($params);
            require $handler;
            return;
        }

        if (is_array($handler) && count($handler) === 2) {
            [$class, $method] = $handler;
            $instance = is_object($class) ? $class : new $class();
            $instance->$method($params);
            return;
        }

        throw new RuntimeException('Handler de ruta inválido');
    }

    /**
     * Obtiene todas las rutas registradas (para debug).
     */
    public function getRoutes(): array
    {
        return $this->routes;
    }
}
