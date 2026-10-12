<?php
/**
 * Módulo: Usuarios Entra ID
 * Investigación de usuarios: perfil, último cambio de contraseña, MFA,
 * registro de sign-ins (con país habitual) y riesgo (Identity Protection).
 * Consultas en vivo a Microsoft Graph.
 */

declare(strict_types=1);

class Module_EntraUsers extends BaseModule
{
    public function key(): string { return 'entra_users'; }
    public function name(): string { return 'Usuarios Entra ID'; }
    public function description(): string { return 'Investigación de usuarios: perfil, contraseña, MFA, logins y riesgo'; }
    public function version(): string { return '1.0.0'; }

    public function requiredPermissions(): array
    {
        return [
            'User.Read.All',
            'AuditLog.Read.All',
            'UserAuthenticationMethod.Read.All',
            'Reports.Read.All',
            'IdentityRiskyUser.Read.All',
            'IdentityRiskEvent.Read.All',
        ];
    }

    public function isSyncable(): bool { return false; }
    public function sync(int $tenantId): array { return ['success' => true, 'records' => 0]; }

    public function getNavItem(): ?array
    {
        return [
            'label' => 'Usuarios Entra ID',
            'url'   => base_url('modules/entra_users'),
            'icon'  => 'users',
            'group' => 'Seguridad',
        ];
    }

    public function routes(): array
    {
        return [
            ['method' => 'GET', 'pattern' => '',          'handler' => [$this, 'index']],
            ['method' => 'GET', 'pattern' => 'user/{id}', 'handler' => [$this, 'userPage']],
            ['method' => 'GET', 'pattern' => 'risky',     'handler' => [$this, 'riskyPage']],
        ];
    }

    // ============================================================
    // Consultas a Graph
    // ============================================================

    private function searchUsersGraph(int $tenantId, string $q): array
    {
        try {
            $client = $this->getGraphClient($tenantId);
            $esc = str_replace("'", "''", $q);
            $filter = "startswith(displayName,'$esc') or startswith(userPrincipalName,'$esc') or startswith(mail,'$esc')";
            $res = $client->graphGet('users', [
                '$filter' => $filter,
                '$top'    => 25,
                '$select' => 'id,displayName,userPrincipalName,mail,department,companyName,jobTitle,accountEnabled',
            ]);
            return ['success' => true, 'users' => $res['value'] ?? []];
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage(), 'users' => []];
        }
    }

    private function getUserProfile(int $tenantId, string $id): array
    {
        try {
            $client = $this->getGraphClient($tenantId);
            $u = $client->graphGet('users/' . rawurlencode($id), [
                '$select' => 'id,displayName,userPrincipalName,mail,department,companyName,jobTitle,accountEnabled,createdDateTime,lastPasswordChangeDateTime,mobilePhone,officeLocation,city,country,preferredLanguage',
            ]);
            return ['success' => true, 'user' => $u];
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage(), 'user' => null];
        }
    }

    private function getAuthMethods(int $tenantId, string $id): array
    {
        try {
            $client = $this->getGraphClient($tenantId);
            $res = $client->graphGet('users/' . rawurlencode($id) . '/authentication/methods');
            return ['success' => true, 'methods' => $res['value'] ?? []];
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage(), 'methods' => []];
        }
    }

    private function getMfaRegistration(int $tenantId, string $id): array
    {
        try {
            $client = $this->getGraphClient($tenantId);
            $esc = str_replace("'", "''", $id);
            $res = $client->graphGet('reports/authenticationMethods/userRegistrationDetails', [
                '$filter' => "id eq '$esc'",
            ]);
            return ['success' => true, 'registration' => $res['value'][0] ?? null];
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage(), 'registration' => null];
        }
    }

    private function getSignIns(int $tenantId, string $id, int $days = 7, int $top = 100): array
    {
        try {
            $client = $this->getGraphClient($tenantId);
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage(), 'signIns' => [], 'fallback' => false];
        }

        $esc = str_replace("'", "''", $id);

        // Intentos: primero con filtro de fecha (si procede), luego sin él.
        $filters = [];
        if ($days > 0) {
            $since = gmdate('Y-m-d\TH:i:s\Z', time() - ($days * 86400));
            $filters[] = "userId eq '$esc' and createdDateTime ge $since";
        }
        $filters[] = "userId eq '$esc'";

        $anySuccess = false;
        $lastError = null;

        foreach ($filters as $i => $filter) {
            try {
                $res = $client->graphGet('auditLogs/signIns', [
                    '$filter' => $filter,
                    '$top'    => $top,
                ]);
                $anySuccess = true;
                $signIns = $res['value'] ?? [];
                if (!empty($signIns)) {
                    usort($signIns, fn($a, $b) => strcmp((string)($b['createdDateTime'] ?? ''), (string)($a['createdDateTime'] ?? '')));
                    return ['success' => true, 'signIns' => $signIns, 'fallback' => ($i > 0)];
                }
            } catch (Throwable $e) {
                $lastError = $e->getMessage();
            }
        }

        if (!$anySuccess && $lastError !== null) {
            return ['success' => false, 'error' => $lastError, 'signIns' => [], 'fallback' => false];
        }
        return ['success' => true, 'signIns' => [], 'fallback' => false];
    }

    private function getRiskyUsers(int $tenantId): array
    {
        try {
            $client = $this->getGraphClient($tenantId);
            $res = $client->graphGet('identityProtection/riskyUsers', ['$top' => 100]);
            return ['success' => true, 'users' => $res['value'] ?? []];
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage(), 'users' => []];
        }
    }

    private function getUserRisk(int $tenantId, string $id): array
    {
        try {
            $client = $this->getGraphClient($tenantId);
            $esc = str_replace("'", "''", $id);
            $res = $client->graphGet('identityProtection/riskyUsers', ['$filter' => "id eq '$esc'"]);
            return ['success' => true, 'risk' => $res['value'][0] ?? null];
        } catch (Throwable $e) {
            return ['success' => false, 'error' => $e->getMessage(), 'risk' => null];
        }
    }

    // ============================================================
    // Páginas
    // ============================================================

    public function index(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));
        $q = trim((string)($_GET['q'] ?? ''));

        $users = [];
        $error = null;
        if ($selectedTenant && $q !== '') {
            $res = $this->searchUsersGraph($selectedTenant, $q);
            $users = $res['users'];
            if (!$res['success']) {
                $error = $res['error'];
            }
        }

        echo $this->page('index', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'q'              => $q,
            'users'          => $users,
            'error'          => $error,
        ]);
    }

    public function userPage(array $params = []): void
    {
        $id = (string)($params['id'] ?? '');
        $tenantId = (int)($_GET['tenant'] ?? 0);
        if ($id === '' || !$tenantId) {
            http_response_code(400);
            echo $this->page('error', ['module' => $this, 'message' => 'Usuario o tenant no indicado']);
            return;
        }

        $profile = $this->getUserProfile($tenantId, $id);
        $methods = $this->getAuthMethods($tenantId, $id);
        $mfa     = $this->getMfaRegistration($tenantId, $id);

        $days = (int)($_GET['days'] ?? 7);
        if (!in_array($days, [0, 1, 7, 14, 30], true)) {
            $days = 7;
        }
        $signIns = $this->getSignIns($tenantId, $id, $days, 100);
        $risk    = $this->getUserRisk($tenantId, $id);

        // País habitual = el más repetido en sus sign-ins
        $countries = [];
        foreach ($signIns['signIns'] as $s) {
            $c = $s['location']['countryOrRegion'] ?? null;
            if (!empty($c)) {
                $countries[$c] = ($countries[$c] ?? 0) + 1;
            }
        }
        arsort($countries);
        $usualCountry = $countries ? array_key_first($countries) : null;

        echo $this->page('user', [
            'module'       => $this,
            'tenant'       => TenantManager::getById($tenantId),
            'user'         => $profile['user'],
            'profileError' => $profile['success'] ? null : $profile['error'],
            'methods'      => $methods['methods'],
            'methodsError' => $methods['success'] ? null : $methods['error'],
            'mfa'          => $mfa['registration'],
            'mfaError'     => $mfa['success'] ? null : $mfa['error'],
            'signIns'      => $signIns['signIns'],
            'signInsError' => $signIns['success'] ? null : $signIns['error'],
            'signInsFallback' => $signIns['fallback'] ?? false,
            'days'         => $days,
            'risk'         => $risk['risk'],
            'riskError'    => $risk['success'] ? null : $risk['error'],
            'usualCountry' => $usualCountry,
            'countryCounts'=> $countries,
        ]);
    }

    public function riskyPage(array $params = []): void
    {
        $tenants = TenantManager::getActive();
        $selectedTenant = (int)($_GET['tenant'] ?? ($tenants[0]['id'] ?? 0));

        $users = [];
        $error = null;
        if ($selectedTenant) {
            $res = $this->getRiskyUsers($selectedTenant);
            $users = $res['users'];
            if (!$res['success']) {
                $error = $res['error'];
            }
        }

        echo $this->page('risky', [
            'module'         => $this,
            'tenants'        => $tenants,
            'selectedTenant' => $selectedTenant,
            'users'          => $users,
            'error'          => $error,
        ]);
    }
}
