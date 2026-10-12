<?php
/**
 * TenantManager — Gestión de tenants multi-empresa.
 * CRUD de tenants, grupos de tenants y descifrado seguro de credenciales.
 */

declare(strict_types=1);

class TenantManager
{
    /**
     * Obtiene todos los tenants activos.
     */
    public static function getActive(): array
    {
        return Database::fetchAll(
            "SELECT t.*, tg.id as in_group, tg.name as group_name
             FROM tenants t
             LEFT JOIN tenant_group_members tgm ON t.id = tgm.tenant_id
             LEFT JOIN tenant_groups tg ON tgm.group_id = tg.id
             WHERE t.is_active = 1
             ORDER BY t.name"
        );
    }

    /**
     * Obtiene todos los tenants (incluidos inactivos).
     */
    public static function getAll(): array
    {
        return Database::fetchAll("SELECT * FROM tenants ORDER BY name");
    }

    /**
     * Obtiene un tenant por ID (con el secret aún cifrado).
     */
    public static function getById(int $id): ?array
    {
        return Database::fetchOne("SELECT * FROM tenants WHERE id = ?", [$id]);
    }

    /**
     * Obtiene un tenant por slug.
     */
    public static function getBySlug(string $slug): ?array
    {
        return Database::fetchOne("SELECT * FROM tenants WHERE slug = ?", [$slug]);
    }

    /**
     * Obtiene un tenant con el client_secret descifrado (uso interno, NUNCA exponer).
     */
    public static function getWithSecret(int $id): ?array
    {
        $tenant = self::getById($id);
        if (!$tenant) return null;
        $tenant['client_secret'] = Encryption::decrypt(
            $tenant['client_secret_encrypted'],
            $tenant['client_secret_iv']
        );
        unset($tenant['client_secret_encrypted'], $tenant['client_secret_iv']);
        return $tenant;
    }

    /**
     * Crea un nuevo tenant. El client_secret se cifra antes de almacenar.
     */
    public static function create(array $data): array
    {
        $errors = [];

        if (empty($data['name'])) $errors[] = 'El nombre es obligatorio';
        if (empty($data['tenant_id'])) $errors[] = 'El Tenant ID es obligatorio';
        if (empty($data['client_id'])) $errors[] = 'El Client ID es obligatorio';
        if (empty($data['client_secret'])) $errors[] = 'El Client Secret es obligatorio';

        $slug = $data['slug'] ?? slugify($data['name']);
        $existing = Database::fetchOne("SELECT id FROM tenants WHERE slug = ? OR tenant_id = ?", [$slug, $data['tenant_id']]);
        if ($existing) $errors[] = 'Ya existe un tenant con ese slug o Tenant ID';

        if (!empty($errors)) {
            return ['success' => false, 'errors' => $errors];
        }

        // Cifrar el secret NUNCA en texto plano
        $encrypted = Encryption::encrypt($data['client_secret']);

        $id = Database::insert(
            "INSERT INTO tenants (name, slug, tenant_id, client_id, client_secret_encrypted, client_secret_iv, permissions, is_active)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                trim($data['name']),
                $slug,
                trim($data['tenant_id']),
                trim($data['client_id']),
                $encrypted['encrypted'],
                $encrypted['iv'],
                json_encode($data['permissions'] ?? [], JSON_UNESCAPED_SLASHES),
                !empty($data['is_active']) ? 1 : 0,
            ]
        );

        log_activity('tenant.created', ['tenant_id' => $id, 'name' => $data['name']]);
        return ['success' => true, 'tenant_id' => $id, 'slug' => $slug];
    }

    /**
     * Actualiza un tenant. Si se proporciona client_secret, se recifra.
     */
    public static function update(int $id, array $data): array
    {
        $tenant = self::getById($id);
        if (!$tenant) {
            return ['success' => false, 'errors' => ['Tenant no encontrado']];
        }

        $fields = [];
        $params = [];

        if (isset($data['name'])) {
            $fields[] = 'name = ?';
            $params[] = trim($data['name']);
        }
        if (isset($data['tenant_id'])) {
            $fields[] = 'tenant_id = ?';
            $params[] = trim($data['tenant_id']);
        }
        if (isset($data['client_id'])) {
            $fields[] = 'client_id = ?';
            $params[] = trim($data['client_id']);
        }
        if (!empty($data['client_secret'])) {
            $encrypted = Encryption::encrypt($data['client_secret']);
            $fields[] = 'client_secret_encrypted = ?';
            $params[] = $encrypted['encrypted'];
            $fields[] = 'client_secret_iv = ?';
            $params[] = $encrypted['iv'];
        }
        if (isset($data['permissions'])) {
            $fields[] = 'permissions = ?';
            $params[] = json_encode($data['permissions'], JSON_UNESCAPED_SLASHES);
        }
        if (isset($data['is_active'])) {
            $fields[] = 'is_active = ?';
            $params[] = !empty($data['is_active']) ? 1 : 0;
        }

        if (empty($fields)) {
            return ['success' => false, 'errors' => ['No hay datos para actualizar']];
        }

        $fields[] = "updated_at = datetime('now')";
        $params[] = $id;

        Database::update(
            "UPDATE tenants SET " . implode(', ', $fields) . " WHERE id = ?",
            $params
        );

        log_activity('tenant.updated', ['tenant_id' => $id]);
        return ['success' => true];
    }

    /**
     * Elimina un tenant y todos sus datos asociados (cascada).
     */
    public static function delete(int $id): bool
    {
        $tenant = self::getById($id);
        if (!$tenant) return false;

        Database::transaction(function (PDO $db) use ($id): void {
            // Eliminar en orden por las foreign keys
            $db->prepare("DELETE FROM tenant_group_members WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM ti_iocs WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM ti_articles WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM alerts WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM incidents WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM vulnerabilities WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM machines WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM secure_scores WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM hunting_results WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM reports WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM sync_log WHERE tenant_id = ?")->execute([$id]);
            $db->prepare("DELETE FROM tenants WHERE id = ?")->execute([$id]);
        });

        log_activity('tenant.deleted', ['tenant_id' => $id, 'name' => $tenant['name']]);
        return true;
    }

    /**
     * Activa/desactiva un tenant.
     */
    public static function toggleActive(int $id): bool
    {
        Database::update(
            "UPDATE tenants SET is_active = 1 - is_active, updated_at = datetime('now') WHERE id = ?",
            [$id]
        );
        return true;
    }

    // ============================================================
    // Grupos de tenants (multitenant de una misma empresa)
    // ============================================================

    public static function getGroups(): array
    {
        return Database::fetchAll(
            "SELECT tg.*, COUNT(tgm.tenant_id) as tenant_count
             FROM tenant_groups tg
             LEFT JOIN tenant_group_members tgm ON tg.id = tgm.group_id
             GROUP BY tg.id
             ORDER BY tg.name"
        );
    }

    public static function createGroup(string $name, string $description = ''): array
    {
        $slug = slugify($name);
        $existing = Database::fetchOne("SELECT id FROM tenant_groups WHERE slug = ?", [$slug]);
        if ($existing) {
            return ['success' => false, 'errors' => ['Ya existe un grupo con ese nombre']];
        }

        $id = Database::insert(
            "INSERT INTO tenant_groups (name, slug, description) VALUES (?, ?, ?)",
            [trim($name), $slug, $description]
        );

        return ['success' => true, 'group_id' => $id];
    }

    public static function addTenantToGroup(int $tenantId, int $groupId): bool
    {
        Database::query(
            "INSERT OR IGNORE INTO tenant_group_members (tenant_id, group_id) VALUES (?, ?)",
            [$tenantId, $groupId]
        );
        return true;
    }

    public static function removeTenantFromGroup(int $tenantId, int $groupId): bool
    {
        Database::query(
            "DELETE FROM tenant_group_members WHERE tenant_id = ? AND group_id = ?",
            [$tenantId, $groupId]
        );
        return true;
    }

    public static function getTenantsInGroup(int $groupId): array
    {
        return Database::fetchAll(
            "SELECT t.* FROM tenants t
             INNER JOIN tenant_group_members tgm ON t.id = tgm.tenant_id
             WHERE tgm.group_id = ? AND t.is_active = 1
             ORDER BY t.name",
            [$groupId]
        );
    }

    /**
     * Obtiene estadísticas globales por tenant.
     */
    public static function getStats(int $tenantId): array
    {
        $stats = [];
        $tables = [
            'articles'       => 'ti_articles',
            'iocs'           => 'ti_iocs',
            'incidents'      => 'incidents',
            'alerts'         => 'alerts',
            'machines'       => 'machines',
            'vulnerabilities'=> 'vulnerabilities',
            'secure_scores'  => 'secure_scores',
            'hunting'        => 'hunting_results',
        ];

        foreach ($tables as $key => $table) {
            $row = Database::fetchOne(
                "SELECT COUNT(*) as cnt FROM $table WHERE tenant_id = ?",
                [$tenantId]
            );
            $stats[$key] = (int)($row['cnt'] ?? 0);
        }

        return $stats;
    }
}
