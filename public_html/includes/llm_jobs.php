<?php
/**
 * llm_jobs.php — Trabajos de IA en segundo plano (estado y progreso).
 *
 * Un análisis por partes puede tardar minutos: más de lo que aguanta un proxy
 * o el navegador. Aquí se guarda el estado del trabajo en la tabla `llm_jobs`
 * para que la pantalla pueda responder al instante y sondear el avance.
 *
 * El trabajo corre en el mismo proceso PHP-FPM (patrón de cve-worker.php):
 * se responde al navegador, se cierra la conexión y se sigue trabajando. Si
 * el proceso muere, el estado queda `running` y la marca de tiempo permite
 * darlo por caducado (ver llm_job_is_stale()).
 *
 * Nunca lanza: si la tabla no existe (instalación antigua), devuelve un
 * objeto vacío y el módulo trabaja en línea como siempre.
 */

declare(strict_types=1);

if (!function_exists('llm_job_create')) {
    /**
     * Crea un trabajo y devuelve su id y su token.
     *
     * @return array{id:int,token:string}
     */
    function llm_job_create(string $kind, ?int $refId = null, ?int $profileId = null, ?int $userId = null): array
    {
        $token = bin2hex(random_bytes(16));
        try {
            $id = Database::insert(
                "INSERT INTO llm_jobs (token, kind, ref_id, estado, fase, hechos, total, perfil, usuario, created_at, updated_at)
                 VALUES (?, ?, ?, 'queued', '', 0, 0, ?, ?, datetime('now'), datetime('now'))",
                [$token, $kind, $refId, $profileId, $userId]
            );
            // Los trabajos son telemetría viva: no hace falta conservarlos más
            // de 90 días (el resultado final vive en el módulo que lo pidió).
            Database::query("DELETE FROM llm_jobs WHERE created_at < datetime('now', '-90 days')");
            return ['id' => (int)$id, 'token' => $token];
        } catch (Throwable $e) {
            return ['id' => 0, 'token' => ''];
        }
    }
}

if (!function_exists('llm_job_get')) {
    /** @return array<string,mixed>|null */
    function llm_job_get(int $id): ?array
    {
        if ($id <= 0) {
            return null;
        }
        try {
            $row = Database::fetchOne('SELECT * FROM llm_jobs WHERE id = ?', [$id]);
        } catch (Throwable $e) {
            return null;
        }
        return is_array($row) ? $row : null;
    }
}

if (!function_exists('llm_job_set')) {
    /**
     * Actualiza campos del trabajo (lista blanca: nada de SQL libre).
     *
     * @param array<string,mixed> $fields
     */
    function llm_job_set(int $id, array $fields): void
    {
        if ($id <= 0 || $fields === []) {
            return;
        }
        $allowed = ['estado', 'fase', 'hechos', 'total', 'resultado_md', 'resultado_json', 'error', 'perfil'];
        $sets = [];
        $params = [];
        foreach ($fields as $key => $value) {
            if (!in_array($key, $allowed, true)) {
                continue;
            }
            $sets[] = $key . ' = ?';
            $params[] = $value;
        }
        if ($sets === []) {
            return;
        }
        $params[] = $id;
        try {
            Database::update(
                'UPDATE llm_jobs SET ' . implode(', ', $sets) . ", updated_at = datetime('now') WHERE id = ?",
                $params
            );
        } catch (Throwable $e) {
            // El estado del trabajo nunca debe romper el análisis.
        }
    }
}

if (!function_exists('llm_job_progress')) {
    /** Marca el trabajo en curso con su avance (parte X de Y). */
    function llm_job_progress(int $id, string $fase, int $hechos, int $total): void
    {
        llm_job_set($id, [
            'estado'  => 'running',
            'fase'    => llm_str_cut($fase, 190),
            'hechos'  => max(0, $hechos),
            'total'   => max(0, $total),
        ]);
    }
}

if (!function_exists('llm_job_finish')) {
    /** Cierra el trabajo con su resultado (Markdown y/o JSON). */
    function llm_job_finish(int $id, ?string $content, mixed $data = null): void
    {
        $json = null;
        if ($data !== null) {
            $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            if ($json === false) {
                $json = null;
            }
        }
        $job = llm_job_get($id);
        llm_job_set($id, [
            'estado'         => 'done',
            'fase'           => 'Completado',
            'hechos'         => (int)($job['total'] ?? 0),
            'resultado_md'   => $content,
            'resultado_json' => $json,
            'error'          => null,
        ]);
    }
}

if (!function_exists('llm_job_fail')) {
    /** Cierra el trabajo con error. */
    function llm_job_fail(int $id, string $error): void
    {
        llm_job_set($id, [
            'estado' => 'error',
            'fase'   => 'Error',
            'error'  => llm_str_cut($error, 2000),
        ]);
    }
}

if (!function_exists('llm_job_cancel')) {
    /**
     * Pide detener un trabajo en curso. El motor lo comprueba entre parte y
     * parte: la llamada en vuelo termina, no se corta a mitad de HTTP.
     */
    function llm_job_cancel(int $id): bool
    {
        if ($id <= 0) {
            return false;
        }
        try {
            return Database::update(
                "UPDATE llm_jobs SET cancelado = 1, updated_at = datetime('now') WHERE id = ? AND estado IN ('queued', 'running')",
                [$id]
            ) > 0;
        } catch (Throwable $e) {
            return false;
        }
    }
}

if (!function_exists('llm_job_is_cancelled')) {
    /** ¿El usuario pidió detener este trabajo? */
    function llm_job_is_cancelled(int $id): bool
    {
        if ($id <= 0) {
            return false;
        }
        try {
            $row = Database::fetchOne('SELECT cancelado FROM llm_jobs WHERE id = ?', [$id]);
        } catch (Throwable $e) {
            return false;
        }
        return (int)($row['cancelado'] ?? 0) === 1;
    }
}
