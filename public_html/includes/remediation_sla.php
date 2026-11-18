<?php
/**
 * remediation_sla.php — SLA de remediación (CVE Desk, F1).
 *
 * Plazos en días naturales desde `importado` (o `created_at` en tareas
 * antiguas). La severidad manda; un activo en producción y criticidad alta
 * aplica el plazo reforzado (72 h para crítica).
 *
 * Estados: en_plazo · en_riesgo (≥80 % consumido) · vencido · cerrado ·
 * riesgo_aceptado · sin_datos.
 */

declare(strict_types=1);

final class RemediationSla
{
    /** @var array<string,int>|null */
    private static ?array $settingsCache = null;

    /** @var array<string,int>|null */
    private static ?array $criticalCache = null;

    /** Plazos base por severidad (días naturales). */
    public static function settings(): array
    {
        if (self::$settingsCache !== null) {
            return self::$settingsCache;
        }
        self::$settingsCache = [
            'critical' => max(1, (int)setting_get('remediation_sla_critical', '7')),
            'high'     => max(1, (int)setting_get('remediation_sla_high', '15')),
            'medium'   => max(1, (int)setting_get('remediation_sla_medium', '30')),
            'low'      => max(1, (int)setting_get('remediation_sla_low', '60')),
        ];
        return self::$settingsCache;
    }

    /** Plazos reforzados cuando el CVE afecta a un activo prod + crítico. */
    public static function criticalSettings(): array
    {
        if (self::$criticalCache !== null) {
            return self::$criticalCache;
        }
        self::$criticalCache = [
            'critical' => max(1, (int)setting_get('remediation_sla_critical_asset_critical', '3')),
            'high'     => max(1, (int)setting_get('remediation_sla_critical_asset_high', '7')),
            'medium'   => max(1, (int)setting_get('remediation_sla_critical_asset_medium', '15')),
            'low'      => max(1, (int)setting_get('remediation_sla_critical_asset_low', '30')),
        ];
        return self::$criticalCache;
    }

    public static function severityKey(string $severity, ?float $cvss = null): string
    {
        $value = strtolower(trim($severity));
        $value = str_replace(['á', 'é', 'í', 'ó', 'ú'], ['a', 'e', 'i', 'o', 'u'], $value);
        if (in_array($value, ['critical', 'critica', 'critico'], true)) {
            return 'critical';
        }
        if (in_array($value, ['high', 'alta', 'alto'], true)) {
            return 'high';
        }
        if (in_array($value, ['medium', 'media', 'medio'], true)) {
            return 'medium';
        }
        if (in_array($value, ['low', 'baja', 'bajo'], true)) {
            return 'low';
        }
        if ($cvss !== null) {
            if ($cvss >= 9.0) {
                return 'critical';
            }
            if ($cvss >= 7.0) {
                return 'high';
            }
            if ($cvss >= 4.0) {
                return 'medium';
            }
            if ($cvss > 0.0) {
                return 'low';
            }
        }
        return 'medium';
    }

    public static function daysFor(string $severity, bool $criticalAsset = false, ?float $cvss = null): int
    {
        $key = self::severityKey($severity, $cvss);
        $settings = $criticalAsset ? self::criticalSettings() : self::settings();
        return max(1, (int)($settings[$key] ?? $settings['medium']));
    }

    /**
     * SLA de una tarea. No escribe nada.
     *
     * @param array<string,mixed> $task
     */
    public static function forTask(array $task, bool $criticalAsset = false): array
    {
        $state = (string)($task['estado'] ?? '');
        if ($state === '') {
            $state = RemediationWorkflow::stateForStatus((string)($task['status'] ?? 'open'));
        }

        $severity = (string)($task['severity'] ?? '');
        $cvss = isset($task['cvss']) && $task['cvss'] !== null ? (float)$task['cvss'] : null;
        $start = (string)($task['importado'] ?? '');
        if ($start === '') {
            $start = (string)($task['created_at'] ?? '');
        }

        if ($state === 'riesgo_aceptado') {
            $days = self::daysFor($severity, $criticalAsset, $cvss);
            return self::build($days, $start, 'riesgo_aceptado', (string)($task['exception_until'] ?? ''), $criticalAsset);
        }

        $closedAt = '';
        if (in_array($state, ['cerrado'], true)
            || in_array((string)($task['status'] ?? ''), ['patched', 'mitigated', 'accepted', 'false_positive'], true)) {
            $closedAt = (string)($task['resolved_at'] ?? '');
        }

        $days = self::daysFor($severity, $criticalAsset, $cvss);
        return self::build($days, $start, $closedAt !== '' ? 'cerrado' : 'abierto', $closedAt, $criticalAsset);
    }

    /**
     * SLA desde una fecha (cola de CVEs y tareas por igual).
     */
    public static function forDate(
        ?string $start,
        string $severity,
        ?float $cvss = null,
        bool $criticalAsset = false,
        ?string $closedAt = null
    ): array {
        $days = self::daysFor($severity, $criticalAsset, $cvss);
        return self::build($days, (string)$start, $closedAt !== null && $closedAt !== '' ? 'cerrado' : 'abierto', (string)$closedAt, $criticalAsset);
    }

    /**
     * @return array{days:int,elapsed:int,day:int,pct:int,state:string,label:string,critical:bool}
     */
    private static function build(int $days, string $start, string $mode, string $closedAt, bool $critical): array
    {
        $today = strtotime(self::today());
        $startTs = strtotime(substr($start, 0, 10));
        if ($startTs === false || $start === '') {
            return [
                'days' => $days, 'elapsed' => 0, 'day' => 1, 'pct' => 0,
                'state' => 'sin_datos', 'label' => 'sin fecha de alta', 'critical' => $critical,
            ];
        }

        $elapsed = (int)floor(($today - $startTs) / 86400);
        $elapsed = max(0, $elapsed);
        $ratio = $days > 0 ? $elapsed / $days : 0;
        $pct = (int)max(0, min(100, (int)round($ratio * 100)));

        if ($mode === 'riesgo_aceptado') {
            $until = $closedAt !== '' ? format_date($closedAt, 'd/m/Y') : '—';
            return [
                'days' => $days, 'elapsed' => $elapsed, 'day' => min($days, $elapsed + 1),
                'pct' => 100, 'state' => 'riesgo_aceptado',
                'label' => 'riesgo aceptado · hasta ' . $until, 'critical' => $critical,
            ];
        }

        if ($mode === 'cerrado') {
            return [
                'days' => $days, 'elapsed' => $elapsed, 'day' => min($days, $elapsed + 1),
                'pct' => 100, 'state' => 'cerrado',
                'label' => 'cerrado en ' . $elapsed . ' d', 'critical' => $critical,
            ];
        }

        $state = $ratio >= 1 ? 'vencido' : ($ratio >= 0.8 ? 'en_riesgo' : 'en_plazo');
        return [
            'days'     => $days,
            'elapsed'  => $elapsed,
            'day'      => min($days, $elapsed + 1),
            'pct'      => $pct,
            'state'    => $state,
            'label'    => 'día ' . min($days, $elapsed + 1) . ' de ' . $days,
            'critical' => $critical,
        ];
    }

    public static function stateLabels(): array
    {
        return [
            'en_plazo'       => 'En plazo',
            'en_riesgo'      => 'En riesgo',
            'vencido'        => 'SLA vencido',
            'cerrado'        => 'Cerrado',
            'riesgo_aceptado'=> 'Riesgo aceptado',
            'sin_datos'      => 'Sin fecha',
        ];
    }

    /**
     * Fecha de hoy en la misma base que `importado` (SQLite almacena UTC).
     * Evita que el SLA se desplace un día en husos como Europe/Madrid.
     */
    private static function today(): string
    {
        static $today = null;
        if ($today !== null) {
            return $today;
        }
        try {
            $row = Database::fetchOne("SELECT date('now') AS d");
            $today = (string)($row['d'] ?? gmdate('Y-m-d'));
        } catch (Throwable $e) {
            $today = gmdate('Y-m-d');
        }
        return $today;
    }

    public static function barClasses(): array
    {
        return [
            'en_plazo'       => 'bg-emerald-500',
            'en_riesgo'      => 'bg-amber-500',
            'vencido'        => 'bg-red-500',
            'cerrado'        => 'bg-emerald-500',
            'riesgo_aceptado'=> 'bg-gray-400',
            'sin_datos'      => 'bg-gray-300',
        ];
    }

    public static function textClasses(): array
    {
        return [
            'en_plazo'       => 'text-ink-muted',
            'en_riesgo'      => 'text-amber-600 dark:text-amber-400',
            'vencido'        => 'text-red-600 dark:text-red-400 font-semibold',
            'cerrado'        => 'text-ink-muted',
            'riesgo_aceptado'=> 'text-ink-muted',
            'sin_datos'      => 'text-ink-soft',
        ];
    }

    /**
     * Tareas con algún activo en producción y criticidad alta/crítica.
     *
     * @param int[] $taskIds
     * @return array<int,true>
     */
    public static function criticalAssetsByTask(array $taskIds): array
    {
        $ids = array_values(array_filter(array_map('intval', $taskIds), static fn(int $id): bool => $id > 0));
        if ($ids === []) {
            return [];
        }
        $out = [];
        foreach (array_chunk($ids, 500) as $chunk) {
            $rows = Database::fetchAll(
                "SELECT DISTINCT task_id
                 FROM remediation_task_assets
                 WHERE task_id IN (" . implode(',', array_fill(0, count($chunk), '?')) . ")
                   AND environment = 'prod'
                   AND criticality IN ('alta', 'critica', 'crítica')",
                $chunk
            );
            foreach ($rows as $row) {
                $out[(int)$row['task_id']] = true;
            }
        }
        return $out;
    }
}
