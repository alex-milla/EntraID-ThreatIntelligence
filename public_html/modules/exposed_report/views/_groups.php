<?php
/**
 * Parcial: pestaña «Grupos de análisis» de Equipos expuestos (v0.4.26.2).
 *
 * Lista los grupos con su número de CVE, la prioridad máxima, el estado del
 * informe y el acceso a la ficha.
 *
 * @var array $console
 */

$console = is_array($console ?? null) ? $console : [];
$groups = is_array($console['groups'] ?? null) ? $console['groups'] : [];
$base = base_url('modules/exposed_report');
$fmtDate = static function (?string $value): string {
    $value = trim((string)$value);
    if ($value === '') {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('d/m/Y H:i', $ts);
};
?>

<div class="space-y-5">

    <div class="card p-5">
        <div class="flex items-start justify-between gap-3 flex-wrap">
            <div class="min-w-0">
                <h2 class="text-sm font-semibold m-0">Grupos de análisis</h2>
                <p class="text-xs text-ink-muted m-0 mt-1 max-w-2xl">
                    Cada grupo guarda los CVE que seleccionaste y su contexto TVM. Desde su ficha se
                    calcula el informe de remediación (prioridad P1–P4, plan por fases, racimos y fichas)
                    y se puede generar la lectura del riesgo con tu IA o crear las tareas en Remediación.
                </p>
            </div>
            <a href="<?= e($base) ?>" class="btn btn-outline text-xs">
                <?= icon('add', 14) ?> Crear desde la consola
            </a>
        </div>
    </div>

    <div class="card overflow-hidden">
        <?php if ($groups === []): ?>
            <p class="p-6 text-sm text-ink-muted m-0">
                Todavía no hay grupos. Ve a <strong>Consola del tenant</strong>, filtra los CVE que te
                interesen, selecciónalos y pulsa <strong>Crear grupo</strong>.
            </p>
        <?php else: ?>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead class="bg-muted text-ink-muted">
                        <tr>
                            <th class="px-3 py-2 text-left">Grupo</th>
                            <th class="px-3 py-2 text-right">CVE</th>
                            <th class="px-3 py-2 text-left">Filtro de origen</th>
                            <th class="px-3 py-2 text-left">Informe</th>
                            <th class="px-3 py-2 text-left">Creado</th>
                            <th class="px-3 py-2"></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-line">
                        <?php foreach ($groups as $group): ?>
                            <?php
                            $gid = (int)($group['id'] ?? 0);
                            $filters = safe_json_decode((string)($group['filters_json'] ?? ''), []);
                            $filterText = [];
                            if (is_array($filters)) {
                                foreach ($filters as $key => $value) {
                                    if ($key === 'sort') {
                                        continue;
                                    }
                                    if (is_array($value)) {
                                        $filterText[] = $key . ': ' . implode('/', array_map('strval', $value));
                                    } elseif ((string)$value !== '') {
                                        $filterText[] = $key . ': ' . (string)$value;
                                    }
                                }
                            }
                            ?>
                            <tr class="hover:bg-muted/50">
                                <td class="px-3 py-2">
                                    <a href="<?= e($base . '/group/' . $gid . '?back=' . rawurlencode('?tab=groups')) ?>"
                                       data-prefetch
                                       class="font-medium text-brand-600 dark:text-brand-300 hover:underline">
                                        <?= e((string)($group['name'] ?? ('Grupo #' . $gid))) ?>
                                    </a>
                                </td>
                                <td class="px-3 py-2 text-right font-mono"><?= (int)($group['cve_count'] ?? 0) ?></td>
                                <td class="px-3 py-2 text-ink-soft max-w-[280px]">
                                    <?= $filterText !== [] ? e(implode(' · ', $filterText)) : 'sin filtro' ?>
                                </td>
                                <td class="px-3 py-2">
                                    <?php if (!empty($group['plan_generated_at'])): ?>
                                        <span class="inline-flex items-center gap-1 text-green-700 dark:text-green-300">
                                            <?= icon('check_circle', 13) ?>
                                            IA · <?= e($fmtDate((string)$group['plan_generated_at'])) ?>
                                        </span>
                                    <?php else: ?>
                                        <span class="text-ink-soft">Solo datos (sin IA)</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-3 py-2 text-ink-soft whitespace-nowrap">
                                    <?= e($fmtDate((string)($group['created_at'] ?? ''))) ?>
                                </td>
                                <td class="px-3 py-2 text-right">
                                    <a href="<?= e($base . '/group/' . $gid . '?back=' . rawurlencode('?tab=groups')) ?>"
                                       data-prefetch
                                       class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline">
                                        Abrir
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>
