<?php
/**
 * Vista: Seguridad — intentos de acceso y detección de fuerza bruta.
 * Variables: $summary, $suspects, $topUsers, $attempts, $filters, $total, $page, $totalPages
 */
$pageTitle = 'Seguridad';

$reasonLabel = function (?string $reason): string {
    return match ((string)$reason) {
        'ok'              => 'correcto',
        'no_user'         => 'usuario inexistente',
        'bad_credentials' => 'contraseña incorrecta',
        'empty'           => 'campos vacíos',
        default           => ($reason ?? '') !== '' ? (string)$reason : '—',
    };
};

$filters = $filters ?? [];
$qsBase = array_filter([
    'result' => $filters['result'] ?? '',
    'user'   => $filters['user'] ?? '',
    'ip'     => $filters['ip'] ?? '',
    'from'   => $filters['from'] ?? '',
    'to'     => $filters['to'] ?? '',
], fn($v) => $v !== '' && $v !== null);
$pageUrl = function (array $extra = []) use ($qsBase): string {
    return '?' . http_build_query(array_merge($qsBase, $extra));
};
$hasFilters = !empty($qsBase);

$failed = (int)($summary['failed'] ?? 0);
$ok24   = (int)($summary['ok'] ?? 0);
$total24 = (int)($summary['total'] ?? 0);
$nSuspects = count($suspects ?? []);
?>

<div class="mb-6">
    <h2 class="text-xl font-bold">Seguridad</h2>
    <p class="text-xs text-ink-soft mt-1">
        Intentos de acceso al portal y detección de fuerza bruta. Se conservan <?= (int)LOGIN_RETENTION_DAYS ?> días.
        Una IP se marca como sospechosa con <?= (int)LOGIN_BRUTE_THRESHOLD ?>+ fallos en <?= (int)LOGIN_BRUTE_WINDOW_MIN ?> min.
    </p>
</div>

<?php if ($nSuspects > 0): ?>
<div class="mb-6 rounded-lg border border-danger-border bg-danger-bg px-4 py-3">
    <p class="text-sm text-danger">
        ⚠️ <strong><?= $nSuspects ?></strong> IP<?= $nSuspects === 1 ? '' : 's' ?> con posible fuerza bruta en los últimos <?= (int)LOGIN_BRUTE_WINDOW_MIN ?> minutos.
    </p>
</div>
<?php endif; ?>

<!-- Resumen -->
<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <div class="card p-4">
        <p class="text-xs text-ink-muted">Intentos (24 h)</p>
        <p class="text-2xl font-bold mt-1"><?= number_format($total24) ?></p>
    </div>
    <div class="card p-4">
        <p class="text-xs text-ink-muted">Fallidos (24 h)</p>
        <p class="text-2xl font-bold mt-1 <?= $failed > 0 ? 'text-red-500' : '' ?>"><?= number_format($failed) ?></p>
    </div>
    <div class="card p-4">
        <p class="text-xs text-ink-muted">Correctos (24 h)</p>
        <p class="text-2xl font-bold mt-1 text-success"><?= number_format($ok24) ?></p>
    </div>
    <div class="card p-4">
        <p class="text-xs text-ink-muted">IPs sospechosas</p>
        <p class="text-2xl font-bold mt-1 <?= $nSuspects > 0 ? 'text-red-500' : '' ?>"><?= $nSuspects ?></p>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <!-- IPs sospechosas -->
    <div class="card overflow-hidden">
        <div class="px-5 py-3 border-b border-line">
            <h3 class="text-sm font-semibold">IPs sospechosas (<?= (int)LOGIN_BRUTE_WINDOW_MIN ?> min)</h3>
        </div>
        <?php if (empty($suspects)): ?>
            <p class="px-5 py-6 text-sm text-ink-muted text-center">Sin actividad sospechosa.</p>
        <?php else: ?>
            <table class="data-table w-full text-sm">
                <thead><tr class="border-b border-line bg-muted text-xs text-ink-muted uppercase">
                    <th class="text-left px-4 py-2">IP</th><th class="text-right px-4 py-2">Fallos</th><th class="text-right px-4 py-2">Usuarios</th><th class="text-left px-4 py-2">Último</th>
                </tr></thead>
                <tbody class="divide-y divide-line-subtle">
                    <?php foreach ($suspects as $s): ?>
                        <tr class="hover:bg-muted">
                            <td class="px-4 py-2 font-mono text-xs"><a href="<?= e($pageUrl(['ip' => $s['ip'], 'result' => 'fail'])) ?>" class="text-brand-500 hover:underline"><?= e((string)$s['ip']) ?></a></td>
                            <td class="px-4 py-2 text-right text-red-500 font-semibold"><?= (int)$s['fails'] ?></td>
                            <td class="px-4 py-2 text-right text-ink-muted"><?= (int)$s['users'] ?></td>
                            <td class="px-4 py-2 text-xs text-ink-muted"><?= e(time_ago((string)$s['last_seen'])) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- Usuarios más atacados -->
    <div class="card overflow-hidden">
        <div class="px-5 py-3 border-b border-line">
            <h3 class="text-sm font-semibold">Usuarios más atacados (24 h)</h3>
        </div>
        <?php if (empty($topUsers)): ?>
            <p class="px-5 py-6 text-sm text-ink-muted text-center">Sin fallos recientes.</p>
        <?php else: ?>
            <table class="data-table w-full text-sm">
                <thead><tr class="border-b border-line bg-muted text-xs text-ink-muted uppercase">
                    <th class="text-left px-4 py-2">Usuario</th><th class="text-right px-4 py-2">Fallos</th>
                </tr></thead>
                <tbody class="divide-y divide-line-subtle">
                    <?php foreach ($topUsers as $u): ?>
                        <tr class="hover:bg-muted">
                            <td class="px-4 py-2"><a href="<?= e($pageUrl(['user' => (string)$u['username'], 'result' => 'fail'])) ?>" class="text-brand-500 hover:underline"><?= e((string)$u['username']) ?></a></td>
                            <td class="px-4 py-2 text-right text-red-500 font-semibold"><?= (int)$u['fails'] ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<!-- Filtros -->
<form method="GET" class="mb-4 flex items-end gap-3 flex-wrap">
    <div>
        <label class="block text-xs text-ink-muted mb-1">Resultado</label>
        <select name="result" class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <option value="">Todos</option>
            <option value="ok" <?= ($filters['result'] ?? '') === 'ok' ? 'selected' : '' ?>>Correctos</option>
            <option value="fail" <?= ($filters['result'] ?? '') === 'fail' ? 'selected' : '' ?>>Fallidos</option>
        </select>
    </div>
    <div>
        <label class="block text-xs text-ink-muted mb-1">Usuario</label>
        <input type="text" name="user" value="<?= e($filters['user'] ?? '') ?>" class="px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none w-40">
    </div>
    <div>
        <label class="block text-xs text-ink-muted mb-1">IP</label>
        <input type="text" name="ip" value="<?= e($filters['ip'] ?? '') ?>" class="px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none w-40">
    </div>
    <div>
        <label class="block text-xs text-ink-muted mb-1">Desde</label>
        <input type="date" name="from" value="<?= e($filters['from'] ?? '') ?>" class="px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none">
    </div>
    <div>
        <label class="block text-xs text-ink-muted mb-1">Hasta</label>
        <input type="date" name="to" value="<?= e($filters['to'] ?? '') ?>" class="px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none">
    </div>
    <button type="submit" class="px-3 py-2 bg-muted hover:bg-surface-3 text-ink text-sm font-medium rounded-lg transition-colors">Filtrar</button>
    <?php if ($hasFilters): ?><a href="?" class="text-xs text-ink-muted hover:underline">Limpiar</a><?php endif; ?>
</form>

<!-- Intentos -->
<div class="card overflow-hidden">
    <div class="px-5 py-3 border-b border-line flex items-center justify-between">
        <h3 class="text-sm font-semibold">Intentos de acceso</h3>
        <span class="text-xs text-ink-soft"><?= number_format($total) ?></span>
    </div>
    <?php if (empty($attempts)): ?>
        <p class="px-5 py-8 text-sm text-ink-muted text-center">Sin registros para estos filtros.</p>
    <?php else: ?>
        <div class="overflow-x-auto">
        <table class="data-table w-full text-sm">
            <thead><tr class="border-b border-line bg-muted text-xs text-ink-muted uppercase">
                <th class="text-left px-4 py-2">Fecha</th>
                <th class="text-left px-4 py-2">Usuario</th>
                <th class="text-left px-4 py-2">Resultado</th>
                <th class="text-left px-4 py-2">Motivo</th>
                <th class="text-left px-4 py-2">IP</th>
                <th class="text-left px-4 py-2">User-agent</th>
            </tr></thead>
            <tbody class="divide-y divide-line-subtle">
                <?php foreach ($attempts as $a): $isOk = !empty($a['success']); ?>
                    <tr class="hover:bg-muted">
                        <td class="px-4 py-2 text-xs text-ink-muted whitespace-nowrap"><?= e(format_date((string)$a['created_at'])) ?></td>
                        <td class="px-4 py-2 font-mono text-xs"><?= e((string)($a['username'] ?? '—')) ?></td>
                        <td class="px-4 py-2"><span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $isOk ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' ?>"><?= $isOk ? 'OK' : 'Fallo' ?></span></td>
                        <td class="px-4 py-2 text-xs text-ink-muted"><?= e($reasonLabel((string)($a['reason'] ?? ''))) ?></td>
                        <td class="px-4 py-2 font-mono text-xs"><?= e((string)($a['ip'] ?? '')) ?></td>
                        <td class="px-4 py-2 text-xs text-ink-soft max-w-xs truncate" title="<?= e((string)($a['user_agent'] ?? '')) ?>"><?= e(truncate((string)($a['user_agent'] ?? ''), 60)) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    <?php endif; ?>
</div>

<?php if (($totalPages ?? 1) > 1): ?>
<div class="mt-4 flex items-center justify-center gap-2 text-sm">
    <?php if (($page ?? 1) > 1): ?><a href="<?= e($pageUrl(['page' => (int)$page - 1])) ?>" class="px-3 py-1.5 border border-line rounded-lg hover:bg-muted">« Anterior</a><?php endif; ?>
    <span class="text-xs text-ink-muted">Página <?= (int)$page ?> de <?= (int)$totalPages ?></span>
    <?php if (($page ?? 1) < ($totalPages ?? 1)): ?><a href="<?= e($pageUrl(['page' => (int)$page + 1])) ?>" class="px-3 py-1.5 border border-line rounded-lg hover:bg-muted">Siguiente »</a><?php endif; ?>
</div>
<?php endif; ?>
