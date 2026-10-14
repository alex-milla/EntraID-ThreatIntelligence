<?php
/**
 * Vista índice del módulo Threat Intelligence.
 */
?>
<?php
$tiActiveTab = 'reports';
$tiFilterQs = array_filter(['q' => $q ?? '', 'from' => $dateFrom ?? '', 'to' => $dateTo ?? ''], fn($v) => $v !== '' && $v !== null);
require VIEWS_PATH . '/partials/ti_header.php';

$stateCounts   = array_merge(['unread' => 0, 'favorites' => 0], (array)($stateCounts ?? []));
$onlyUnread    = !empty($onlyUnread);
$onlyFavorites = !empty($onlyFavorites);
$tiBaseQs = [
    'tenant' => (int)($selectedTenant ?? 0),
    'q'      => $q ?? '',
    'tag'    => $tag ?? '',
    'sector' => $sector ?? '',
    'from'   => $dateFrom ?? '',
    'to'     => $dateTo ?? '',
];
$tiStateUrl = function (array $extra) use ($tiBaseQs): string {
    return '?' . http_build_query(array_filter(array_merge($tiBaseQs, $extra), fn($v) => $v !== '' && $v !== null));
};
$chipOn  = 'inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-brand-500 text-white';
$chipOff = 'inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700';
?>

<div class="mb-6 space-y-3">
    <form method="GET" class="flex items-end gap-3 flex-wrap">
        <div>
            <label class="block text-xs text-gray-500 mb-1">Tenant</label>
            <select name="tenant" onchange="this.form.submit()"
                    class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 focus:border-transparent outline-none">
                <?php foreach ($tenants as $t): ?>
                    <option value="<?= $t['id'] ?>" <?= (int)($selectedTenant ?? 0) === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Buscar</label>
            <input type="text" name="q" value="<?= e($q ?? '') ?>" placeholder="APT, Storm-2992, sector…"
                   class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none w-56">
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Tag</label>
            <select name="tag" class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none max-w-[16rem]">
                <option value="">Todas las tags</option>
                <?php foreach (($tagOptions ?? []) as $tg => $cnt): ?>
                    <option value="<?= e($tg) ?>" <?= ($tag ?? '') === $tg ? 'selected' : '' ?>><?= e(truncate((string)$tg, 60)) ?> (<?= (int)$cnt ?>)</option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Sector</label>
            <select name="sector" class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="">Todos los sectores</option>
                <?php foreach (($sectors ?? []) as $sc): ?>
                    <option value="<?= e($sc) ?>" <?= ($sector ?? '') === $sc ? 'selected' : '' ?>><?= e($sc) ?></option>
                <?php endforeach; ?>
            </select>
            <?php if (!empty($mySector)): ?>
                <a href="?<?= e(http_build_query(array_filter(['tenant' => (int)$selectedTenant, 'from' => $dateFrom ?? '', 'to' => $dateTo ?? '', 'sector' => $mySector]))) ?>" class="text-[11px] text-brand-500 hover:underline">→ Mi sector (<?= e($mySector) ?>)</a>
            <?php endif; ?>
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Desde</label>
            <input type="date" name="from" value="<?= e($dateFrom ?? '') ?>"
                   class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <div>
            <label class="block text-xs text-gray-500 mb-1">Hasta</label>
            <input type="date" name="to" value="<?= e($dateTo ?? '') ?>"
                   class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <?php if ($onlyUnread): ?><input type="hidden" name="only_unread" value="1"><?php endif; ?>
        <?php if ($onlyFavorites): ?><input type="hidden" name="only_favorites" value="1"><?php endif; ?>
        <button type="submit" class="px-3 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">Filtrar</button>
        <?php
        $tiDefFrom = $dateDefaultFrom ?? '';
        $tiDefTo   = $dateDefaultTo ?? '';
        $tiDatesCustom = (($dateFrom ?? '') !== $tiDefFrom) || (($dateTo ?? '') !== $tiDefTo);
        ?>
        <?php if (($q ?? '') !== '' || ($tag ?? '') !== '' || ($sector ?? '') !== '' || $tiDatesCustom || $onlyUnread || $onlyFavorites): ?>
            <?php $tiClearQs = http_build_query(array_filter(['tenant' => (int)$selectedTenant, 'from' => $tiDefFrom, 'to' => $tiDefTo], fn($v) => $v !== '' && $v !== null)); ?>
            <a href="?<?= e($tiClearQs) ?>" class="text-xs text-gray-500 hover:underline">Limpiar</a>
        <?php endif; ?>
    </form>
    <div class="flex items-center gap-3 text-xs flex-wrap">
        <span class="text-gray-400">Rápido:</span>
        <?php foreach ([7 => '7 días', 30 => '30 días', 90 => '90 días'] as $d => $lbl): $f = gmdate('Y-m-d', strtotime($dateTo ?? 'now') - $d * 86400); ?>
            <a href="?<?= e(http_build_query(array_filter(array_merge($tiBaseQs, ['from' => $f, 'to' => $dateTo ?? ''])))) ?>" class="text-brand-500 hover:underline"><?= $lbl ?></a>
        <?php endforeach; ?>
        <span class="text-gray-400">· máx. 90 días</span>
    </div>
    <?php if (!empty($selectedTenant)): ?>
    <div class="flex items-center gap-2 text-xs flex-wrap">
        <span class="text-gray-400">Triaje:</span>
        <a href="?<?= e($tiStateUrl([])) ?>" class="<?= (!$onlyUnread && !$onlyFavorites) ? $chipOn : $chipOff ?>">Todas</a>
        <a href="?<?= e($tiStateUrl(['only_unread' => 1])) ?>" class="<?= $onlyUnread ? $chipOn : $chipOff ?>" title="Artículos sin leer"><span class="text-[10px] font-bold uppercase tracking-wide">New</span> Sin leer (<?= (int)$stateCounts['unread'] ?>)</a>
        <a href="?<?= e($tiStateUrl(['only_favorites' => 1])) ?>" class="<?= $onlyFavorites ? $chipOn : $chipOff ?>">★ Favoritas (<?= (int)$stateCounts['favorites'] ?>)</a>
    </div>
    <?php endif; ?>
</div>

<?php if (!empty($selectedTenant)): ?>
<!-- Stats de IOCs -->
<?php if (!empty($stats)): ?>
<div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
    <?php foreach ($stats as $s): ?>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-center">
            <p class="text-2xl font-bold text-brand-500"><?= number_format($s['cnt']) ?></p>
            <p class="text-xs text-gray-500 font-mono mt-1"><?= e($s['ioc_type']) ?></p>
        </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<!-- Artículos recientes -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
        <h2 class="text-sm font-semibold">Artículos recientes <span class="text-gray-400 font-normal">· por fecha de publicación</span></h2>
        <a href="<?= base_url('modules/threat_intelligence/iocs?tenant=' . $selectedTenant) ?>" class="text-xs text-brand-500 hover:underline">Ver todos los IOCs</a>
    </div>
    <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
        <?php if (empty($articles['data'])): ?>
            <p class="px-5 py-8 text-sm text-gray-500 text-center">Sin artículos. Sincroniza el tenant para obtener datos.</p>
        <?php else: ?>
            <?php foreach ($articles['data'] as $a):
                $artId   = (int)$a['id'];
                $unread  = empty($a['is_read']);
                $fav     = !empty($a['is_favorite']);
                $created = $a['created_date'] ?? null;
                $updated = $a['last_updated'] ?? null;
                $showUpdated = $created && $updated && substr((string)$updated, 0, 19) !== substr((string)$created, 0, 19);
                $isNew24 = $created && (strtotime((string)$created) !== false) && (strtotime((string)$created) >= time() - 86400);
                $rowUrl  = base_url('modules/threat_intelligence/article/' . $artId . '?' . http_build_query(array_filter([
                    'tenant' => (int)$selectedTenant, 'from' => $dateFrom ?? '', 'to' => $dateTo ?? '',
                    'q' => $q ?? '', 'tag' => $tag ?? '', 'sector' => $sector ?? '',
                    'only_unread' => $onlyUnread ? 1 : '', 'only_favorites' => $onlyFavorites ? 1 : '',
                ])));
            ?>
                <div class="px-5 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors border-l-2 <?= $isNew24 ? 'border-brand-500' : 'border-transparent' ?>"
                     data-art="<?= $artId ?>" data-read="<?= $unread ? '0' : '1' ?>" data-fav="<?= $fav ? '1' : '0' ?>">
                    <div class="flex items-start justify-between gap-3">
                        <a href="<?= e($rowUrl) ?>" class="min-w-0 flex-1">
                            <div class="flex items-center gap-2 min-w-0">
                                <span data-role="new" class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide bg-brand-500 text-white <?= $unread ? '' : 'hidden' ?>">New</span>
                                <?php if ($isNew24): ?><span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 shrink-0" title="Publicado en las últimas 24 h">24 h</span><?php endif; ?>
                                <p class="text-sm font-medium truncate"><?= e($a['title']) ?></p>
                            </div>
                            <p class="text-xs text-gray-400 mt-0.5">
                                <?= format_date($created ?: $updated) ?>
                                <?php if ($showUpdated): ?> · <span title="Última actualización del artículo">actualizado <?= format_date($updated) ?></span><?php endif; ?>
                                · <?= (int)$a['ioc_count'] ?> IOCs
                            </p>
                        </a>
                        <div class="flex items-center gap-1 shrink-0">
                            <button type="button" data-role="fav" onclick="tiFav(event, <?= $artId ?>)" title="<?= $fav ? 'Quitar de favoritos' : 'Añadir a favoritos' ?>"
                                    class="w-7 h-7 inline-flex items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 text-base leading-none <?= $fav ? 'text-amber-400' : 'text-gray-300 dark:text-gray-600' ?>"><?= $fav ? '★' : '☆' ?></button>
                            <button type="button" data-role="read" onclick="tiRead(event, <?= $artId ?>)" title="<?= $unread ? 'Marcar como leído' : 'Dejar sin leer' ?>"
                                    class="w-7 h-7 inline-flex items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 <?= $unread ? 'text-gray-400' : 'text-green-500' ?>">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                            </button>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</div>
<?php else: ?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
    <p class="text-sm text-gray-500">Selecciona un tenant para ver los datos de Threat Intelligence.</p>
</div>
<?php endif; ?>

<script>
var TI_STATE_FILTER = <?= ($onlyUnread || $onlyFavorites) ? 'true' : 'false' ?>;
var TI_STATE_URL = '<?= base_url('modules/threat_intelligence/article') ?>';
function tiSetState(id, payload) {
    api('POST', TI_STATE_URL + '/' + id + '/state', payload).then(function (res) {
        if (!res || !res.success) { toast((res && res.error) ? res.error : 'Error', 'error'); return; }
        var row = document.querySelector('[data-art="' + id + '"]');
        if (row) {
            var nb = row.querySelector('[data-role="new"]');
            if (nb) { nb.classList.toggle('hidden', !!res.is_read); }
            var fb = row.querySelector('[data-role="fav"]');
            if (fb) {
                fb.textContent = res.is_favorite ? '\u2605' : '\u2606';
                fb.classList.toggle('text-amber-400', !!res.is_favorite);
                fb.classList.toggle('text-gray-300', !res.is_favorite);
                fb.classList.toggle('dark:text-gray-600', !res.is_favorite);
                fb.title = res.is_favorite ? 'Quitar de favoritos' : 'Añadir a favoritos';
            }
            var rb = row.querySelector('[data-role="read"]');
            if (rb) {
                rb.title = res.is_read ? 'Dejar sin leer' : 'Marcar como leído';
                rb.classList.toggle('text-green-500', !!res.is_read);
                rb.classList.toggle('text-gray-400', !res.is_read);
            }
            row.dataset.read = res.is_read ? '1' : '0';
            row.dataset.fav = res.is_favorite ? '1' : '0';
        }
        if (TI_STATE_FILTER) { location.reload(); }
    }).catch(function () { toast('Error de conexión', 'error'); });
}
function tiRead(ev, id) {
    if (ev) { ev.preventDefault(); ev.stopPropagation(); }
    var row = document.querySelector('[data-art="' + id + '"]');
    var cur = row && row.dataset.read === '1';
    tiSetState(id, { is_read: cur ? 0 : 1 });
}
function tiFav(ev, id) {
    if (ev) { ev.preventDefault(); ev.stopPropagation(); }
    var row = document.querySelector('[data-art="' + id + '"]');
    var cur = row && row.dataset.fav === '1';
    tiSetState(id, { is_favorite: cur ? 0 : 1 });
}
</script>

<?php if (!empty($selectedTenant)) { require VIEWS_PATH . '/partials/ti_sync.php'; } ?>
