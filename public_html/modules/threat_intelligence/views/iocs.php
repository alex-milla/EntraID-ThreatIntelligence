<?php
/**
 * Vista: lista de IOCs de Threat Intelligence (filtros + paginación).
 * Variables: $module, $tenants, $selectedTenant, $filters, $iocs, $types
 */
$rows = $iocs['data'] ?? [];
$totalPages = (int)($iocs['totalPages'] ?? 1);
$page = (int)($iocs['page'] ?? 1);

// Rango por defecto (24 h) para poder restablecer y para detectar fechas personalizadas.
$tiDefFrom = $dateDefaultFrom ?? '';
$tiDefTo   = $dateDefaultTo ?? '';
$tiCustomDates = (($filters['from'] ?? '') !== $tiDefFrom) || (($filters['to'] ?? '') !== $tiDefTo);

function ti_q(array $extra, int $tenant, array $filters): string {
    $q = array_merge([
        'tenant' => $tenant,
        'type'   => $filters['type'] ?? '',
        'search' => $filters['search'] ?? '',
        'from'   => $filters['from'] ?? '',
        'to'     => $filters['to'] ?? '',
        'sort'   => $filters['sort'] ?? '',
    ], $extra);
    return http_build_query(array_filter($q, fn($v) => $v !== '' && $v !== null));
}
?>
<?php $tiActiveTab = 'indicators'; require VIEWS_PATH . '/partials/ti_header.php'; ?>

<div class="mb-4">
    <p class="text-xs text-gray-400"><?= number_format((int)($iocs['total'] ?? 0)) ?> IOCs · <?= count($types) ?> tipos</p>
</div>

<div class="mb-4 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950 px-4 py-2.5">
    <p class="text-xs text-amber-700 dark:text-amber-300">Se muestran los indicadores <strong>ingeridos</strong> (artículos + perfiles). El portal de Microsoft incluye además el <strong>feed global</strong> de indicadores, que la API de Graph no expone.</p>
</div>

<!-- Filtros -->
<form method="GET" class="mb-4 flex items-end gap-3 flex-wrap">
    <div>
        <label class="block text-xs text-gray-500 mb-1">Tenant</label>
        <select name="tenant" onchange="this.form.submit()" class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <?php foreach ($tenants as $t): ?>
                <option value="<?= $t['id'] ?>" <?= (int)$selectedTenant === (int)$t['id'] ? 'selected' : '' ?>><?= e($t['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </div>
    <div>
        <label class="block text-xs text-gray-500 mb-1">Tipo</label>
        <select name="type" class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <option value="">Todos los tipos</option>
            <?php foreach ($types as $ty): ?>
                <option value="<?= e($ty['ioc_type']) ?>" <?= ($filters['type'] ?? '') === $ty['ioc_type'] ? 'selected' : '' ?>><?= e($ty['ioc_type']) ?> (<?= (int)$ty['cnt'] ?>)</option>
            <?php endforeach; ?>
        </select>
    </div>
    <div>
        <label class="block text-xs text-gray-500 mb-1">Buscar</label>
        <input type="text" name="search" value="<?= e($filters['search'] ?? '') ?>" placeholder="Buscar valor…"
               class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none w-56">
    </div>
    <div>
        <label class="block text-xs text-gray-500 mb-1">Desde</label>
        <input type="date" name="from" value="<?= e($filters['from'] ?? '') ?>" title="Actividad desde"
               class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
    </div>
    <div>
        <label class="block text-xs text-gray-500 mb-1">Hasta</label>
        <input type="date" name="to" value="<?= e($filters['to'] ?? '') ?>" title="Actividad hasta"
               class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
    </div>
    <div>
        <label class="block text-xs text-gray-500 mb-1">Orden</label>
        <select name="sort" class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <option value="" <?= ($filters['sort'] ?? '') === '' ? 'selected' : '' ?>>Orden: última actividad</option>
            <option value="value" <?= ($filters['sort'] ?? '') === 'value' ? 'selected' : '' ?>>Orden: valor (A-Z)</option>
        </select>
    </div>
    <button type="submit" class="px-3 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">Filtrar</button>
    <?php if (($filters['type'] ?? '') !== '' || ($filters['search'] ?? '') !== '' || ($filters['sort'] ?? '') !== '' || $tiCustomDates): ?>
        <?php $tiClearQs = http_build_query(array_filter(['tenant' => (int)$selectedTenant, 'from' => $tiDefFrom, 'to' => $tiDefTo], fn($v) => $v !== '' && $v !== null)); ?>
        <a href="?<?= e($tiClearQs) ?>" class="text-xs text-gray-500 hover:underline">Limpiar</a>
    <?php endif; ?>
</form>

<?php
// Chips de filtros activos (con ×)
$chipBase = ['tenant' => $selectedTenant, 'type' => $filters['type'] ?? '', 'search' => $filters['search'] ?? '', 'from' => $filters['from'] ?? '', 'to' => $filters['to'] ?? '', 'sort' => $filters['sort'] ?? ''];
$chips = [];
if (($filters['search'] ?? '') !== '') { $chipBase['search'] = ''; $chips[] = ['Valor: ' . $filters['search'], $chipBase]; $chipBase['search'] = $filters['search']; }
if (($filters['type'] ?? '') !== '') { $c = $chipBase; $c['type'] = ''; $chips[] = ['Tipo: ' . $filters['type'], $c]; }
if (($filters['from'] ?? '') !== '' && ($filters['from'] ?? '') !== $tiDefFrom) { $c = $chipBase; $c['from'] = $tiDefFrom; $chips[] = ['Desde: ' . $filters['from'], $c]; }
if (($filters['to'] ?? '') !== '' && ($filters['to'] ?? '') !== $tiDefTo) { $c = $chipBase; $c['to'] = $tiDefTo; $chips[] = ['Hasta: ' . $filters['to'], $c]; }
?>
<?php if (!empty($chips)): ?>
<div class="mb-4 flex flex-wrap items-center gap-2">
    <?php foreach ($chips as $ch): ?>
        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full bg-brand-50 dark:bg-brand-950 text-brand-600 dark:text-brand-300">
            <?= e($ch[0]) ?>
            <a href="?<?= e(http_build_query(array_filter($ch[1], fn($v) => $v !== '' && $v !== null))) ?>" class="hover:text-red-500" title="Quitar">×</a>
        </span>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<!-- Exportar -->
<div class="mb-4 flex flex-wrap items-center gap-2">
    <span class="text-xs text-gray-500">Exportar (según filtros):</span>
    <button onclick="exportIocs('txt')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">TXT</button>
    <button onclick="exportIocs('csv')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">CSV</button>
    <button onclick="exportIocs('stix')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">STIX 2.1</button>
    <button onclick="exportIocs('misp')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">MISP</button>
    <span id="export-msg" class="text-xs text-gray-500"></span>
</div>

<!-- Análisis con IA (indicadores) -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-4">
    <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-semibold">Análisis con IA</h3>
        <?php if (Auth::isAdmin()): ?>
            <button type="button" onclick="scopeOpenEditor()" class="w-7 h-7 inline-flex items-center justify-center rounded-lg text-gray-400 hover:text-brand-500 hover:bg-gray-100 dark:hover:bg-gray-800 text-lg leading-none" title="Editar acciones">&#8942;</button>
        <?php endif; ?>
    </div>
    <?php if (empty($profiles)): ?>
        <p class="text-xs text-gray-400">No hay perfiles de IA configurados. Añádelos en <a href="<?= base_url('admin/apis') ?>" class="text-brand-500 hover:underline">Admin → APIs</a>.</p>
    <?php else: ?>
        <p class="text-xs text-gray-400 mb-2">Analiza los indicadores <strong>según los filtros actuales</strong> (máx. 200).</p>
        <select id="ia-profile" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none mb-3">
            <?php foreach ($profiles as $p): ?>
                <option value="<?= (int)$p['id'] ?>" <?= (int)($defaultProfileId ?? 0) === (int)$p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?><?= !empty($p['model']) ? ' · ' . e($p['model']) : '' ?></option>
            <?php endforeach; ?>
        </select>
        <div class="flex flex-wrap gap-2">
            <?php foreach (($actions ?? []) as $ac): ?>
                <button type="button" onclick="analyzeIndicatorsIA(<?= (int)$ac['id'] ?>)" class="inline-flex items-center px-3 py-1.5 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-xs font-medium rounded-lg transition-colors"><?= e($ac['label']) ?></button>
            <?php endforeach; ?>
        </div>
        <textarea id="ia-question" rows="2" placeholder="Pregunta libre (opcional)…" class="w-full mt-3 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
        <button type="button" onclick="analyzeIndicatorsIA(0)" class="w-full mt-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Preguntar</button>
        <div id="scope-result-actions" class="hidden items-center justify-end gap-2 mt-3">
            <button type="button" onclick="copyAnalysisScope()" class="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Copiar</button>
            <button type="button" onclick="downloadAnalysisScope()" class="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Descargar .md</button>
        </div>
        <div id="ia-result" class="hidden md-body mt-3 border-t border-gray-100 dark:border-gray-700 pt-3"></div>
    <?php endif; ?>
</div>

<!-- Tabla -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <?php if (empty($rows)): ?>
        <p class="px-5 py-8 text-sm text-gray-500 text-center">Sin IOCs para estos filtros.</p>
    <?php else: ?>
        <table class="w-full text-sm">
            <thead>
                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                    <th class="text-left px-4 py-2">Tipo</th>
                    <th class="text-left px-4 py-2">Valor</th>
                    <th class="text-left px-4 py-2">Severidad</th>
                    <th class="text-left px-4 py-2">First seen</th>
                    <th class="text-left px-4 py-2">Last seen</th>
                    <th class="text-left px-4 py-2">Descripción</th>
                    <th class="text-right px-4 py-2"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                <?php foreach ($rows as $ioc): ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <td class="px-4 py-2"><span class="font-mono text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-800"><?= e($ioc['ioc_type']) ?></span></td>
                        <td class="px-4 py-2 font-mono text-xs break-all" data-ioc="<?= e($ioc['ioc_value']) ?>"><?= e($ioc['ioc_value']) ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($ioc['severity'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($ioc['first_seen'] ? substr((string)$ioc['first_seen'], 0, 10) : '—') ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($ioc['last_seen'] ? substr((string)$ioc['last_seen'], 0, 10) : '—') ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500 max-w-xs truncate"><?= e($ioc['description'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-right">
                            <?php if (!empty($ioc['article_id'])): ?>
                                <a href="<?= base_url('modules/threat_intelligence/article/' . (int)$ioc['article_id']) ?>" class="text-xs text-brand-500 hover:underline">artículo</a>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<!-- Paginación -->
<?php if ($totalPages > 1): ?>
<div class="mt-4 flex items-center justify-center gap-2 text-sm">
    <?php if ($page > 1): ?>
        <a href="?<?= ti_q(['page' => $page - 1], $selectedTenant, $filters) ?>" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">« Anterior</a>
    <?php endif; ?>
    <span class="text-xs text-gray-500">Página <?= $page ?> de <?= $totalPages ?></span>
    <?php if ($page < $totalPages): ?>
        <a href="?<?= ti_q(['page' => $page + 1], $selectedTenant, $filters) ?>" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark">Siguiente »</a>
    <?php endif; ?>
</div>
<?php endif; ?>

<script>
function exportIocs(fmt) {
    var el = document.getElementById('export-msg');
    el.textContent = 'Generando…';
    api('POST', '<?= base_url('modules/export') ?>/' + fmt, {
        tenant_id: <?= (int)$selectedTenant ?>,
        filters: { type: '<?= e(addslashes($filters['type'] ?? '')) ?>', search: '<?= e(addslashes($filters['search'] ?? '')) ?>', from: '<?= e(addslashes($filters['from'] ?? '')) ?>', to: '<?= e(addslashes($filters['to'] ?? '')) ?>' }
    }).then(function(res) {
        if (res && res.success) { downloadFile(res.content, res.filename, res.mime); el.textContent = 'Exportado (' + (res.count || 0) + ')'; }
        else { el.textContent = 'Error al exportar'; }
    }).catch(function() { el.textContent = 'Error de conexión'; });
}

var SCOPE_REPORT = '';
function getIaProfile() { var s = document.getElementById('ia-profile'); return s ? parseInt(s.value, 10) : 0; }
function setScopeActions(show) { var el = document.getElementById('scope-result-actions'); if (!el) return; if (show) { el.classList.remove('hidden'); el.classList.add('flex'); } else { el.classList.add('hidden'); el.classList.remove('flex'); } }
function analyzeIndicatorsIA(actionId) {
    var q = document.getElementById('ia-question');
    var question = q ? q.value : '';
    if (actionId === 0 && !question.trim()) { toast('Escribe una pregunta', 'warning'); return; }
    var box = document.getElementById('ia-result');
    if (!box) return;
    box.classList.remove('hidden');
    setScopeActions(false);
    box.innerHTML = '<div class="spinner mx-auto"></div>';
    api('POST', '<?= base_url('modules/llm/analyze-indicators') ?>', {
        tenant_id: <?= (int)$selectedTenant ?>,
        type: '<?= e(addslashes($filters['type'] ?? '')) ?>',
        search: '<?= e(addslashes($filters['search'] ?? '')) ?>',
        action_id: actionId,
        question: question,
        profile_id: getIaProfile()
    }).then(function (res) {
        if (res.success) { SCOPE_REPORT = res.content || ''; box.innerHTML = res.content_html || esc(res.content); setScopeActions(SCOPE_REPORT.trim() !== ''); }
        else { box.innerHTML = '<p class="text-sm text-red-500">' + esc(res.error || 'Error') + '</p>'; toast('Error: ' + (res.error || ''), 'error'); }
    }).catch(function () { box.innerHTML = '<p class="text-sm text-red-500">Error de conexión</p>'; });
}
function copyAnalysisScope() { if (!SCOPE_REPORT) return; navigator.clipboard.writeText(SCOPE_REPORT).then(function () { toast('Copiado al portapapeles', 'success'); }).catch(function () { toast('No se pudo copiar', 'error'); }); }
function downloadAnalysisScope() { if (!SCOPE_REPORT) return; var d = new Date(); var s = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0'); downloadFile(SCOPE_REPORT, 'indicadores-<?= (int)$selectedTenant ?>-' + s + '.md', 'text/markdown'); }
function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }
</script>

<?php if (!empty($selectedTenant)) { require VIEWS_PATH . '/partials/ti_sync.php'; } ?>

<?php if (Auth::isAdmin()) { require VIEWS_PATH . '/partials/llm_actions_editor.php'; } ?>
