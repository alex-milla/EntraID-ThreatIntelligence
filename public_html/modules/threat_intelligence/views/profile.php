<?php
/**
 * Vista: detalle de un Intel Profile (threat actor / tool).
 */
$aliases  = safe_json_decode((string)($profile['aliases'] ?? ''), []);
$targets  = safe_json_decode((string)($profile['targets'] ?? ''), []);
$parsedTargets = ti_parse_targets(is_array($targets) ? $targets : []);
$subindustries = $parsedTargets['subindustries'] ?? [];
$countries = safe_json_decode((string)($profile['countries'] ?? ''), []);
$industries = safe_json_decode((string)($profile['industries'] ?? ''), []);
$regions    = safe_json_decode((string)($profile['regions'] ?? ''), []);
$summaryHtml    = render_markdown((string)($profile['summary'] ?? ''));
$descHtml       = render_markdown((string)($profile['description'] ?? ''));
$tradecraftHtml = render_markdown((string)($profile['tradecraft'] ?? ''));

$countryLabel = function ($c) {
    if (is_array($c)) {
        return (string)($c['countryOrRegion'] ?? $c['name'] ?? json_encode($c));
    }
    return (string)$c;
};
?>
<div class="mb-6">
    <a href="<?= base_url('modules/threat_intelligence/profiles?tenant=' . (int)$profile['tenant_id'] . '&kind=' . urlencode((string)($profile['kind'] ?? ''))) ?>" class="text-xs text-brand-500 hover:underline">← Volver a perfiles</a>
    <div class="flex items-start justify-between gap-3 mt-3 flex-wrap">
        <div class="min-w-0">
            <h2 class="text-xl font-bold"><?= e($profile['title']) ?></h2>
            <p class="text-xs text-gray-400 mt-1">
                <?= e(ucfirst((string)($profile['kind'] ?? ''))) ?>
                <?php if (!empty($profile['first_active'])): ?> · Primera actividad: <?= e(substr((string)$profile['first_active'], 0, 10)) ?><?php endif; ?>
                <?php if ($tenant): ?> · <?= e($tenant['name']) ?><?php endif; ?>
            </p>
        </div>
        <?php if (($profile['kind'] ?? '') === 'actor'): ?>
            <span class="inline-flex px-3 py-1 text-xs rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300">threat actor</span>
        <?php else: ?>
            <span class="inline-flex px-3 py-1 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300"><?= e((string)($profile['kind'] ?? 'tool')) ?></span>
        <?php endif; ?>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <div class="lg:col-span-2 space-y-6">
        <?php if (is_array($aliases) && $aliases): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <h3 class="text-sm font-semibold mb-2">Alias</h3>
                <div class="flex flex-wrap gap-1.5">
                    <?php foreach ($aliases as $a): ?><span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300"><?= e($a) ?></span><?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ((is_array($industries) && $industries) || (is_array($regions) && $regions)): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <h3 class="text-sm font-semibold mb-2">Targeted industries / regions</h3>
                <?php if (is_array($industries) && $industries): ?>
                    <div class="flex flex-wrap gap-1.5 mb-2">
                        <?php foreach ($industries as $ind): ?><span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-brand-50 dark:bg-brand-950 text-brand-600 dark:text-brand-300"><?= e((string)$ind) ?></span><?php endforeach; ?>
                    </div>
                <?php endif; ?>
                <?php if (is_array($regions) && $regions): ?>
                    <div class="flex flex-wrap gap-1.5">
                        <?php foreach ($regions as $rg): ?><span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300"><?= e((string)$rg) ?></span><?php endforeach; ?>
                    </div>
                <?php endif; ?>
                <?php if (is_array($subindustries) && $subindustries): ?>
                    <div class="mt-3">
                        <p class="text-[11px] text-gray-400 mb-1">Subsectores</p>
                        <div class="flex flex-wrap gap-1.5">
                            <?php foreach ($subindustries as $sub): ?><span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400 border border-gray-200 dark:border-gray-700"><?= e((string)$sub) ?></span><?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if (is_array($targets) && $targets || (is_array($countries) && $countries)): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <h3 class="text-sm font-semibold mb-2">Objetivos / origen</h3>
                <?php if (is_array($targets) && $targets): ?>
                    <p class="text-sm text-gray-600 dark:text-gray-300"><strong class="font-medium">Objetivos:</strong> <?= e(implode(', ', array_map('strval', array_slice($targets, 0, 20)))) ?></p>
                <?php endif; ?>
                <?php if (is_array($countries) && $countries): ?>
                    <p class="text-sm text-gray-600 dark:text-gray-300 mt-1"><strong class="font-medium">Origen:</strong> <?= e(implode(', ', array_map($countryLabel, array_slice($countries, 0, 20)))) ?></p>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($summaryHtml !== ''): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 md-body"><?= $summaryHtml ?></div>
        <?php endif; ?>

        <?php if ($descHtml !== ''): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <details open>
                    <summary class="text-sm font-semibold cursor-pointer select-none">Descripción</summary>
                    <div class="md-body mt-4"><?= $descHtml ?></div>
                </details>
            </div>
        <?php endif; ?>

        <?php if ($tradecraftHtml !== ''): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <details>
                    <summary class="text-sm font-semibold cursor-pointer select-none">Tradecraft (TTP)</summary>
                    <div class="md-body mt-4"><?= $tradecraftHtml ?></div>
                </details>
            </div>
        <?php endif; ?>
    </div>

    <div class="lg:col-span-1">
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-6">
            <div class="flex items-center justify-between mb-3">
                <h3 class="text-sm font-semibold">Análisis con IA</h3>
                <?php if (Auth::isAdmin()): ?>
                    <button type="button" onclick="scopeOpenEditor()" class="w-7 h-7 inline-flex items-center justify-center rounded-lg text-gray-400 hover:text-brand-500 hover:bg-gray-100 dark:hover:bg-gray-800 text-lg leading-none" title="Editar acciones">&#8942;</button>
                <?php endif; ?>
            </div>
            <?php if (empty($profiles)): ?>
                <p class="text-xs text-gray-400">No hay perfiles de IA configurados. Añádelos en <a href="<?= base_url('admin/apis') ?>" class="text-brand-500 hover:underline">Admin → APIs</a>.</p>
            <?php else: ?>
                <select id="ia-profile" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none mb-3">
                    <?php foreach ($profiles as $p): ?>
                        <option value="<?= (int)$p['id'] ?>" <?= (int)($defaultProfileId ?? 0) === (int)$p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?><?= !empty($p['model']) ? ' · ' . e($p['model']) : '' ?></option>
                    <?php endforeach; ?>
                </select>
                <div class="flex flex-wrap gap-2">
                    <?php foreach (($actions ?? []) as $ac): ?>
                        <button type="button" onclick="analyzeProfileIA(<?= (int)$ac['id'] ?>)" class="inline-flex items-center px-3 py-1.5 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-xs font-medium rounded-lg transition-colors"><?= e($ac['label']) ?></button>
                    <?php endforeach; ?>
                </div>
                <textarea id="ia-question" rows="2" placeholder="Pregunta libre (opcional)…" class="w-full mt-3 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
                <button type="button" onclick="analyzeProfileIA(0)" class="w-full mt-2 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Preguntar</button>
                <div id="scope-result-actions" class="hidden items-center justify-end gap-2 mt-3">
                    <button type="button" onclick="copyAnalysisScope()" class="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Copiar</button>
                    <button type="button" onclick="downloadAnalysisScope()" class="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Descargar .md</button>
                </div>
                <div id="ia-result" class="hidden md-body mt-3 border-t border-gray-100 dark:border-gray-700 pt-3"></div>
            <?php endif; ?>
        </div>

        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <h2 class="text-sm font-semibold">Indicadores (<?= count($indicators) ?>)</h2>
                <?php if (!empty($indicators)): ?>
                    <button onclick="copyProfileIocs()" class="text-xs text-brand-500 hover:underline">Copiar todos</button>
                <?php endif; ?>
            </div>
            <?php if (empty($indicators)): ?>
                <p class="px-4 py-6 text-sm text-gray-500 text-center">Sin indicadores sincronizados. Pulsa «Sincronizar indicadores» en la lista de perfiles.</p>
            <?php else: ?>
                <div class="divide-y divide-gray-100 dark:divide-gray-700/50 max-h-[70vh] overflow-y-auto">
                    <?php foreach ($indicators as $ioc): ?>
                        <div class="px-4 py-2.5">
                            <div class="flex items-center justify-between gap-2">
                                <span class="font-mono text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-500"><?= e($ioc['ioc_type']) ?></span>
                            </div>
                            <p class="font-mono text-xs break-all mt-1" data-ioc="<?= e($ioc['ioc_value']) ?>"><?= e($ioc['ioc_value']) ?></p>
                            <?php if (!empty($ioc['first_seen']) || !empty($ioc['last_seen'])): ?>
                                <p class="text-[11px] text-gray-400 mt-0.5"><?= e((string)$ioc['first_seen']) ?><?= $ioc['first_seen'] && $ioc['last_seen'] ? ' → ' . e((string)$ioc['last_seen']) : '' ?></p>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
function copyProfileIocs() {
    var vals = Array.prototype.map.call(document.querySelectorAll('[data-ioc]'), function (el) { return el.getAttribute('data-ioc'); });
    navigator.clipboard.writeText(vals.join('\n')).then(function () { toast('Copiados ' + vals.length + ' indicadores', 'success'); })
        .catch(function () { toast('No se pudo copiar', 'error'); });
}

var SCOPE_REPORT = '';
function getIaProfile() { var s = document.getElementById('ia-profile'); return s ? parseInt(s.value, 10) : 0; }
function setScopeActions(show) { var el = document.getElementById('scope-result-actions'); if (!el) return; if (show) { el.classList.remove('hidden'); el.classList.add('flex'); } else { el.classList.add('hidden'); el.classList.remove('flex'); } }
function analyzeProfileIA(actionId) {
    var q = document.getElementById('ia-question');
    var question = q ? q.value : '';
    if (actionId === 0 && !question.trim()) { toast('Escribe una pregunta', 'warning'); return; }
    var box = document.getElementById('ia-result');
    if (!box) return;
    box.classList.remove('hidden');
    setScopeActions(false);
    box.innerHTML = '<div class="spinner mx-auto"></div>';
    api('POST', '<?= base_url('modules/llm/analyze-profile') ?>/<?= (int)$profile['id'] ?>', { action_id: actionId, question: question, profile_id: getIaProfile() })
        .then(function (res) {
            if (res.success) { SCOPE_REPORT = res.content || ''; box.innerHTML = res.content_html || esc(res.content); setScopeActions(SCOPE_REPORT.trim() !== ''); }
            else { box.innerHTML = '<p class="text-sm text-red-500">' + esc(res.error || 'Error') + '</p>'; toast('Error: ' + (res.error || ''), 'error'); }
        })
        .catch(function () { box.innerHTML = '<p class="text-sm text-red-500">Error de conexión</p>'; });
}
function copyAnalysisScope() { if (!SCOPE_REPORT) return; navigator.clipboard.writeText(SCOPE_REPORT).then(function () { toast('Copiado al portapapeles', 'success'); }).catch(function () { toast('No se pudo copiar', 'error'); }); }
function downloadAnalysisScope() { if (!SCOPE_REPORT) return; var d = new Date(); var s = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0'); downloadFile(SCOPE_REPORT, 'perfil-<?= (int)$profile['id'] ?>-' + s + '.md', 'text/markdown'); }
function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }
</script>

<?php if (Auth::isAdmin()) { require VIEWS_PATH . '/partials/llm_actions_editor.php'; } ?>
