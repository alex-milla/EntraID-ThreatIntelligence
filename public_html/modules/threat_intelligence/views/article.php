<?php
/**
 * Vista: detalle de un artículo de Threat Intelligence.
 * Variables: $module, $article, $iocs, $tenant
 */
$tags = safe_json_decode($article['tags'] ?? '[]', []);
$summaryHtml = render_markdown((string)($article['summary'] ?? ''));
$bodyHtml    = render_markdown((string)($article['body'] ?? ''));
?>
<div class="mb-5">
    <a href="<?= base_url('modules/threat_intelligence') ?>" class="text-xs text-brand-500 hover:underline">← Volver</a>
    <h1 class="text-xl font-semibold mt-2"><?= e($article['title']) ?></h1>
    <p class="text-xs text-gray-400 mt-1">
        <?= e($tenant['name'] ?? '') ?> ·
        <?= format_date($article['last_updated'] ?? $article['created_date']) ?>
        · <?= time_ago($article['fetched_at']) ?>
    </p>
    <?php if (!empty($tags) && is_array($tags)): ?>
        <div class="flex flex-wrap gap-1 mt-2">
            <?php foreach ($tags as $tag): ?>
                <?php $tval = is_array($tag) ? ($tag['value'] ?? $tag['name'] ?? '') : $tag; ?>
                <?php if ($tval !== ''): ?><span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300"><?= e((string)$tval) ?></span><?php endif; ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<!-- Navegación anterior / siguiente -->
<?php
$navQs = 'tenant=' . (int)$article['tenant_id']
    . '&from=' . urlencode($dateFrom ?? '')
    . '&to=' . urlencode($dateTo ?? '')
    . '&q=' . urlencode($q ?? '')
    . '&tag=' . urlencode($tag ?? '')
    . '&sector=' . urlencode($sector ?? '');
?>
<div class="mb-4 flex items-center justify-between">
    <?php if (!empty($prevId)): ?>
        <a href="<?= base_url('modules/threat_intelligence/article/' . (int)$prevId . '?' . $navQs) ?>" class="text-sm text-brand-500 hover:underline">← Anterior</a>
    <?php else: ?><span></span><?php endif; ?>
    <?php if (!empty($nextId)): ?>
        <a href="<?= base_url('modules/threat_intelligence/article/' . (int)$nextId . '?' . $navQs) ?>" class="text-sm text-brand-500 hover:underline">Siguiente →</a>
    <?php else: ?><span></span><?php endif; ?>
</div>

<!-- Acciones -->
<div class="mb-6 flex flex-wrap items-center gap-2">
    <span class="text-xs text-gray-500 mr-1">Exportar IOCs del artículo:</span>
    <button onclick="exportArticle('txt')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">TXT</button>
    <button onclick="exportArticle('csv')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">CSV</button>
    <button onclick="exportArticle('stix')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">STIX 2.1</button>
    <button onclick="exportArticle('misp')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">MISP</button>
    <span id="export-msg" class="text-xs text-gray-500"></span>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Columna izquierda: contenido del artículo -->
    <div class="lg:col-span-2 space-y-6">
        <?php if ($summaryHtml !== ''): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 md-body">
                <?= $summaryHtml ?>
            </div>
        <?php endif; ?>

        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
            <details>
                <summary class="text-sm font-semibold cursor-pointer select-none">Cuerpo del artículo</summary>
                <?php if ($bodyHtml !== ''): ?>
                    <div class="md-body mt-4"><?= $bodyHtml ?></div>
                <?php else: ?>
                    <p class="mt-3 text-sm text-gray-500">(sin cuerpo)</p>
                <?php endif; ?>
            </details>
        </div>
    </div>

    <!-- Columna derecha: IOCs + IA -->
    <div class="lg:col-span-1 space-y-6">
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between gap-2">
                <h2 class="text-sm font-semibold">IOCs (<?= count($iocs) ?>)</h2>
                <?php if (!empty($iocs)): ?>
                    <div class="flex items-center gap-3">
                        <label class="inline-flex items-center gap-1 text-[11px] text-gray-500 cursor-pointer" title="Ofusca IP y dominio con [.] para informes">
                            <input type="checkbox" onchange="toggleIocDefang(this)" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500"> [.] seguro
                        </label>
                        <button onclick="copyAll()" class="text-xs text-brand-500 hover:underline">Copiar todos</button>
                    </div>
                <?php endif; ?>
            </div>
            <?php if (empty($iocs)): ?>
                <p class="px-4 py-6 text-sm text-gray-500 text-center">Este artículo no tiene IOCs.</p>
            <?php else: ?>
                <div class="divide-y divide-gray-100 dark:divide-gray-700/50">
                    <?php foreach ($iocs as $ioc): ?>
                        <div class="px-4 py-2.5">
                            <div class="flex items-center justify-between gap-2">
                                <span class="font-mono text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-500"><?= e($ioc['ioc_type']) ?></span>
                                <button onclick="copyIoc(this)" class="text-[11px] text-gray-400 hover:text-brand-500" title="Copiar">copiar</button>
                            </div>
                            <p class="font-mono text-xs break-all mt-1" data-ioc="<?= e($ioc['ioc_value']) ?>" data-ioc-defang="<?= e(defang_ioc((string)$ioc['ioc_value'], (string)$ioc['ioc_type'])) ?>"><?= e($ioc['ioc_value']) ?></p>
                            <?php if (!empty($ioc['severity']) || !empty($ioc['source'])): ?>
                                <p class="text-[11px] text-gray-400 mt-0.5">
                                    <?php if (!empty($ioc['severity'])): ?><?= e($ioc['severity']) ?><?php endif; ?>
                                    <?php if (!empty($ioc['severity']) && !empty($ioc['source'])): ?> · <?php endif; ?>
                                    <?php if (!empty($ioc['source'])): ?><?= e($ioc['source']) ?><?php endif; ?>
                                </p>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <div id="ai-panel" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
            <div class="flex items-center justify-between mb-3">
                <h2 class="text-sm font-semibold">Análisis con IA</h2>
                <div class="flex items-center gap-2">
                    <?php if (Auth::isAdmin()): ?>
                        <button type="button" onclick="scopeOpenEditor()" class="w-7 h-7 inline-flex items-center justify-center rounded-lg text-gray-400 hover:text-brand-500 hover:bg-gray-100 dark:hover:bg-gray-800 text-lg leading-none" title="Editar acciones">&#8942;</button>
                    <?php endif; ?>
                    <div id="art-result-actions" class="hidden items-center gap-2">
                        <button type="button" onclick="copyArtAnalysis()" class="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Copiar</button>
                        <button type="button" onclick="downloadArtAnalysis()" class="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">Descargar .md</button>
                    </div>
                </div>
            </div>
            <?php if (empty($profiles)): ?>
                <p class="text-xs text-gray-400">No hay perfiles de IA configurados. Añádelos en <a href="<?= base_url('admin/apis') ?>" class="text-brand-500 hover:underline">Admin → APIs</a>.</p>
            <?php else: ?>
                <select id="ia-profile" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none mb-3">
                    <?php foreach ($profiles as $p): ?>
                        <option value="<?= (int)$p['id'] ?>" <?= (int)($defaultProfileId ?? 0) === (int)$p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?><?= !empty($p['model']) ? ' · ' . e($p['model']) : '' ?></option>
                    <?php endforeach; ?>
                </select>
                <?php if (!empty($actions)): ?>
                    <div class="flex flex-wrap gap-2">
                        <?php foreach ($actions as $ac): ?>
                            <button type="button" onclick="analyzeArticleIA(<?= (int)$ac['id'] ?>)" class="inline-flex items-center px-3 py-1.5 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-xs font-medium rounded-lg transition-colors"><?= e($ac['label']) ?></button>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                <label class="inline-flex items-center gap-2 text-xs text-gray-500 mt-3 cursor-pointer" title="Ofusca IP y dominio con [.] en el informe generado">
                    <input type="checkbox" id="ia-defang" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500"> Defang [.] en el informe
                </label>
                <textarea id="ia-question" rows="2" placeholder="Pregunta libre (opcional)…" class="w-full mt-3 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
                <div class="flex items-center gap-2 mt-2">
                    <button type="button" onclick="analyzeArticleIA(0)" class="flex-1 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Preguntar</button>
                    <button type="button" onclick="analyzeAI()" class="px-3 py-2 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-muted-dark text-xs font-medium rounded-lg transition-colors" title="Extrae los IOCs del artículo en tabla estructurada">Extraer IOCs</button>
                </div>
                <div id="ai-result" class="hidden md-body mt-3 border-t border-gray-100 dark:border-gray-700 pt-3"></div>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }

function getAiProfile() { var s = document.getElementById('ai-profile'); return s ? parseInt(s.value, 10) : 0; }

var ART_RAW = '';
function setArtActions(show) {
    var el = document.getElementById('art-result-actions');
    if (!el) return;
    if (show) { el.classList.remove('hidden'); el.classList.add('flex'); }
    else { el.classList.add('hidden'); el.classList.remove('flex'); }
}
function copyArtAnalysis() {
    if (!ART_RAW) return;
    navigator.clipboard.writeText(ART_RAW).then(function () { toast('Copiado al portapapeles', 'success'); })
        .catch(function () { toast('No se pudo copiar', 'error'); });
}
function downloadArtAnalysis() {
    if (!ART_RAW) return;
    var d = new Date();
    var stamp = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
    downloadFile(ART_RAW, 'articulo-<?= (int)$article['id'] ?>-' + stamp + '.md', 'text/markdown');
}

function exportArticle(fmt) {
    var el = document.getElementById('export-msg');
    el.textContent = 'Generando…';
    api('POST', '<?= base_url('modules/export') ?>/' + fmt, {
        tenant_id: <?= (int)$article['tenant_id'] ?>,
        filters: { article_id: <?= (int)$article['id'] ?> }
    }).then(function(res) {
        if (res && res.success) { downloadFile(res.content, res.filename, res.mime); el.textContent = 'Exportado (' + (res.count || 0) + ')'; }
        else { el.textContent = 'Error al exportar'; }
    }).catch(function() { el.textContent = 'Error de conexión'; });
}

/* ---- Defang de IOCs ([.] seguro para informes) ---- */
var IOC_DEFANG = false;
function applyIocDefang() {
    document.querySelectorAll('[data-ioc]').forEach(function (el) {
        var v = IOC_DEFANG ? el.getAttribute('data-ioc-defang') : el.getAttribute('data-ioc');
        el.textContent = (v == null) ? '' : v;
    });
}
function toggleIocDefang(cb) { IOC_DEFANG = !!(cb && cb.checked); applyIocDefang(); }

function copyIoc(btn) {
    var el = btn.closest('div').parentElement.querySelector('[data-ioc]');
    if (!el) return;
    var val = IOC_DEFANG ? el.getAttribute('data-ioc-defang') : el.getAttribute('data-ioc');
    navigator.clipboard.writeText(val).then(function(){ btn.textContent = 'copiado'; setTimeout(function(){ btn.textContent = 'copiar'; }, 1200); });
}

function copyAll() {
    var vals = Array.prototype.map.call(document.querySelectorAll('[data-ioc]'), function(el) {
        return IOC_DEFANG ? el.getAttribute('data-ioc-defang') : el.getAttribute('data-ioc');
    });
    navigator.clipboard.writeText(vals.join('\n')).then(function(){ toast('Copiados ' + vals.length + ' IOCs', 'success'); });
}

/* ---- Análisis con IA por acciones (ámbito Artículos) ---- */
function analyzeArticleIA(actionId) {
    var q = document.getElementById('ia-question');
    var question = q ? q.value : '';
    if (actionId === 0 && !question.trim()) { toast('Escribe una pregunta', 'warning'); return; }
    var box = document.getElementById('ai-result');
    if (!box) return;
    box.classList.remove('hidden');
    setArtActions(false);
    box.innerHTML = '<div class="spinner mx-auto"></div>';
    var df = document.getElementById('ia-defang');
    api('POST', '<?= base_url('modules/llm/analyze-article') ?>/<?= (int)$article['id'] ?>', {
        action_id: actionId,
        question: question,
        profile_id: getAiProfile(),
        defang: (df && df.checked) ? 1 : 0
    }).then(function (res) {
        if (res.success) { ART_RAW = res.content || ''; box.innerHTML = res.content_html || esc(res.content); setArtActions(ART_RAW.trim() !== ''); }
        else { box.innerHTML = '<p class="text-sm text-red-500">' + esc(res.error || 'Error') + '</p>'; toast('Error: ' + (res.error || ''), 'error'); }
    }).catch(function () { box.innerHTML = '<p class="text-sm text-red-500">Error de conexión</p>'; });
}

/* ---- Extracción estructurada de IOCs (JSON) ---- */
function analyzeAI() {
    var box = document.getElementById('ai-result');
    if (!box) return;
    box.classList.remove('hidden');
    setArtActions(false);
    box.innerHTML = '<div class="spinner mx-auto"></div>';
    api('POST', '<?= base_url('modules/llm/extract-iocs') ?>', { article_id: <?= (int)$article['id'] ?>, profile_id: getAiProfile() })
        .then(function(res) {
            if (!res.success) { box.innerHTML = '<p class="text-sm text-red-500">' + esc(res.error || 'Error') + '</p>'; return; }
            ART_RAW = res.content || '';
            setArtActions(ART_RAW.trim() !== '');
            var p = res.parsed;
            if (!p) { box.innerHTML = '<div class="md-body">' + (res.content_html || esc(res.content || '')) + '</div>'; return; }
            var html = '<p class="whitespace-pre-wrap">' + esc(p.resumen || '') + '</p>';
            if (p.iocs && p.iocs.length) {
                html += '<table class="mt-3 w-full text-xs"><thead><tr class="text-gray-500 uppercase"><th class="text-left py-1">Tipo</th><th class="text-left py-1">Valor</th></tr></thead><tbody>';
                p.iocs.forEach(function(i) { html += '<tr><td class="py-1 pr-3 font-mono">' + esc(i.tipo || '') + '</td><td class="py-1 font-mono break-all">' + esc(i.valor || '') + '</td></tr>'; });
                html += '</tbody></table>';
            }
            if (p.recomendaciones) { html += '<p class="mt-3 text-gray-500">' + esc(p.recomendaciones) + '</p>'; }
            box.innerHTML = html;
        })
        .catch(function() { box.innerHTML = '<p class="text-sm text-red-500">Error de conexión</p>'; });
}
</script>

<?php if (Auth::isAdmin()) { require VIEWS_PATH . '/partials/llm_actions_editor.php'; } ?>
