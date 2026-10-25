<?php
/**
 * Vista: detalle de un artículo de Threat Intelligence.
 * Variables: $module, $article, $iocs, $tenant, $articleState, $hasTranslation, $translationHtml
 */
$tags = safe_json_decode($article['tags'] ?? '[]', []);
$summaryHtml = render_markdown((string)($article['summary'] ?? ''));
$bodyHtml    = render_markdown((string)($article['body'] ?? ''));

$unread  = empty($articleState['is_read']);
$fav     = !empty($articleState['is_favorite']);
$created = $article['created_date'] ?? null;
$updated = $article['last_updated'] ?? null;
$showUpdated = $created && $updated && substr((string)$updated, 0, 19) !== substr((string)$created, 0, 19);
$isNew24 = $created && (strtotime((string)$created) !== false) && (strtotime((string)$created) >= time() - 86400);
?>
<div class="mb-5">
    <a href="<?= base_url('modules/threat_intelligence') ?>" class="text-xs text-brand-500 hover:underline">← Volver</a>
    <div class="flex items-center gap-2 mt-2">
        <span id="art-new" class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide bg-brand-500 text-white <?= $unread ? '' : 'hidden' ?>">New</span>
        <?php if ($isNew24): ?><span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-warning-bg text-warning" title="Publicado en las últimas 24 h">24 h</span><?php endif; ?>
        <h1 class="text-xl font-semibold"><?= e($article['title']) ?></h1>
    </div>
    <p class="text-xs text-ink-soft mt-1">
        <?= e($tenant['name'] ?? '') ?> ·
        Publicado el <?= format_date($created ?: $updated) ?>
        <?php if ($showUpdated): ?> · actualizado el <?= format_date($updated) ?><?php endif; ?>
    </p>
    <?php if (!empty($tags) && is_array($tags)): ?>
        <div class="flex flex-wrap gap-1 mt-2">
            <?php foreach ($tags as $tag): ?>
                <?php $tval = is_array($tag) ? ($tag['value'] ?? $tag['name'] ?? '') : $tag; ?>
                <?php if ($tval !== ''): ?><span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-muted text-ink-muted"><?= e((string)$tval) ?></span><?php endif; ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<!-- Estado de triaje: leído / favorito -->
<div class="mb-4 flex flex-wrap items-center gap-2">
    <button type="button" id="btn-read" onclick="tiReadToggle()"
            class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
        <i class="material-icons icon-16" aria-hidden="true">check</i>
        <span id="btn-read-label"><?= $unread ? 'Confirmar como leído' : 'Dejar sin leer' ?></span>
    </button>
    <button type="button" id="btn-fav" onclick="tiFavToggle()"
            class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors <?= $fav ? 'text-amber-500' : '' ?>">
        <span id="btn-fav-label"><?= $fav ? '★ Favorito' : '☆ Añadir a favoritos' ?></span>
    </button>
    <span id="state-msg" class="text-xs text-ink-soft"></span>
</div>

<!-- Navegación anterior / siguiente -->
<?php
$navQs = 'tenant=' . (int)$article['tenant_id']
    . '&from=' . urlencode($dateFrom ?? '')
    . '&to=' . urlencode($dateTo ?? '')
    . '&q=' . urlencode($q ?? '')
    . '&tag=' . urlencode($tag ?? '')
    . '&sector=' . urlencode($sector ?? '');
if (!empty($_GET['only_unread']))    { $navQs .= '&only_unread=1'; }
if (!empty($_GET['only_favorites'])) { $navQs .= '&only_favorites=1'; }
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
    <span class="text-xs text-ink-muted mr-1">Exportar IOCs del artículo:</span>
    <button onclick="exportArticle('txt')" class="px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">TXT</button>
    <button onclick="exportArticle('csv')" class="px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">CSV</button>
    <button onclick="exportArticle('stix')" class="px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">STIX 2.1</button>
    <button onclick="exportArticle('misp')" class="px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">MISP</button>
    <span id="export-msg" class="text-xs text-ink-muted"></span>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Columna izquierda: contenido del artículo -->
    <div class="lg:col-span-2 space-y-6">
        <?php if ($summaryHtml !== ''): ?>
            <div class="card p-5 md-body">
                <?= $summaryHtml ?>
            </div>
        <?php endif; ?>

        <div class="card p-5">
            <details>
                <summary class="text-sm font-semibold cursor-pointer select-none">Cuerpo del artículo</summary>
                <?php if ($bodyHtml !== ''): ?>
                    <div class="md-body mt-4"><?= $bodyHtml ?></div>
                <?php else: ?>
                    <p class="mt-3 text-sm text-ink-muted">(sin cuerpo)</p>
                <?php endif; ?>
            </details>
        </div>

        <!-- Traducción IA al español -->
        <div class="card p-5">
            <div class="flex items-center justify-between gap-3">
                <h2 class="text-sm font-semibold">Traducción al español (IA)</h2>
                <div class="flex items-center gap-2">
                    <button type="button" id="btn-translate" onclick="tiTranslate()"
                            class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">
                        <?= $hasTranslation ? 'Ver traducción' : 'Traducir al español' ?>
                    </button>
                    <button type="button" id="btn-translation-hide" onclick="tiTranslationHide()"
                            class="hidden px-3 py-1.5 border border-line text-xs font-medium rounded-lg hover:bg-muted transition-colors">Ver original</button>
                </div>
            </div>
            <div id="translation-body" class="md-body mt-3 <?= $hasTranslation ? '' : 'hidden' ?>"><?= $translationHtml ?? '' ?></div>
            <p id="translation-msg" class="text-xs text-ink-soft mt-2"><?= $hasTranslation ? 'Traducción guardada (se reutiliza hasta que cambie el artículo o pasen 90 días).' : '' ?></p>
        </div>
    </div>

    <!-- Columna derecha: IA + IOCs (IA primero para no tener que bajar) -->
    <div class="lg:col-span-1 flex flex-col gap-6">
        <div class="card overflow-hidden order-2">
            <div class="px-4 py-3 border-b border-line flex items-center justify-between gap-2">
                <h2 class="text-sm font-semibold">IOCs (<?= count($iocs) ?>)</h2>
                <?php if (!empty($iocs)): ?>
                    <div class="flex items-center gap-3">
                        <label class="inline-flex items-center gap-1 text-[11px] text-ink-muted cursor-pointer" title="Ofusca IP y dominio con [.] para informes">
                            <input type="checkbox" onchange="toggleIocDefang(this)" class="rounded border-line-strong text-brand-500 focus:ring-brand-500"> [.] seguro
                        </label>
                        <button onclick="copyAll()" class="text-xs text-brand-500 hover:underline">Copiar todos</button>
                    </div>
                <?php endif; ?>
            </div>
            <?php if (empty($iocs)): ?>
                <p class="px-4 py-6 text-sm text-ink-muted text-center">Este artículo no tiene IOCs.</p>
            <?php else: ?>
                <div class="divide-y divide-line-subtle max-h-[70vh] overflow-y-auto">
                    <?php foreach ($iocs as $ioc): ?>
                        <div class="px-4 py-2.5">
                            <div class="flex items-center justify-between gap-2">
                                <span class="font-mono text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-muted text-ink-muted"><?= e($ioc['ioc_type']) ?></span>
                                <button onclick="copyIoc(this)" class="text-[11px] text-ink-soft hover:text-brand-500" title="Copiar">copiar</button>
                            </div>
                            <p class="font-mono text-xs break-all mt-1" data-ioc="<?= e($ioc['ioc_value']) ?>" data-ioc-defang="<?= e(defang_ioc((string)$ioc['ioc_value'], (string)$ioc['ioc_type'])) ?>"><?= e($ioc['ioc_value']) ?></p>
                            <?php if (!empty($ioc['severity']) || !empty($ioc['source'])): ?>
                                <p class="text-[11px] text-ink-soft mt-0.5">
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

        <div id="ai-panel" class="card p-5 order-1">
            <div class="flex items-center justify-between mb-3">
                <h2 class="text-sm font-semibold">Análisis con IA</h2>
                <div class="flex items-center gap-2">
                    <?php if (Auth::isAdmin()): ?>
                        <button type="button" onclick="scopeOpenEditor()" class="w-7 h-7 inline-flex items-center justify-center rounded-lg text-ink-soft hover:text-brand-500 hover:bg-muted text-lg leading-none" title="Editar acciones">&#8942;</button>
                    <?php endif; ?>
                    <div id="art-result-actions" class="hidden items-center gap-2">
                        <button type="button" onclick="copyArtAnalysis()" class="btn btn-small btn-outline">Copiar</button>
                        <button type="button" onclick="downloadArtAnalysis()" class="btn btn-small btn-outline">Descargar .md</button>
                    </div>
                </div>
            </div>
            <?php if (empty($profiles)): ?>
                <p class="text-xs text-ink-soft">No hay perfiles de IA configurados. Añádelos en <a href="<?= base_url('admin/apis') ?>" class="text-brand-500 hover:underline">Admin → APIs</a>.</p>
            <?php else: ?>
                <select id="ia-profile" class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-sm focus:ring-2 focus:ring-brand-500 outline-none mb-3">
                    <?php foreach ($profiles as $p): ?>
                        <option value="<?= (int)$p['id'] ?>" <?= (int)($defaultProfileId ?? 0) === (int)$p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?><?= !empty($p['model']) ? ' · ' . e($p['model']) : '' ?></option>
                    <?php endforeach; ?>
                </select>
                <?php if (!empty($actions)): ?>
                    <div class="flex flex-wrap gap-2">
                        <?php foreach ($actions as $ac): ?>
                            <button type="button" onclick="analyzeArticleIA(<?= (int)$ac['id'] ?>)" class="btn btn-small btn-outline"><?= e($ac['label']) ?></button>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                <label class="inline-flex items-center gap-2 text-xs text-ink-muted mt-3 cursor-pointer" title="Ofusca IP y dominio con [.] en el informe generado">
                    <input type="checkbox" id="ia-defang" class="rounded border-line-strong text-brand-500 focus:ring-brand-500"> Defang [.] en el informe
                </label>
                <textarea id="ia-question" rows="2" placeholder="Pregunta libre (opcional)…" class="w-full mt-3 px-3 py-2 rounded-lg border border-line-strong bg-input text-sm focus:ring-2 focus:ring-brand-500 outline-none"></textarea>
                <div class="flex items-center gap-2 mt-2">
                    <button type="button" onclick="analyzeArticleIA(0)" class="flex-1 btn">Preguntar</button>
                    <button type="button" onclick="analyzeAI()" class="px-3 py-2 border border-line hover:bg-muted text-xs font-medium rounded-lg transition-colors" title="Extrae los IOCs del artículo en tabla estructurada">Extraer IOCs</button>
                </div>
                <div id="ai-result" class="hidden md-body mt-3 border-t border-line-subtle pt-3"></div>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }

function getAiProfile() { var s = document.getElementById('ai-profile'); return s ? parseInt(s.value, 10) : 0; }

/* ---- Estado de triaje: leído / favorito ---- */
var ART_READ = <?= $unread ? 'false' : 'true' ?>;
var ART_FAV  = <?= $fav ? 'true' : 'false' ?>;
function tiStateApply(st) {
    ART_READ = !!st.is_read;
    ART_FAV  = !!st.is_favorite;
    var rl = document.getElementById('btn-read-label'); if (rl) rl.textContent = ART_READ ? 'Dejar sin leer' : 'Confirmar como leído';
    var fl = document.getElementById('btn-fav-label');  if (fl) fl.textContent = ART_FAV ? '★ Favorito' : '☆ Añadir a favoritos';
    var fb = document.getElementById('btn-fav'); if (fb) fb.classList.toggle('text-amber-500', ART_FAV);
    var nb = document.getElementById('art-new'); if (nb) nb.classList.toggle('hidden', ART_READ);
    var msg = document.getElementById('state-msg'); if (msg) { msg.textContent = ART_READ ? 'Marcado como leído' : 'Marcado como sin leer'; setTimeout(function(){ if (msg.textContent) msg.textContent = ''; }, 2500); }
}
function tiStateSend(payload) {
    api('POST', '<?= base_url('modules/threat_intelligence/article') ?>/<?= (int)$article['id'] ?>/state', payload)
        .then(function (res) { if (res && res.success) { tiStateApply(res); } else { toast((res && res.error) ? res.error : 'Error', 'error'); } })
        .catch(function () { toast('Error de conexión', 'error'); });
}
function tiReadToggle() { tiStateSend({ is_read: ART_READ ? 0 : 1 }); }
function tiFavToggle()  { tiStateSend({ is_favorite: ART_FAV ? 0 : 1 }); }

/* ---- Traducción IA (con caché en servidor) ---- */
var ART_HAS_TRANSLATION = <?= $hasTranslation ? 'true' : 'false' ?>;
function tiTranslationShow() {
    var box = document.getElementById('translation-body'); if (box) box.classList.remove('hidden');
    var hb = document.getElementById('btn-translation-hide'); if (hb) hb.classList.remove('hidden');
}
function tiTranslationHide() {
    var box = document.getElementById('translation-body'); if (box) box.classList.add('hidden');
    var hb = document.getElementById('btn-translation-hide'); if (hb) hb.classList.add('hidden');
}
function tiTranslate() {
    var btn = document.getElementById('btn-translate');
    var box = document.getElementById('translation-body');
    var msg = document.getElementById('translation-msg');
    if (!btn || !box) return;
    if (ART_HAS_TRANSLATION) { tiTranslationShow(); if (msg) msg.textContent = 'Traducción guardada.'; return; }
    var old = btn.textContent;
    btn.disabled = true; btn.textContent = 'Traduciendo…';
    box.classList.remove('hidden'); box.innerHTML = '<div class="spinner mx-auto"></div>'; if (msg) msg.textContent = '';
    api('POST', '<?= base_url('modules/llm/translate-article') ?>/<?= (int)$article['id'] ?>', { profile_id: getAiProfile() })
        .then(function (res) {
            btn.disabled = false;
            if (res && res.success) {
                ART_HAS_TRANSLATION = true;
                box.innerHTML = res.content_html || esc(res.content || '');
                btn.textContent = 'Ver traducción';
                tiTranslationShow();
                if (msg) msg.textContent = res.cached ? 'Traducción guardada.' : 'Traducción generada y guardada.';
            } else {
                box.classList.add('hidden');
                btn.textContent = old;
                if (msg) msg.textContent = '';
                toast((res && res.error) ? res.error : 'Error al traducir', 'error');
            }
        })
        .catch(function () { btn.disabled = false; btn.textContent = old; box.classList.add('hidden'); toast('Error de conexión', 'error'); });
}
</script>

<script>
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
                html += '<table class="data-table mt-3 w-full text-xs"><thead><tr class="text-ink-muted uppercase"><th class="text-left py-1">Tipo</th><th class="text-left py-1">Valor</th></tr></thead><tbody>';
                p.iocs.forEach(function(i) { html += '<tr><td class="py-1 pr-3 font-mono">' + esc(i.tipo || '') + '</td><td class="py-1 font-mono break-all">' + esc(i.valor || '') + '</td></tr>'; });
                html += '</tbody></table>';
            }
            if (p.recomendaciones) { html += '<p class="mt-3 text-ink-muted">' + esc(p.recomendaciones) + '</p>'; }
            box.innerHTML = html;
        })
        .catch(function() { box.innerHTML = '<p class="text-sm text-red-500">Error de conexión</p>'; });
}
</script>

<?php if (Auth::isAdmin()) { require VIEWS_PATH . '/partials/llm_actions_editor.php'; } ?>
