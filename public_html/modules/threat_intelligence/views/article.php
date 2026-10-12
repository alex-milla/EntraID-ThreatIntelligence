<?php
/**
 * Vista: detalle de un artículo de Threat Intelligence.
 * Variables: $module, $article, $iocs, $tenant
 */
$tags = safe_json_decode($article['tags'] ?? '[]', []);
$bodyText = trim(strip_tags((string)($article['body'] ?? '')));
?>
<div class="mb-6 flex items-start justify-between gap-4">
    <div class="min-w-0">
        <a href="<?= base_url('modules/threat_intelligence') ?>" class="text-xs text-brand-500 hover:underline">← Volver</a>
        <h1 class="text-xl font-semibold mt-2"><?= e($article['title']) ?></h1>
        <p class="text-xs text-gray-400 mt-1">
            <?= e($tenant['name'] ?? '') ?> ·
            <?= format_date($article['last_updated'] ?? $article['created_date']) ?>
            <?php if (!empty($article['article_id'])): ?>· <span class="font-mono"><?= e($article['article_id']) ?></span><?php endif; ?>
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
    <span class="text-xs text-gray-400 shrink-0"><?= time_ago($article['fetched_at']) ?></span>
</div>

<!-- Acciones -->
<div class="mb-6 flex flex-wrap items-center gap-2">
    <span class="text-xs text-gray-500 mr-1">Exportar IOCs del artículo:</span>
    <button onclick="exportArticle('txt')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">TXT</button>
    <button onclick="exportArticle('csv')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">CSV</button>
    <button onclick="exportArticle('stix')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">STIX 2.1</button>
    <button onclick="exportArticle('misp')" class="px-3 py-1.5 border border-gray-200 dark:border-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">MISP</button>
    <button onclick="analyzeAI()" class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg transition-colors">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
        Analizar con IA
    </button>
    <span id="export-msg" class="text-xs text-gray-500"></span>
</div>

<!-- IOCs del artículo -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden mb-6">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
        <h2 class="text-sm font-semibold">IOCs (<?= count($iocs) ?>)</h2>
        <button onclick="copyAll()" class="text-xs text-brand-500 hover:underline">Copiar todos</button>
    </div>
    <?php if (empty($iocs)): ?>
        <p class="px-5 py-8 text-sm text-gray-500 text-center">Este artículo no tiene IOCs.</p>
    <?php else: ?>
        <table class="w-full text-sm">
            <thead>
                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                    <th class="text-left px-4 py-2">Tipo</th>
                    <th class="text-left px-4 py-2">Valor</th>
                    <th class="text-left px-4 py-2">Severidad</th>
                    <th class="text-left px-4 py-2">Fuente</th>
                    <th class="text-right px-4 py-2"></th>
                </tr>
            </thead>
            <tbody id="ioc-body" class="divide-y divide-gray-100 dark:divide-gray-700/50">
                <?php foreach ($iocs as $ioc): ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <td class="px-4 py-2"><span class="font-mono text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-800"><?= e($ioc['ioc_type']) ?></span></td>
                        <td class="px-4 py-2 font-mono text-xs break-all" data-ioc="<?= e($ioc['ioc_value']) ?>"><?= e($ioc['ioc_value']) ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($ioc['severity'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($ioc['source'] ?? '—') ?></td>
                        <td class="px-4 py-2 text-right">
                            <button onclick="copyIoc(this)" class="text-xs text-gray-400 hover:text-brand-500" title="Copiar">copiar</button>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<!-- Cuerpo del artículo -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5 mb-6">
    <details>
        <summary class="text-sm font-semibold cursor-pointer">Cuerpo del artículo</summary>
        <?php if ($bodyText !== ''): ?>
            <pre class="mt-3 text-xs text-gray-600 dark:text-gray-300 whitespace-pre-wrap font-sans"><?= e($bodyText) ?></pre>
        <?php else: ?>
            <p class="mt-3 text-sm text-gray-500">(sin cuerpo)</p>
        <?php endif; ?>
    </details>
</div>

<!-- Resultado IA -->
<div id="ai-panel" class="hidden bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
    <h2 class="text-sm font-semibold mb-3">Análisis IA</h2>
    <div id="ai-result" class="text-sm text-gray-700 dark:text-gray-200"></div>
</div>

<script>
function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }

function exportArticle(fmt) {
    var el = document.getElementById('export-msg');
    el.textContent = 'Generando…';
    api('POST', '<?= base_url('modules/export/') ?>' + fmt, {
        tenant_id: <?= (int)$article['tenant_id'] ?>,
        filters: { article_id: <?= (int)$article['id'] ?> }
    }).then(function(res) {
        if (res && res.success) { downloadFile(res.content, res.filename, res.mime); el.textContent = 'Exportado (' + (res.count || 0) + ')'; }
        else { el.textContent = 'Error al exportar'; }
    }).catch(function() { el.textContent = 'Error de conexión'; });
}

function copyIoc(btn) {
    var val = btn.closest('tr').querySelector('[data-ioc]').getAttribute('data-ioc');
    navigator.clipboard.writeText(val).then(function(){ btn.textContent = 'copiado'; setTimeout(function(){ btn.textContent = 'copiar'; }, 1200); });
}

function copyAll() {
    var vals = Array.prototype.map.call(document.querySelectorAll('[data-ioc]'), function(el) { return el.getAttribute('data-ioc'); });
    navigator.clipboard.writeText(vals.join('\n')).then(function(){ toast('Copiados ' + vals.length + ' IOCs', 'success'); });
}

function analyzeAI() {
    var panel = document.getElementById('ai-panel');
    var box = document.getElementById('ai-result');
    panel.classList.remove('hidden');
    box.innerHTML = '<p class="text-sm text-gray-500">Analizando con IA…</p>';
    api('POST', '<?= base_url('modules/llm/extract-iocs') ?>', { article_id: <?= (int)$article['id'] ?> })
        .then(function(res) {
            if (!res.success) { box.innerHTML = '<p class="text-sm text-red-500">' + esc(res.error || 'Error') + '</p>'; return; }
            var p = res.parsed;
            if (!p) { box.innerHTML = '<div class="whitespace-pre-wrap">' + esc(res.content || '') + '</div>'; return; }
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
