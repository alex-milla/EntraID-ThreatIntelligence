<?php
/**
 * Vista: listado de artículos públicos de Unit 42 (Unit42-timely-threat-intel).
 */
$tiActiveTab = 'unit42';
$tiFilterQs = ['q' => $q ?? ''];
require VIEWS_PATH . '/partials/ti_header.php';

$st = array_merge([
    'last_run_at' => '', 'files_total' => 0, 'added' => 0, 'updated' => 0,
    'error' => '', 'articles' => 0, 'bytes' => 0, 'iocs' => 0, 'new' => 0,
], (array)($status ?? []));
$articles = is_array($articles ?? null) ? $articles : [];
$q = (string)($q ?? '');
$page = max(1, (int)($page ?? 1));
$hasMore = !empty($hasMore);

$sizeLabel = static function (int $bytes): string {
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return number_format($bytes / 1024, 1) . ' KB';
    return number_format($bytes / 1048576, 1) . ' MB';
};
?>
<div class="space-y-4">
    <div class="card p-4">
        <div class="flex items-start justify-between gap-4 flex-wrap">
            <div class="min-w-0">
                <h2 class="text-sm font-semibold">Unit 42 · timely threat intel</h2>
                <p class="text-xs text-ink-muted mt-1">
                    Artículos públicos descargados de
                    <a href="https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel"
                       target="_blank" rel="noopener" class="text-brand-600 hover:underline">GitHub</a>.
                    Solo se descargan los ficheros nuevos o modificados; el texto original se conserva sin cambios.
                </p>
                <p class="text-[11px] text-ink-soft mt-2">
                    <?= (int)$st['articles'] ?> artículos · <?= (int)$st['iocs'] ?> IOCs ·
                    <?= e($sizeLabel((int)$st['bytes'])) ?> en local
                    <?php if ($st['last_run_at'] !== ''): ?>
                        · última sincronización <?= e($st['last_run_at']) ?>
                    <?php endif; ?>
                </p>
                <?php if ($st['error'] !== ''): ?>
                    <p class="mt-2 text-xs text-danger">Error: <?= e($st['error']) ?></p>
                <?php endif; ?>
            </div>
            <?php if (Auth::isAdmin()): ?>
                <button type="button" id="u42-sync-btn" onclick="u42Sync(this)"
                        class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                    Actualizar desde GitHub
                </button>
            <?php endif; ?>
        </div>
    </div>

    <div class="card overflow-hidden">
        <div class="px-4 py-3 border-b border-line flex items-center justify-between gap-3 flex-wrap">
            <h3 class="text-sm font-semibold m-0">Artículos</h3>
            <form method="GET" class="m-0 flex items-center gap-2">
                <input type="hidden" name="tenant" value="<?= (int)($selectedTenant ?? 0) ?>">
                <input type="text" name="q" value="<?= e($q) ?>" placeholder="Buscar por título o fichero…"
                       class="px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs w-64">
                <button type="submit" class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">Buscar</button>
            </form>
        </div>

        <?php if ($articles === []): ?>
            <p class="p-8 text-center text-sm text-ink-muted">
                <?= $q !== '' ? 'No hay artículos que coincidan con la búsqueda.' : 'Todavía no hay artículos descargados. Pulsa «Actualizar desde GitHub».' ?>
            </p>
        <?php else: ?>
            <div class="divide-y divide-line-subtle">
                <?php foreach ($articles as $article): ?>
                    <?php
                    $new = (string)($article['first_seen_at'] ?? '') >= gmdate('Y-m-d H:i:s', time() - 7 * 86400);
                    ?>
                    <a href="<?= e(base_url('modules/threat_intelligence/unit42/' . (int)$article['id'])) ?>?tenant=<?= (int)($selectedTenant ?? 0) ?>"
                       class="block px-4 py-3 hover:bg-muted/50 transition-colors">
                        <div class="flex items-start justify-between gap-3">
                            <div class="min-w-0">
                                <p class="text-sm font-medium break-words"><?= e((string)($article['title'] ?? '')) ?></p>
                                <p class="text-[11px] text-ink-muted mt-1 truncate"><?= e((string)($article['path'] ?? '')) ?></p>
                            </div>
                            <div class="shrink-0 text-right text-[11px] text-ink-soft">
                                <p><?= e((string)($article['published_at'] ?? '—')) ?></p>
                                <p><?= e($sizeLabel((int)($article['size'] ?? 0))) ?></p>
                                <?php if ($new): ?>
                                    <span class="inline-block mt-1 px-1.5 py-0.5 rounded-full bg-brand-100 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300 text-[9px] font-semibold">NUEVO</span>
                                <?php endif; ?>
                            </div>
                        </div>
                    </a>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if ($page > 1 || $hasMore): ?>
            <div class="px-4 py-3 border-t border-line flex items-center justify-between gap-2">
                <?php if ($page > 1): ?>
                    <a href="?tenant=<?= (int)($selectedTenant ?? 0) ?>&q=<?= e(rawurlencode($q)) ?>&p=<?= $page - 1 ?>"
                       class="text-xs text-brand-600 hover:underline">← Anterior</a>
                <?php else: ?><span></span><?php endif; ?>
                <span class="text-[11px] text-ink-soft">Página <?= $page ?></span>
                <?php if ($hasMore): ?>
                    <a href="?tenant=<?= (int)($selectedTenant ?? 0) ?>&q=<?= e(rawurlencode($q)) ?>&p=<?= $page + 1 ?>"
                       class="text-xs text-brand-600 hover:underline">Siguiente →</a>
                <?php else: ?><span></span><?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<script>
(function () {
    'use strict';
    window.u42Sync = function (button) {
        if (!button || button.disabled) { return; }
        var tokenEl = document.querySelector('input[name="csrf_token"]');
        var token = tokenEl ? tokenEl.value : '';
        var oldText = button.textContent;
        button.disabled = true;
        button.textContent = 'Descargando…';

        fetch('<?= e(base_url('modules/threat_intelligence/unit42/sync')) ?>', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': token
            },
            credentials: 'same-origin',
            body: '{}'
        }).then(function (res) {
            return res.json().catch(function () { return {}; }).then(function (data) {
                if (!res.ok || !data.success) {
                    throw new Error(data.error || ('HTTP ' + res.status));
                }
                return data;
            });
        }).then(function (data) {
            if (typeof toast === 'function') {
                toast(data.added + ' nuevos · ' + data.updated + ' actualizados · ' + data.unchanged + ' sin cambios', 'success');
            }
            window.location.reload();
        }).catch(function (err) {
            if (typeof appAlert === 'function') {
                appAlert('No se pudo sincronizar: ' + (err && err.message ? err.message : 'error de red'), { title: 'Sincronización' });
            }
            button.disabled = false;
            button.textContent = oldText;
        });
    };
})();
</script>
