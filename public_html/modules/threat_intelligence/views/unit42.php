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
        <div id="u42-sync-panel" class="hidden mt-4 pt-4 border-t border-line">
            <p id="u42-sync-message" class="text-xs text-ink"></p>
            <div id="u42-sync-progress-wrap" class="hidden mt-2">
                <div class="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                    <div id="u42-sync-bar" class="h-full bg-brand-500 transition-all" style="width:0%"></div>
                </div>
                <p id="u42-sync-detail" class="text-[11px] text-ink-muted mt-1"></p>
            </div>
            <div class="mt-3 flex items-center gap-2 flex-wrap">
                <button type="button" id="u42-download-btn" onclick="u42Download()"
                        class="hidden px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                    Descargar
                </button>
                <button type="button" onclick="u42HidePanel()"
                        class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">Cerrar</button>
            </div>
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
    var SYNC_URL = '<?= e(base_url('modules/threat_intelligence/unit42/sync')) ?>';
    var STATUS_URL = '<?= e(base_url('modules/threat_intelligence/unit42/status')) ?>';
    var pollTimer = null;

    function csrfToken() {
        var el = document.querySelector('input[name="csrf_token"]');
        return el ? el.value : '';
    }

    function post(payload) {
        return fetch(SYNC_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': csrfToken()
            },
            credentials: 'same-origin',
            body: JSON.stringify(payload)
        }).then(function (res) {
            return res.json().catch(function () { return {}; }).then(function (data) {
                return { res: res, data: data };
            });
        });
    }

    function panel() { return document.getElementById('u42-sync-panel'); }
    function message() { return document.getElementById('u42-sync-message'); }
    function progressWrap() { return document.getElementById('u42-sync-progress-wrap'); }
    function bar() { return document.getElementById('u42-sync-bar'); }
    function detail() { return document.getElementById('u42-sync-detail'); }
    function downloadBtn() { return document.getElementById('u42-download-btn'); }

    window.u42HidePanel = function () {
        if (panel()) { panel().classList.add('hidden'); }
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    };

    /* Paso 1: solo cuenta cuántos hay nuevos/modificados (no descarga). */
    window.u42Sync = function (button) {
        if (!button || button.disabled) { return; }
        var oldText = button.textContent;
        button.disabled = true;
        button.textContent = 'Comprobando…';
        if (panel()) { panel().classList.remove('hidden'); }
        if (message()) { message().textContent = 'Consultando GitHub…'; }
        if (downloadBtn()) { downloadBtn().classList.add('hidden'); }
        if (progressWrap()) { progressWrap().classList.add('hidden'); }

        post({ check: true }).then(function (out) {
            button.disabled = false;
            button.textContent = oldText;
            var d = out.data || {};
            if (!out.res.ok || !d.ok) {
                if (message()) { message().textContent = d.error || 'No se pudo comprobar GitHub.'; }
                return;
            }
            if (!d.pending) {
                if (message()) { message().textContent = 'Todo está al día: ' + d.total + ' ficheros, ninguno nuevo.'; }
                return;
            }
            var parts = [];
            if (d.new) { parts.push(d.new + ' nuevos'); }
            if (d.changed) { parts.push(d.changed + ' modificados'); }
            if (message()) {
                message().textContent = 'Hay ' + parts.join(' y ') + ' de ' + d.total + ' ficheros. ¿Descargarlos todos?';
            }
            if (downloadBtn()) {
                downloadBtn().classList.remove('hidden');
                downloadBtn().dataset.pending = String(d.pending);
            }
        }).catch(function (err) {
            button.disabled = false;
            button.textContent = oldText;
            if (message()) { message().textContent = 'Error: ' + (err && err.message ? err.message : 'red'); }
        });
    };

    /* Paso 2: descarga todo de golpe (con FPM responde ya y sigue en segundo plano). */
    window.u42Download = function () {
        var btn = downloadBtn();
        if (!btn || btn.disabled) { return; }
        btn.disabled = true;
        btn.textContent = 'Descargando…';
        if (progressWrap()) { progressWrap().classList.remove('hidden'); }
        if (message()) { message().textContent = 'Descargando desde GitHub…'; }

        post({}).then(function (out) {
            var d = out.data || {};
            if (!out.res.ok || !d.success) {
                if (message()) { message().textContent = d.error || 'No se pudo descargar.'; }
                btn.disabled = false;
                btn.textContent = 'Reintentar';
                return;
            }
            if (d.queued || d.worker === 'fpm') {
                startPolling();
            } else {
                if (message()) {
                    message().textContent = d.added + ' nuevos · ' + d.updated + ' actualizados · ' + d.unchanged + ' sin cambios';
                }
                window.setTimeout(function () { window.location.reload(); }, 1200);
            }
        }).catch(function (err) {
            if (message()) { message().textContent = 'Error: ' + (err && err.message ? err.message : 'red'); }
            btn.disabled = false;
            btn.textContent = 'Reintentar';
        });
    };

    function startPolling() {
        if (pollTimer) { return; }
        pollTimer = window.setInterval(function () {
            fetch(STATUS_URL, {
                headers: {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
                credentials: 'same-origin'
            }).then(function (res) { return res.json(); }).then(function (st) {
                if (!st) { return; }
                var total = (st.files_total || 0) + (st.pending || 0);
                var done = parseInt(st.processed || 0, 10);
                if (bar() && total > 0) { bar().style.width = Math.min(100, Math.round(done * 100 / total)) + '%'; }
                if (detail()) {
                    detail().textContent = done + ' descargados' + (st.pending ? ' · quedan ' + st.pending : '');
                }
                if (st.state === 'done' || st.state === 'error') {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    if (st.state === 'error') {
                        if (message()) { message().textContent = 'Error: ' + (st.error || 'descarga interrumpida'); }
                        var btn = downloadBtn();
                        if (btn) { btn.disabled = false; btn.textContent = 'Continuar'; }
                    } else {
                        window.location.reload();
                    }
                }
            }).catch(function () { /* reintenta */ });
        }, 3000);
    }
})();
</script>
