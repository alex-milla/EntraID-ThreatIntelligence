<?php
/**
 * Vista: listado de artículos de Unit 42 con selección, estado de lectura y filtros.
 */
$tiActiveTab = 'unit42';
require VIEWS_PATH . '/partials/ti_header.php';

$st = array_merge([
    'last_run_at' => '', 'files_total' => 0, 'added' => 0, 'updated' => 0,
    'error' => '', 'articles' => 0, 'bytes' => 0, 'iocs' => 0, 'new' => 0,
], (array)($status ?? []));
$counts = array_merge([
    'total' => 0, 'unread' => 0, 'favorites' => 0, 'with_iocs' => 0,
], (array)($counts ?? []));
$filters = array_merge([
    'q' => '', 'from' => '', 'to' => '',
    'only_unread' => false, 'only_favorites' => false, 'only_iocs' => false,
], (array)($filters ?? []));
$articles = is_array($articles ?? null) ? $articles : [];
$q = (string)($q ?? '');
$page = max(1, (int)($page ?? 1));
$hasMore = !empty($hasMore);
$tenantId = (int)($selectedTenant ?? 0);

$sizeLabel = static function (int $bytes): string {
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return number_format($bytes / 1024, 1) . ' KB';
    return number_format($bytes / 1048576, 1) . ' MB';
};

$listParams = array_filter([
    'tenant'         => $tenantId,
    'q'              => $q,
    'from'           => $filters['from'],
    'to'             => $filters['to'],
    'only_unread'    => $filters['only_unread'] ? '1' : '',
    'only_favorites' => $filters['only_favorites'] ? '1' : '',
    'only_iocs'      => $filters['only_iocs'] ? '1' : '',
], static fn($v) => $v !== '' && $v !== null && $v !== false);
$listUrl = static function (array $extra = []) use ($listParams): string {
    return '?' . http_build_query(array_merge($listParams, $extra));
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
                <div class="flex flex-wrap items-center gap-1.5 mt-3">
                    <span class="px-2 py-0.5 rounded-full bg-muted text-[10px] text-ink-muted">
                        <?= (int)$counts['total'] ?> artículos
                    </span>
                    <a href="<?= e($listUrl(['only_unread' => '1', 'p' => ''])) ?>"
                       class="px-2 py-0.5 rounded-full text-[10px] font-medium <?= $filters['only_unread'] ? 'bg-brand-500 text-white' : 'bg-muted text-ink-muted hover:bg-gray-200' ?>">
                        Sin leer (<span data-u42-count="unread"><?= (int)$counts['unread'] ?></span>)
                    </a>
                    <a href="<?= e($listUrl(['only_favorites' => '1', 'p' => ''])) ?>"
                       class="px-2 py-0.5 rounded-full text-[10px] font-medium <?= $filters['only_favorites'] ? 'bg-brand-500 text-white' : 'bg-muted text-ink-muted hover:bg-gray-200' ?>">
                        Favoritos (<span data-u42-count="favorites"><?= (int)$counts['favorites'] ?></span>)
                    </a>
                    <span class="px-2 py-0.5 rounded-full bg-muted text-[10px] text-ink-muted">
                        Con IOCs (<?= (int)$counts['with_iocs'] ?>)
                    </span>
                    <?php if ($st['last_run_at'] !== ''): ?>
                        <span class="text-[10px] text-ink-soft">· última sinc. <?= e($st['last_run_at']) ?></span>
                    <?php endif; ?>
                </div>
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
            <a href="<?= e(base_url('modules/threat_intelligence/unit42/reports')) ?>?tenant=<?= $tenantId ?>"
               class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">
                Informes con IA
            </a>
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

    <!-- Filtros -->
    <div class="card p-4">
        <form method="GET" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 items-end">
            <input type="hidden" name="tenant" value="<?= $tenantId ?>">
            <label class="block">
                <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Buscar</span>
                <input type="text" name="q" value="<?= e($q) ?>" placeholder="Título o fichero…"
                       class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
            </label>
            <label class="block">
                <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Desde</span>
                <input type="date" name="from" value="<?= e((string)$filters['from']) ?>"
                       class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
            </label>
            <label class="block">
                <span class="block text-[10px] font-semibold uppercase tracking-wide text-ink-soft mb-1">Hasta</span>
                <input type="date" name="to" value="<?= e((string)$filters['to']) ?>"
                       class="w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
            </label>
            <div class="flex items-center gap-3 lg:col-span-2 flex-wrap pb-1">
                <label class="flex items-center gap-1.5 text-[11px] text-ink">
                    <input type="checkbox" name="only_unread" value="1" <?= $filters['only_unread'] ? 'checked' : '' ?>
                           class="rounded border-line-strong text-brand-500"> Solo sin leer
                </label>
                <label class="flex items-center gap-1.5 text-[11px] text-ink">
                    <input type="checkbox" name="only_favorites" value="1" <?= $filters['only_favorites'] ? 'checked' : '' ?>
                           class="rounded border-line-strong text-brand-500"> Favoritos
                </label>
                <label class="flex items-center gap-1.5 text-[11px] text-ink">
                    <input type="checkbox" name="only_iocs" value="1" <?= $filters['only_iocs'] ? 'checked' : '' ?>
                           class="rounded border-line-strong text-brand-500"> Con IOCs
                </label>
                <button type="submit" class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                    Aplicar
                </button>
                <a href="?tenant=<?= $tenantId ?>" class="text-[11px] text-ink-soft hover:text-brand-600">Limpiar</a>
            </div>
        </form>
    </div>

    <!-- Acciones en lote -->
    <div id="u42-bulk-bar" class="hidden card px-4 py-2 flex items-center gap-2 flex-wrap no-print">
        <span id="u42-selected-count" class="text-xs font-semibold text-ink-muted"></span>
        <button type="button" onclick="u42Bulk({is_read:1})"
                class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Marcar como leídas</button>
        <button type="button" onclick="u42Bulk({is_read:0})"
                class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Marcar como no leídas</button>
        <button type="button" onclick="u42Bulk({is_favorite:1})"
                class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Favoritos</button>
        <button type="button" onclick="u42MarkAllRead()"
                class="px-2.5 py-1 text-brand-600 text-xs font-medium hover:underline">Marcar todo como leído</button>
        <button type="button" onclick="u42ReportOpen()"
                class="px-2.5 py-1 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
            Informe con IA
        </button>
    </div>

    <div class="card overflow-hidden">
        <?php if ($articles === []): ?>
            <p class="p-8 text-center text-sm text-ink-muted">
                <?= $q !== '' || $filters['from'] !== '' || $filters['to'] !== ''
                    ? 'No hay artículos que coincidan con los filtros.'
                    : 'Todavía no hay artículos descargados. Pulsa «Actualizar desde GitHub».' ?>
            </p>
        <?php else: ?>
            <div class="divide-y divide-line-subtle">
                <?php foreach ($articles as $article): ?>
                    <div class="px-4 py-3 flex items-start gap-3 hover:bg-muted/50" data-u42-row="<?= (int)$article['id'] ?>">
                        <input type="checkbox" class="u42-check mt-1 shrink-0 rounded border-line-strong text-brand-500"
                               value="<?= (int)$article['id'] ?>" aria-label="Seleccionar artículo">
                        <a href="<?= e(base_url('modules/threat_intelligence/unit42/' . (int)$article['id'])) ?>?tenant=<?= $tenantId ?>"
                           class="min-w-0 flex-1 block">
                            <p class="text-sm font-medium break-words <?= empty($article['is_read']) ? '' : 'text-ink-muted' ?>">
                                <?= e((string)($article['title'] ?? '')) ?>
                            </p>
                            <p class="text-[11px] text-ink-muted mt-1 truncate"><?= e((string)($article['path'] ?? '')) ?></p>
                        </a>
                        <div class="shrink-0 text-right text-[11px] text-ink-soft">
                            <p><?= e((string)($article['published_at'] ?? '—')) ?></p>
                            <p><?= e($sizeLabel((int)($article['size'] ?? 0))) ?></p>
                            <?php if (empty($article['is_read'])): ?>
                                <span class="inline-block mt-1 px-1.5 py-0.5 rounded-full bg-brand-100 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300 text-[9px] font-semibold">NUEVO</span>
                            <?php endif; ?>
                            <?php if (!empty($article['is_favorite'])): ?>
                                <span class="text-amber-500 ml-1" title="Favorito">★</span>
                            <?php endif; ?>
                        </div>
                        <button type="button"
                                class="u42-read-toggle shrink-0 text-sm px-1 <?= empty($article['is_read']) ? 'text-gray-400' : 'text-green-500' ?>"
                                data-id="<?= (int)$article['id'] ?>"
                                data-read="<?= empty($article['is_read']) ? '0' : '1' ?>"
                                title="<?= empty($article['is_read']) ? 'Marcar como leído' : 'Marcar como no leído' ?>">
                            <?= empty($article['is_read']) ? '○' : '●' ?>
                        </button>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if ($page > 1 || $hasMore): ?>
            <div class="px-4 py-3 border-t border-line flex items-center justify-between gap-2">
                <?php if ($page > 1): ?>
                    <a href="<?= e($listUrl(['p' => $page - 1])) ?>" class="text-xs text-brand-600 hover:underline">← Anterior</a>
                <?php else: ?><span></span><?php endif; ?>
                <span class="text-[11px] text-ink-soft">Página <?= $page ?></span>
                <?php if ($hasMore): ?>
                    <a href="<?= e($listUrl(['p' => $page + 1])) ?>" class="text-xs text-brand-600 hover:underline">Siguiente →</a>
                <?php else: ?><span></span><?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Modal: informe con IA sobre la selección -->
<div id="u42-report-modal" class="hidden fixed inset-0 z-50 no-print">
    <div class="absolute inset-0 bg-black/40" onclick="u42ReportClose()"></div>
    <div class="relative mx-auto mt-24 w-[calc(100%-2rem)] max-w-lg card shadow-xl p-5">
        <div class="flex items-start justify-between gap-3">
            <div>
                <h3 class="text-sm font-semibold">Informe con IA</h3>
                <p class="text-xs text-ink-muted mt-1" id="u42-report-selected"></p>
            </div>
            <button type="button" onclick="u42ReportClose()" class="text-xs text-ink-soft hover:text-gray-600">Cerrar</button>
        </div>

        <div class="mt-4 space-y-2">
            <?php foreach (Unit42Feed::reportKinds() as $kindKey => $kindMeta): ?>
                <label class="flex items-start gap-2 p-2 rounded-lg border border-line hover:bg-muted cursor-pointer">
                    <input type="radio" name="u42-report-kind" value="<?= e($kindKey) ?>"
                           <?= $kindKey === 'resumen' ? 'checked' : '' ?>
                           class="mt-0.5 rounded border-line-strong text-brand-500">
                    <span>
                        <span class="block text-xs font-semibold text-ink"><?= e($kindMeta['label']) ?></span>
                        <span class="block text-[11px] text-ink-muted mt-0.5"><?= e($kindMeta['hint']) ?></span>
                    </span>
                </label>
            <?php endforeach; ?>
        </div>

        <p class="text-[11px] text-ink-soft mt-3">
            La IA no inventa datos: solo usa las publicaciones seleccionadas y cita sus fuentes.
            Las plantillas se pueden editar en Administración → Plantillas (grupo Unit 42).
        </p>

        <div class="mt-4 flex items-center justify-end gap-2">
            <button type="button" onclick="u42ReportClose()"
                    class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">Cancelar</button>
            <button type="button" id="u42-report-generate" onclick="u42ReportSubmit(this)"
                    class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                Generar informe
            </button>
        </div>
    </div>
</div>

<script>
(function () {
    'use strict';
    var SYNC_URL = '<?= e(base_url('modules/threat_intelligence/unit42/sync')) ?>';
    var STATE_URL = '<?= e(base_url('modules/threat_intelligence/unit42/state')) ?>';
    var REPORT_CREATE_URL = '<?= e(base_url('modules/threat_intelligence/unit42/report-create')) ?>';
    var STATUS_URL = '<?= e(base_url('modules/threat_intelligence/unit42/status')) ?>';
    var CURRENT_FILTERS = <?= json_encode(array_filter([
        'q' => $filters['q'], 'from' => $filters['from'], 'to' => $filters['to'],
        'only_unread' => $filters['only_unread'], 'only_favorites' => $filters['only_favorites'],
        'only_iocs' => $filters['only_iocs'],
    ]), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var pollTimer = null;

    function csrfToken() {
        var el = document.querySelector('input[name="csrf_token"]');
        return el ? el.value : '';
    }

    function post(url, payload) {
        return fetch(url, {
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

    function selectedIds() {
        return Array.prototype.slice.call(document.querySelectorAll('.u42-check:checked'))
            .map(function (el) { return parseInt(el.value, 10) || 0; })
            .filter(function (id) { return id > 0; });
    }

    function updateBulkBar() {
        var ids = selectedIds();
        var bar = document.getElementById('u42-bulk-bar');
        var label = document.getElementById('u42-selected-count');
        if (bar) { bar.classList.toggle('hidden', ids.length === 0); }
        if (label) {
            label.textContent = ids.length + (ids.length === 1 ? ' seleccionado' : ' seleccionados');
        }
    }

    document.addEventListener('change', function (ev) {
        if (ev.target && ev.target.classList && ev.target.classList.contains('u42-check')) {
            updateBulkBar();
        }
    });

    function applyCounts(counts) {
        if (!counts) { return; }
        var chips = document.querySelectorAll('[data-u42-count]');
        chips.forEach(function (el) {
            var key = el.getAttribute('data-u42-count');
            if (counts[key] !== undefined) { el.textContent = counts[key]; }
        });
    }

    window.u42Bulk = function (changes) {
        var ids = selectedIds();
        if (!ids.length) { return; }
        post(STATE_URL, { ids: ids, changes: changes }).then(function (out) {
            if (!out.res.ok || !out.data.success) {
                if (typeof appAlert === 'function') { appAlert(out.data.error || 'No se pudo actualizar.'); }
                return;
            }
            window.location.reload();
        }).catch(function (err) {
            if (typeof appAlert === 'function') { appAlert('Error: ' + (err && err.message ? err.message : 'red')); }
        });
    };

    window.u42MarkAllRead = function () {
        post(STATE_URL, { all: true, filters: CURRENT_FILTERS, changes: { is_read: 1 } })
            .then(function (out) {
                if (!out.res.ok || !out.data.success) {
                    if (typeof appAlert === 'function') { appAlert(out.data.error || 'No se pudo actualizar.'); }
                    return;
                }
                window.location.reload();
            }).catch(function (err) {
                if (typeof appAlert === 'function') { appAlert('Error: ' + (err && err.message ? err.message : 'red')); }
            });
    };

    /* --- Informe con IA sobre la selección --- */
    window.u42ReportOpen = function () {
        var ids = selectedIds();
        if (!ids.length) {
            if (typeof appAlert === 'function') { appAlert('Selecciona al menos una publicación.'); }
            return;
        }
        var label = document.getElementById('u42-report-selected');
        if (label) {
            label.textContent = ids.length + (ids.length === 1 ? ' publicación seleccionada' : ' publicaciones seleccionadas');
        }
        var modal = document.getElementById('u42-report-modal');
        if (modal) { modal.classList.remove('hidden'); }
    };

    window.u42ReportClose = function () {
        var modal = document.getElementById('u42-report-modal');
        if (modal) { modal.classList.add('hidden'); }
    };

    window.u42ReportSubmit = function (button) {
        var ids = selectedIds();
        if (!ids.length) { return; }
        var checked = document.querySelector('input[name="u42-report-kind"]:checked');
        var kind = checked ? checked.value : 'resumen';
        if (button) { button.disabled = true; button.textContent = 'Creando…'; }

        post(REPORT_CREATE_URL, {
            item_ids: ids,
            kind: kind,
            tenant_id: <?= $tenantId ?>,
            profile_id: 0
        }).then(function (out) {
            var d = out.data || {};
            if (!out.res.ok || !d.success) {
                if (typeof appAlert === 'function') { appAlert(d.error || 'No se pudo crear el informe.'); }
                if (button) { button.disabled = false; button.textContent = 'Generar informe'; }
                return;
            }
            if (d.queued || d.worker === 'fpm') {
                window.location.href = d.url; // la página del informe sondea el estado
            } else {
                window.location.href = d.url;
            }
        }).catch(function (err) {
            if (typeof appAlert === 'function') { appAlert('Error: ' + (err && err.message ? err.message : 'red')); }
            if (button) { button.disabled = false; button.textContent = 'Generar informe'; }
        });
    };

    document.addEventListener('click', function (ev) {
        var btn = ev.target && ev.target.closest ? ev.target.closest('.u42-read-toggle') : null;
        if (!btn) { return; }
        ev.preventDefault();
        ev.stopPropagation();
        var id = parseInt(btn.dataset.id, 10) || 0;
        var read = btn.dataset.read === '1' ? 0 : 1;
        post(STATE_URL, { ids: [id], changes: { is_read: read } }).then(function (out) {
            if (!out.res.ok || !out.data.success) { return; }
            btn.dataset.read = String(read);
            btn.textContent = read ? '●' : '○';
            btn.className = 'u42-read-toggle shrink-0 text-sm px-1 ' + (read ? 'text-green-500' : 'text-gray-400');
            btn.title = read ? 'Marcar como no leído' : 'Marcar como leído';
            applyCounts(out.data.counts);
            var row = document.querySelector('[data-u42-row="' + id + '"]');
            if (row) {
                var title = row.querySelector('p');
                if (title) { title.className = read ? 'text-sm font-medium break-words text-ink-muted' : 'text-sm font-medium break-words'; }
            }
        });
    });

    /* --- Sincronización (check → descargar → progreso) --- */
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

    window.u42Sync = function (button) {
        if (!button || button.disabled) { return; }
        var oldText = button.textContent;
        button.disabled = true;
        button.textContent = 'Comprobando…';
        if (panel()) { panel().classList.remove('hidden'); }
        if (message()) { message().textContent = 'Consultando GitHub…'; }
        if (downloadBtn()) { downloadBtn().classList.add('hidden'); }
        if (progressWrap()) { progressWrap().classList.add('hidden'); }

        post(SYNC_URL, { check: true }).then(function (out) {
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
            if (message()) { message().textContent = 'Hay ' + parts.join(' y ') + ' de ' + d.total + ' ficheros. ¿Descargarlos todos?'; }
            if (downloadBtn()) { downloadBtn().classList.remove('hidden'); }
        }).catch(function (err) {
            button.disabled = false;
            button.textContent = oldText;
            if (message()) { message().textContent = 'Error: ' + (err && err.message ? err.message : 'red'); }
        });
    };

    window.u42Download = function () {
        var btn = downloadBtn();
        if (!btn || btn.disabled) { return; }
        btn.disabled = true;
        btn.textContent = 'Descargando…';
        if (progressWrap()) { progressWrap().classList.remove('hidden'); }
        if (message()) { message().textContent = 'Descargando desde GitHub…'; }

        post(SYNC_URL, {}).then(function (out) {
            var d = out.data || {};
            if (!out.res.ok || !d.success) {
                if (message()) { message().textContent = d.error || 'No se pudo descargar.'; }
                btn.disabled = false;
                btn.textContent = 'Reintentar';
                return;
            }
            if (d.queued || d.worker === 'fpm') { startPolling(); }
            else {
                if (message()) { message().textContent = d.added + ' nuevos · ' + d.updated + ' actualizados · ' + d.unchanged + ' sin cambios'; }
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
                if (detail()) { detail().textContent = done + ' descargados' + (st.pending ? ' · quedan ' + st.pending : ''); }
                if (st.state === 'done' || st.state === 'error') {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    if (st.state === 'error') {
                        if (message()) { message().textContent = 'Error: ' + (st.error || 'descarga interrumpida'); }
                        if (downloadBtn()) { downloadBtn().disabled = false; downloadBtn().textContent = 'Continuar'; }
                    } else {
                        window.location.reload();
                    }
                }
            }).catch(function () { /* reintenta */ });
        }, 3000);
    }
})();
</script>
