<?php
/**
 * Vista: listado de artículos de Unit 42 con selección, estado de lectura y filtros.
 */

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
            <a href="<?= e(base_url('modules/unit42/reports')) ?>?tenant=<?= $tenantId ?>"
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

    <!-- Acciones masivas: siempre visibles -->
    <div id="u42-mass-bar" class="card px-4 py-2 flex items-center gap-2 flex-wrap no-print">
        <label class="flex items-center gap-2 text-xs font-semibold text-ink cursor-pointer">
            <input type="checkbox" id="u42-select-all"
                   class="rounded border-line-strong text-brand-500"
                   aria-label="Seleccionar todos los artículos de esta página">
            Todos (esta página)
        </label>
        <span class="w-px h-4 bg-line" aria-hidden="true"></span>
        <button type="button" onclick="u42MarkAllRead()"
                class="px-2.5 py-1 border border-green-300 text-green-700 text-xs font-medium rounded-lg hover:bg-green-50 dark:hover:bg-green-900/20">
            ✓ Marcar todo como leído
        </button>
        <button type="button" onclick="u42MarkAllUnread()"
                class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">
            Marcar todo como no leído
        </button>
        <span class="text-[11px] text-ink-soft hidden sm:inline">Aplica a los artículos que cumplen los filtros, no solo a esta página.</span>
    </div>

    <!-- Acciones sobre la selección (aparece al marcar artículos) -->
    <div id="u42-bulk-bar" class="hidden card px-4 py-2 flex items-center gap-2 flex-wrap no-print">
        <span id="u42-selected-count" class="text-xs font-semibold text-ink-muted"></span>
        <button type="button" onclick="u42Bulk({is_read:1})"
                class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Marcar como leídas</button>
        <button type="button" onclick="u42Bulk({is_read:0})"
                class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Marcar como no leídas</button>
        <button type="button" onclick="u42Bulk({is_favorite:1})"
                class="px-2.5 py-1 border border-line-strong text-xs rounded-lg hover:bg-muted">Favoritos</button>
        <button type="button" onclick="u42ReportOpen()"
                class="px-2.5 py-1 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
            Informe con IA
        </button>
    </div>

    <div class="card overflow-hidden">
        <div class="flex items-center justify-between gap-3 px-5 py-3 border-b border-line">
            <h2 class="text-sm font-semibold">Publicaciones <span class="text-ink-soft font-normal">· por fecha de publicación</span></h2>
            <button type="button"
                    onclick="IOCExtractor.open({source:'u42', format:'stix'})"
                    class="text-xs text-brand-500 hover:underline">Exportar IOCs</button>
        </div>
        <?php if ($articles === []): ?>
            <p class="p-8 text-center text-sm text-ink-muted">
                <?= $q !== '' || $filters['from'] !== '' || $filters['to'] !== ''
                    ? 'No hay artículos que coincidan con los filtros.'
                    : 'Todavía no hay artículos descargados. Pulsa «Actualizar desde GitHub».' ?>
            </p>
        <?php else: ?>
            <div class="divide-y divide-line-subtle">
                <?php foreach ($articles as $article): ?>
                    <?php
                    $rowId = (int)$article['id'];
                    $unread = empty($article['is_read']);
                    $fav = !empty($article['is_favorite']);
                    $fresh = Unit42Feed::freshness($article);
                    $highlight = $fresh['new24'] || $fresh['updated24'];
                    $created = (string)($article['published_at'] ?? '');
                    $updatedAt = (string)($article['updated_at'] ?? '');
                    $showUpdated = $fresh['updated'];
                    $iocCount = (int)($article['ioc_count'] ?? 0);
                    ?>
                    <div data-u42-row="<?= $rowId ?>">
                        <div class="px-5 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors border-l-2 <?= $highlight ? 'border-brand-500' : 'border-transparent' ?>"
                             data-read="<?= $unread ? '0' : '1' ?>" data-fav="<?= $fav ? '1' : '0' ?>">
                            <div class="flex items-start gap-3">
                                <input type="checkbox" class="u42-check mt-1 shrink-0 rounded border-line-strong text-brand-500"
                                       value="<?= $rowId ?>" aria-label="Seleccionar artículo">
                                <a href="<?= e(base_url('modules/unit42/' . $rowId)) ?>?tenant=<?= $tenantId ?>"
                                   data-u42-toggle="<?= $rowId ?>"
                                   class="u42-title-link min-w-0 flex-1 block group"
                                   title="Desplegar el artículo debajo">
                                    <div class="flex items-center gap-2 min-w-0">
                                        <span data-role="new"
                                              class="u42-nuevo inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide bg-brand-500 text-white shrink-0 <?= $unread ? '' : 'hidden' ?>"
                                              title="Sin leer">New</span>
                                        <?php if ($fresh['new24']): ?>
                                            <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-warning-bg text-warning shrink-0"
                                                  title="Descargado en las últimas 24 h">24 h</span>
                                        <?php endif; ?>
                                        <?php if ($fresh['updated24']): ?>
                                            <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 shrink-0"
                                                  title="Fichero modificado en GitHub y vuelto a descargar">Actualizado</span>
                                        <?php endif; ?>
                                        <span class="u42-chevron inline-block mr-0.5 text-brand-500 text-[10px]">▸</span>
                                        <p class="u42-title text-sm font-medium truncate"><?= e((string)($article['title'] ?? '')) ?></p>
                                    </div>
                                    <p class="text-xs text-ink-soft mt-0.5">
                                        <?= e(format_date($created)) ?>
                                        <?php if ($showUpdated): ?> · <span title="El fichero se modificó en el repositorio">actualizado <?= e(format_date($updatedAt)) ?></span><?php endif; ?>
                                        · <?= $iocCount ?> IOCs
                                    </p>
                                </a>
                                <div class="flex items-center gap-1 shrink-0">
                                    <button type="button" data-role="fav" data-id="<?= $rowId ?>"
                                            onclick="u42RowFav(event, <?= $rowId ?>)"
                                            title="<?= $fav ? 'Quitar de favoritos' : 'Añadir a favoritos' ?>"
                                            class="u42-fav-toggle w-7 h-7 inline-flex items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 text-base leading-none <?= $fav ? 'text-amber-400' : 'text-gray-300 dark:text-gray-600' ?>"><?= $fav ? '★' : '☆' ?></button>
                                    <button type="button" data-role="read" data-id="<?= $rowId ?>"
                                            class="u42-read-toggle w-7 h-7 inline-flex items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 <?= $unread ? 'text-gray-400' : 'text-green-500' ?>"
                                            data-read="<?= $unread ? '0' : '1' ?>"
                                            title="<?= $unread ? 'Marcar como leído' : 'Dejar sin leer' ?>">
                                        <i class="material-icons icon-16" aria-hidden="true">check</i>
                                    </button>
                                </div>
                            </div>
                        </div>
                        <div id="u42-panel-<?= $rowId ?>" class="u42-panel hidden px-5 pb-4" data-u42-panel="<?= $rowId ?>"></div>
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

        <div class="mt-4">
            <label for="u42-report-profile" class="block text-xs font-medium text-ink-muted mb-1">
                Perfil de IA
            </label>
            <select id="u42-report-profile"
                    class="w-full px-2.5 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                <option value="0">— Modelo predeterminado —</option>
                <?php foreach (($llmProfiles ?? []) as $profile): ?>
                    <?php $pid = (int)($profile['id'] ?? 0); ?>
                    <option value="<?= $pid ?>">
                        <?= e((string)($profile['name'] ?? ('Perfil ' . $pid))) ?>
                        <?php if (!empty($profile['model'])): ?>(<?= e((string)$profile['model']) ?>)<?php endif; ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <p class="text-[10px] text-ink-soft mt-1">
                Si eliges «predeterminado» se usa el modelo asignado a la tarea <code>unit42_report</code> en Admin → APIs.
            </p>
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
    var SYNC_URL = '<?= e(base_url('modules/unit42/sync')) ?>';
    var STATE_URL = '<?= e(base_url('modules/unit42/state')) ?>';
    var REPORT_CREATE_URL = '<?= e(base_url('modules/unit42/report-create')) ?>';
    var STATUS_URL = '<?= e(base_url('modules/unit42/status')) ?>';
    var PANEL_URL_TPL = '<?= e(base_url('modules/unit42')) ?>/{id}/panel';
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
        var all = document.querySelectorAll('.u42-check');
        var master = document.getElementById('u42-select-all');
        if (master) {
            master.checked = all.length > 0 && ids.length === all.length;
            master.indeterminate = ids.length > 0 && ids.length < all.length;
        }
    }

    document.addEventListener('change', function (ev) {
        if (!ev.target || !ev.target.classList) { return; }
        if (ev.target.classList.contains('u42-check')) {
            updateBulkBar();
        } else if (ev.target.id === 'u42-select-all') {
            var checked = ev.target.checked;
            document.querySelectorAll('.u42-check').forEach(function (c) { c.checked = checked; });
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

    function markAll(changes) {
        post(STATE_URL, { all: true, filters: CURRENT_FILTERS, changes: changes })
            .then(function (out) {
                if (!out.res.ok || !out.data.success) {
                    if (typeof appAlert === 'function') { appAlert(out.data.error || 'No se pudo actualizar.'); }
                    return;
                }
                window.location.reload();
            }).catch(function (err) {
                if (typeof appAlert === 'function') { appAlert('Error: ' + (err && err.message ? err.message : 'red')); }
            });
    }

    window.u42MarkAllRead = function () { markAll({ is_read: 1 }); };
    window.u42MarkAllUnread = function () { markAll({ is_read: 0 }); };

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
        var profileSel = document.getElementById('u42-report-profile');
        var profileId = profileSel ? (parseInt(profileSel.value, 10) || 0) : 0;
        if (button) { button.disabled = true; button.textContent = 'Creando…'; }

        post(REPORT_CREATE_URL, {
            item_ids: ids,
            kind: kind,
            tenant_id: <?= $tenantId ?>,
            profile_id: profileId
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

    function renderReadToggle(btn, read) {
        btn.dataset.read = read ? '1' : '0';
        btn.title = read ? 'Dejar sin leer' : 'Marcar como leído';
        btn.className = 'u42-read-toggle w-7 h-7 inline-flex items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 '
            + (read ? 'text-green-500' : 'text-gray-400');
        btn.innerHTML = '<i class="material-icons icon-16" aria-hidden="true">check</i>';
    }

    function renderFavToggle(btn, fav) {
        btn.dataset.fav = fav ? '1' : '0';
        btn.title = fav ? 'Quitar de favoritos' : 'Añadir a favoritos';
        btn.className = 'u42-fav-toggle w-7 h-7 inline-flex items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 text-base leading-none '
            + (fav
                ? 'text-amber-400'
                : 'text-gray-300 dark:text-gray-600');
        btn.textContent = fav ? '★' : '☆';
    }

    function syncRow(id, field, value) {
        var row = document.querySelector('[data-u42-row="' + id + '"]');
        if (!row) { return; }
        var container = row.firstElementChild;
        if (field === 'is_read') {
            var badge = row.querySelector('.u42-nuevo');
            if (badge) { badge.classList.toggle('hidden', !!value); }
            if (container) { container.dataset.read = value ? '1' : '0'; }
        } else if (field === 'is_favorite') {
            if (container) { container.dataset.fav = value ? '1' : '0'; }
        }
    }

    /* --- Despliegue en línea del artículo --- */
    function setArticleParam(id) {
        if (!window.history || !window.history.replaceState) { return; }
        var url = new URL(window.location.href);
        if (id) { url.searchParams.set('articulo', id); }
        else { url.searchParams.delete('articulo'); }
        window.history.replaceState(null, '', url.pathname + url.search);
    }

    function openArticle(id, link) {
        var panel = document.getElementById('u42-panel-' + id);
        if (!panel) { return; }

        var isOpen = !panel.classList.contains('hidden');
        document.querySelectorAll('.u42-panel:not(.hidden)').forEach(function (p) {
            if (p !== panel) { p.classList.add('hidden'); }
        });
        document.querySelectorAll('.u42-title-link').forEach(function (a) {
            a.classList.remove('u42-open');
            var chevron = a.querySelector('.u42-chevron');
            if (chevron) { chevron.textContent = '▸'; }
        });

        if (isOpen) {
            panel.classList.add('hidden');
            setArticleParam(null);
            return;
        }

        panel.classList.remove('hidden');
        if (link) {
            link.classList.add('u42-open');
            var ch = link.querySelector('.u42-chevron');
            if (ch) { ch.textContent = '▾'; }
        }
        setArticleParam(id);

        if (!panel.dataset.loaded) {
            panel.innerHTML = '<p class="text-xs text-ink-muted py-3">Cargando artículo…</p>';
            fetch(PANEL_URL_TPL.replace('{id}', id), {
                headers: {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'text/html'},
                credentials: 'same-origin'
            }).then(function (res) {
                if (!res.ok) { throw new Error('HTTP ' + res.status); }
                return res.text();
            }).then(function (html) {
                panel.innerHTML = html;
                panel.dataset.loaded = '1';
            }).catch(function () {
                panel.dataset.loaded = '';
                panel.innerHTML = '<p class="text-xs text-danger py-3">No se pudo cargar el artículo. '
                    + '<a class="underline" href="' + PANEL_URL_TPL.replace('{id}', id).replace('/panel', '') + '">Abrir ficha completa ↗</a></p>';
            });
        }
    }

    window.u42OpenArticle = openArticle;
    window.u42RowFav = function (ev, id) {
        if (ev) { ev.preventDefault(); ev.stopPropagation(); }
        var btn = document.querySelector('[data-u42-row="' + id + '"] .u42-fav-toggle');
        if (!btn) { return; }
        var fav = btn.dataset.fav === '1' ? 0 : 1;
        post(STATE_URL, { ids: [id], changes: { is_favorite: fav } }).then(function (out) {
            if (!out.res.ok || !out.data.success) { return; }
            document.querySelectorAll('.u42-fav-toggle[data-id="' + id + '"]').forEach(function (b) {
                renderFavToggle(b, fav);
            });
            syncRow(id, 'is_favorite', fav);
            applyCounts(out.data.counts);
        });
    };

    document.addEventListener('click', function (ev) {
        var target = ev.target && ev.target.closest ? ev.target : null;
        if (!target) { return; }

        var link = target.closest('[data-u42-toggle]');
        if (link) {
            ev.preventDefault();
            openArticle(link.getAttribute('data-u42-toggle'), link);
            return;
        }

        var readBtn = target.closest('.u42-read-toggle');
        if (readBtn) {
            ev.preventDefault();
            ev.stopPropagation();
            var id = parseInt(readBtn.dataset.id, 10) || 0;
            var read = readBtn.dataset.read === '1' ? 0 : 1;
            post(STATE_URL, { ids: [id], changes: { is_read: read } }).then(function (out) {
                if (!out.res.ok || !out.data.success) { return; }
                document.querySelectorAll('.u42-read-toggle[data-id="' + id + '"]').forEach(function (b) {
                    renderReadToggle(b, read);
                });
                syncRow(id, 'is_read', read);
                applyCounts(out.data.counts);
            });
            return;
        }

        var favBtn = target.closest('.u42-fav-toggle');
        if (favBtn) {
            ev.preventDefault();
            ev.stopPropagation();
            var fid = parseInt(favBtn.dataset.id, 10) || 0;
            var fav = favBtn.dataset.fav === '1' ? 0 : 1;
            post(STATE_URL, { ids: [fid], changes: { is_favorite: fav } }).then(function (out) {
                if (!out.res.ok || !out.data.success) { return; }
                document.querySelectorAll('.u42-fav-toggle[data-id="' + fid + '"]').forEach(function (b) {
                    renderFavToggle(b, fav);
                });
                syncRow(fid, 'is_favorite', fav);
                applyCounts(out.data.counts);
            });
            return;
        }

        var rawBtn = target.closest('.u42-raw-toggle');
        if (rawBtn) {
            ev.preventDefault();
            var raw = document.getElementById(rawBtn.dataset.raw);
            var report = document.getElementById(rawBtn.dataset.report);
            if (!raw || !report) { return; }
            var show = raw.hidden;
            raw.hidden = !show;
            raw.classList.toggle('hidden', !show);
            report.classList.toggle('hidden', show);
            rawBtn.textContent = show ? 'Ver análisis' : 'Ver texto original';
        }
    });

    // Al recargar con ?articulo=<id>, se reabre desplegado.
    (function autoOpen() {
        var id = 0;
        try {
            id = parseInt(new URLSearchParams(window.location.search).get('articulo') || '0', 10) || 0;
        } catch (e) { return; }
        if (!id) { return; }
        var link = document.querySelector('[data-u42-toggle="' + id + '"]');
        if (link) { openArticle(id, link); }
    })();

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
