<?php
/**
 * Vista: un fichero de Unit 42 mostrado como informe, sin tocar el original.
 * El cuerpo se comparte con el panel desplegable del listado (_unit42_panel.php).
 */

$article = is_array($article ?? null) ? $article : [];
$articleId = (int)($article['id'] ?? 0);
$tenantId = (int)($selectedTenant ?? 0);
$userId = (int)(Auth::id() ?? 0);
$articleState = $userId > 0 ? (Unit42Feed::statesFor($userId, [$articleId])[$articleId] ?? []) : [];
$isRead = !empty($articleState['is_read']);
$isFavorite = !empty($articleState['is_favorite']);
$panelMode = false;
$fresh = Unit42Feed::freshness($article);
$updatedAt = (string)($article['updated_at'] ?? '');

$rawUrl = 'https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/'
    . rawurlencode((string)($article['path'] ?? ''));
?>
<div class="space-y-4">
    <div class="card p-5">
        <div class="min-w-0">
            <a href="<?= e(base_url('modules/unit42')) ?>?tenant=<?= $tenantId ?>"
               class="text-xs text-brand-600 hover:underline">← Unit42</a>
            <div class="flex items-center gap-2 flex-wrap mt-3">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft">
                    Informe Unit 42
                    <?= (string)($article['published_at'] ?? '') !== '' ? '· ' . e(format_date((string)$article['published_at'])) : '' ?>
                    <?php if ($fresh['updated']): ?>
                        · <span title="El fichero se modificó en el repositorio">actualizado <?= e(format_date($updatedAt)) ?></span>
                    <?php endif; ?>
                </p>
                <?php if ($fresh['new24']): ?>
                    <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-warning-bg text-warning"
                          title="Descargado en las últimas 24 h">24 h</span>
                <?php endif; ?>
                <?php if ($fresh['updated24']): ?>
                    <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300"
                          title="Fichero modificado en GitHub y vuelto a descargar">Actualizado</span>
                <?php endif; ?>
            </div>
            <h2 class="text-lg font-bold mt-1 break-words"><?= e((string)($article['title'] ?? '')) ?></h2>
        </div>
    </div>

    <?php include __DIR__ . '/_unit42_panel.php'; ?>
</div>

<script>
(function () {
    'use strict';
    var STATE_URL = '<?= e(base_url('modules/unit42/state')) ?>';

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
                return {res: res, data: data};
            });
        });
    }

    function renderReadToggle(btn, read) {
        btn.dataset.read = read ? '1' : '0';
        btn.title = read ? 'Marcar como no leído' : 'Marcar como leído';
        btn.className = 'u42-read-toggle inline-flex items-center gap-1 text-xs px-2 py-1 rounded-lg border '
            + (read
                ? 'border-green-300 text-green-600 bg-green-50 dark:bg-green-900/20'
                : 'border-line-strong text-ink-muted hover:bg-muted');
        btn.innerHTML = '<span aria-hidden="true">' + (read ? '●' : '○') + '</span>'
            + '<span class="hidden sm:inline">' + (read ? 'Leído' : 'Marcar como leído') + '</span>';
    }

    function renderFavToggle(btn, fav) {
        btn.dataset.fav = fav ? '1' : '0';
        btn.title = fav ? 'Quitar favorito' : 'Añadir a favoritos';
        btn.className = 'u42-fav-toggle inline-flex items-center gap-1 text-xs px-2 py-1 rounded-lg border '
            + (fav
                ? 'border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-900/20'
                : 'border-line-strong text-ink-muted hover:bg-muted');
        btn.textContent = fav ? '★ Quitar favorito' : '☆ Favorito';
    }

    document.addEventListener('click', function (ev) {
        var target = ev.target && ev.target.closest ? ev.target : null;
        if (!target) { return; }

        var readBtn = target.closest('.u42-read-toggle');
        if (readBtn) {
            ev.preventDefault();
            ev.stopPropagation();
            var id = parseInt(readBtn.dataset.id, 10) || 0;
            var read = readBtn.dataset.read === '1' ? 0 : 1;
            post(STATE_URL, {ids: [id], changes: {is_read: read}}).then(function (out) {
                if (!out.res.ok || !out.data.success) { return; }
                document.querySelectorAll('.u42-read-toggle[data-id="' + id + '"]').forEach(function (b) {
                    renderReadToggle(b, read);
                });
            });
            return;
        }

        var favBtn = target.closest('.u42-fav-toggle');
        if (favBtn) {
            ev.preventDefault();
            ev.stopPropagation();
            var fid = parseInt(favBtn.dataset.id, 10) || 0;
            var fav = favBtn.dataset.fav === '1' ? 0 : 1;
            post(STATE_URL, {ids: [fid], changes: {is_favorite: fav}}).then(function (out) {
                if (!out.res.ok || !out.data.success) { return; }
                document.querySelectorAll('.u42-fav-toggle[data-id="' + fid + '"]').forEach(function (b) {
                    renderFavToggle(b, fav);
                });
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
})();
</script>
