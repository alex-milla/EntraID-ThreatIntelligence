<?php
/**
 * Panel de feeds externos — Seguimiento TI TF (v0.4.29.1).
 *
 * @var Module_TiTracker $module
 * @var array $published listas habilitadas para la API
 * @var array $tokens tokens existentes
 * @var array $taxiiRequests últimas peticiones TAXII recibidas
 * @var array $formats
 * @var array $scopes
 * @var array $types
 * @var string $newToken secreto recién creado (se muestra una sola vez)
 * @var array|null $notice
 */

$base = base_url('modules/ti_tracker');
$apiBase = base_url('api/ti-tf');
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
$host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
$apiRootUrl = $https ? 'https://' : 'http://';
$apiRootUrl .= $host . rtrim((string)parse_url((string)base_url('api/taxii2/ti-tf'), PHP_URL_PATH), '/');
$fmt = static fn(int|float $n): string => number_format((float)$n, 0, ',', '.');
$short = static fn(?string $date): string => $date === null || trim($date) === ''
    ? '—'
    : substr(trim($date), 0, 16);

$feedOptions = [
    'lists'  => array_map(static fn(array $s): array => [
        'id'   => (int)$s['id'],
        'slug' => (string)$s['slug'],
        'name' => (string)$s['name'],
    ], $published),
    'base'   => $apiBase,
];
?>
<div class="page-header">
    <h1>API / Feeds externos</h1>
    <p class="subtitle">
        Publica las búsquedas de Seguimiento TI TF como listas de indicadores
        para Sentinel, Defender, MISP o firewalls EDL.
    </p>
    <span class="spacer"></span>
    <a class="btn-flat btn" href="<?= e($base) ?>">
        <?= icon('arrow_back', 18) ?> Volver
    </a>
</div>

<?php if (!empty($notice) && is_array($notice)): ?>
    <div class="alert alert-<?= e((string)($notice['type'] ?? 'info')) ?>" role="status">
        <?= e((string)($notice['text'] ?? '')) ?>
    </div>
<?php endif; ?>

<?php if ($newToken !== ''): ?>
    <div class="alert alert-success" role="status">
        <strong>Token creado.</strong> Cópialo ahora: por seguridad no se volverá a mostrar.
        <div class="mt-2 flex flex-wrap items-center gap-2">
            <code class="break-all" id="tf-new-token"><?= e($newToken) ?></code>
            <button type="button" class="btn-tiny btn-outline btn" data-tf-copy="tf-new-token">
                <?= icon('content_copy', 14) ?> Copiar
            </button>
        </div>
    </div>
<?php endif; ?>

<div class="card mt-6">
    <div class="card-head">
        <h2>Listas publicadas</h2>
    </div>
    <?php if ($published === []): ?>
        <p class="text-sm text-ink-muted p-4 m-0">
            No hay listas publicadas. Activa el interruptor <strong>API</strong>
            en el listado de búsquedas.
        </p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="data-table w-full">
                <thead>
                    <tr>
                        <th>Búsqueda</th>
                        <th>Slug</th>
                        <th>Collection ID (TAXII)</th>
                        <th>IOCs</th>
                        <th class="col-secondary">Última ejecución</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($published as $search): ?>
                    <tr>
                        <td><strong><?= e((string)$search['name']) ?></strong></td>
                        <td class="font-mono text-xs"><?= e((string)$search['slug']) ?></td>
                        <td>
                            <div class="flex flex-wrap items-center gap-2">
                                <code class="text-xs" id="tf-col-<?= (int)$search['id'] ?>"><?= e(TiTrackerFeed::collectionId((int)$search['id'])) ?></code>
                                <button type="button" class="btn-tiny btn-outline btn"
                                        data-tf-copy="tf-col-<?= (int)$search['id'] ?>"
                                        title="Copiar Collection ID para Sentinel">
                                    <?= icon('content_copy', 14) ?>
                                </button>
                            </div>
                            <div class="text-xs text-ink-muted mt-1">
                                o el slug: <code><?= e((string)$search['slug']) ?></code>
                            </div>
                        </td>
                        <td><?= $fmt((int)($search['tracked'] ?? 0)) ?></td>
                        <td class="col-secondary text-xs"><?= e($short($search['last_run_at'] ?? null)) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<div class="card mt-6">
    <div class="card-head">
        <h2>Conexión Microsoft Sentinel (TAXII 2.1)</h2>
    </div>
    <div class="p-4">
        <p class="text-sm text-ink-muted mt-0 mb-3">
            En <em>Data Connectors → Threat Intelligence – TAXII</em> pega estos
            valores. Rellena <strong>Username y Password con el token</strong>:
            el botón <strong>Add</strong> de Azure no se habilita si Username
            está vacío y Password tiene texto.
        </p>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
                <label for="tf-api-root">API root URL</label>
                <div class="flex flex-wrap items-center gap-2">
                    <input id="tf-api-root" class="flex-1 font-mono text-xs" readonly
                           value="<?= e($apiRootUrl) ?>">
                    <button type="button" class="btn-tiny btn-outline btn" data-tf-copy="tf-api-root">
                        <?= icon('content_copy', 14) ?> Copiar
                    </button>
                </div>
            </div>
            <div>
                <label for="tf-all-collection">Collection ID (todas las listas)</label>
                <div class="flex flex-wrap items-center gap-2">
                    <input id="tf-all-collection" class="flex-1 font-mono text-xs" readonly
                           value="<?= e(TiTrackerFeed::collectionId()) ?>">
                    <button type="button" class="btn-tiny btn-outline btn" data-tf-copy="tf-all-collection">
                        <?= icon('content_copy', 14) ?> Copiar
                    </button>
                </div>
            </div>
        </div>
        <p class="text-xs text-ink-muted mt-3 mb-0">
            Como <strong>Collection ID</strong> puedes poner <code>all</code>
            (todas las listas), el <strong>slug</strong> de una lista
            (p. ej. <code>gta6</code> o <code>github</code>), su nombre, su id
            numérico o el UUID de la tabla de arriba. El servidor es de solo
            lectura y el conector avanza el cursor con <code>added_after</code>.
        </p>
    </div>
</div>

<div class="card mt-6">
    <div class="card-head">
        <h2>Tokens de API</h2>
    </div>
    <div class="overflow-x-auto">
        <table class="data-table w-full">
            <thead>
                <tr>
                    <th>Nombre</th>
                    <th>Alcance</th>
                    <th class="col-secondary">Creado</th>
                    <th class="col-secondary">Caduca</th>
                    <th class="col-secondary">Último uso</th>
                    <th class="text-right">Acciones</th>
                </tr>
            </thead>
            <tbody>
            <?php if ($tokens === []): ?>
                <tr>
                    <td colspan="6" class="text-sm text-ink-muted">
                        No hay tokens. Crea uno con el formulario de abajo.
                    </td>
                </tr>
            <?php else: ?>
                <?php foreach ($tokens as $token): ?>
                    <tr>
                        <td>
                            <strong><?= e((string)$token['name']) ?></strong>
                            <?php if (!empty($token['ti_scope'])): ?>
                                <span class="tag-chip good">TI TF</span>
                            <?php endif; ?>
                        </td>
                        <td class="text-xs"><?= e((string)($token['summary'] ?? '')) ?></td>
                        <td class="col-secondary text-xs"><?= e($short((string)($token['created_at'] ?? ''))) ?></td>
                        <td class="col-secondary text-xs"><?= e($short((string)($token['expires_at'] ?? ''))) ?></td>
                        <td class="col-secondary text-xs"><?= e($short((string)($token['last_used_at'] ?? ''))) ?></td>
                        <td class="text-right whitespace-nowrap">
                            <form method="POST" action="<?= e($base . '/api/token/delete/' . (int)$token['id']) ?>"
                                  class="inline"
                                  data-confirm="¿Revocar el token «<?= e((string)$token['name']) ?>»? Dejará de funcionar al instante."
                                  data-confirm-danger>
                                <?= Csrf::field() ?>
                                <button type="submit" class="btn-tiny btn-outline btn">Revocar</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="card mt-6">
    <div class="card-head">
        <h2>Crear token</h2>
    </div>
    <form method="POST" action="<?= e($base . '/api/token') ?>" class="p-4">
        <?= Csrf::field() ?>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
                <label for="tf-token-name">Nombre</label>
                <input id="tf-token-name" name="name" required maxlength="80"
                       placeholder="Ej. Sentinel Producción">
            </div>
            <div>
                <label for="tf-token-days">Caducidad (días, vacío = nunca)</label>
                <input id="tf-token-days" name="expires_days" type="number" min="1" max="3650" placeholder="365">
            </div>
        </div>

        <div class="mt-4">
            <label class="inline-flex items-center gap-2">
                <input type="checkbox" name="all_lists" value="1" id="tf-all-lists" checked>
                Todas las listas publicadas
            </label>
            <p class="text-xs text-ink-muted mt-1">
                Si lo desmarcas, el token solo podrá leer las listas que marques aquí:
            </p>
            <div class="flex flex-wrap gap-3 mt-2" id="tf-list-checks">
                <?php foreach ($published as $search): ?>
                    <label class="inline-flex items-center gap-1 text-sm">
                        <input type="checkbox" name="search_ids[]" value="<?= (int)$search['id'] ?>">
                        <?= e((string)$search['name']) ?>
                    </label>
                <?php endforeach; ?>
                <?php if ($published === []): ?>
                    <span class="text-xs text-ink-muted">No hay listas publicadas.</span>
                <?php endif; ?>
            </div>
        </div>

        <div class="mt-4">
            <label class="inline-flex items-center gap-2">
                <input type="checkbox" name="allow_query_token" value="1">
                Permitir el token en la URL (<code>?token=</code>) — solo para firewalls EDL
            </label>
        </div>

        <div class="mt-4">
            <button type="submit" class="btn">
                <?= icon('add', 18) ?> Crear token
            </button>
        </div>
    </form>
</div>

<div class="card mt-6">
    <div class="card-head">
        <h2>Diagnóstico TAXII (últimas peticiones)</h2>
    </div>
    <?php if ($taxiiRequests === []): ?>
        <p class="text-sm text-ink-muted p-4 m-0">
            Todavía no ha llegado ninguna petición a <code>/api/taxii2/*</code>.
            Pulsa <strong>Add</strong> en Microsoft Sentinel y recarga esta página
            para ver si la llamada llegó y qué respondió el servidor.
        </p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="data-table w-full">
                <thead>
                    <tr>
                        <th>Fecha</th>
                        <th>Origen</th>
                        <th>Ruta</th>
                        <th class="col-secondary">Accept</th>
                        <th>Auth</th>
                        <th>HTTP</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($taxiiRequests as $req): ?>
                    <tr>
                        <td class="whitespace-nowrap text-xs"><?= e($short((string)$req['created_at'])) ?></td>
                        <td class="text-xs font-mono"><?= e((string)$req['ip']) ?></td>
                        <td class="text-xs break-all"><?= e(truncate((string)$req['path'], 90)) ?></td>
                        <td class="col-secondary text-xs text-ink-muted">
                            <?= e(truncate((string)$req['accept'], 70)) ?>
                        </td>
                        <td>
                            <span class="tag-chip <?= !empty($req['auth_ok']) ? 'good' : 'excluded' ?>">
                                <?= !empty($req['auth_ok']) ? 'OK' : '401' ?>
                            </span>
                        </td>
                        <td><?= (int)$req['status'] ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<div class="card mt-6">
    <div class="card-head">
        <h2>Constructor de feed</h2>
    </div>
    <div class="p-4" id="tf-builder">
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
                <label for="tf-format">Formato</label>
                <select id="tf-format">
                    <?php foreach ($formats as $format): ?>
                        <option value="<?= e($format) ?>"><?= e(strtoupper($format)) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label for="tf-scope">Alcance</label>
                <select id="tf-scope">
                    <?php foreach ($scopes as $scope): ?>
                        <option value="<?= e($scope) ?>"><?= e($scope) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label for="tf-type">Tipo de IOC</label>
                <select id="tf-type">
                    <?php foreach ($types as $type): ?>
                        <option value="<?= e($type) ?>"><?= e($type) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label for="tf-since">Desde (ISO-8601, opcional)</label>
                <input id="tf-since" placeholder="2026-11-23T00:00:00Z">
            </div>
        </div>

        <div class="mt-4">
            <p class="text-sm font-medium mb-2">Listas incluidas</p>
            <?php foreach ($published as $search): ?>
                <label class="inline-flex items-center gap-2 mr-4 text-sm">
                    <input type="checkbox" class="tf-feed-list" value="<?= e((string)$search['slug']) ?>" checked>
                    <?= e((string)$search['name']) ?>
                </label>
            <?php endforeach; ?>
            <?php if ($published === []): ?>
                <span class="text-xs text-ink-muted">Publica alguna lista para generar una URL.</span>
            <?php endif; ?>
        </div>

        <div class="mt-4">
            <label for="tf-url">URL del feed</label>
            <div class="flex flex-wrap items-center gap-2">
                <input id="tf-url" class="flex-1 font-mono text-xs" readonly>
                <button type="button" class="btn-tiny btn-outline btn" data-tf-copy="tf-url">
                    <?= icon('content_copy', 14) ?> Copiar
                </button>
            </div>
            <p class="text-xs text-ink-muted mt-1">
                Sustituye <code>&lt;TOKEN&gt;</code> por el secreto del token. La sesión web
                también puede consultar la URL sin token.
            </p>
        </div>

        <div class="mt-4">
            <label for="tf-curl">Ejemplo con curl</label>
            <pre id="tf-curl" class="text-xs break-all p-3 bg-muted rounded"></pre>
            <button type="button" class="btn-tiny btn-outline btn mt-2" data-tf-copy="tf-curl">
                <?= icon('content_copy', 14) ?> Copiar curl
            </button>
        </div>
    </div>
</div>

<script>
(function () {
    'use strict';
    var config = <?= json_encode($feedOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    function val(id) {
        var el = document.getElementById(id);
        return el ? String(el.value || '').trim() : '';
    }

    function checkedValues(selector) {
        var out = [];
        document.querySelectorAll(selector).forEach(function (el) {
            if (el.checked && String(el.value || '').trim() !== '') { out.push(el.value.trim()); }
        });
        return out;
    }

    function build() {
        var lists = checkedValues('.tf-feed-list');
        var url = config.base + '/indicators?lists=' + (lists.length ? lists.join(',') : 'all')
            + '&format=' + encodeURIComponent(val('tf-format'))
            + '&scope=' + encodeURIComponent(val('tf-scope'))
            + '&type=' + encodeURIComponent(val('tf-type'));
        var since = val('tf-since');
        if (since !== '') { url += '&since=' + encodeURIComponent(since); }

        var urlEl = document.getElementById('tf-url');
        var curlEl = document.getElementById('tf-curl');
        if (urlEl) { urlEl.value = url; }
        if (curlEl) {
            curlEl.textContent = 'curl -H "Authorization: Bearer <TOKEN>" \\\n  "' + url + '"';
        }
    }

    ['tf-format', 'tf-scope', 'tf-type', 'tf-since'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) { el.addEventListener('change', build); }
    });
    document.querySelectorAll('.tf-feed-list').forEach(function (el) {
        el.addEventListener('change', build);
    });
    build();

    var all = document.getElementById('tf-all-lists');
    if (all) {
        all.addEventListener('change', function () {
            document.querySelectorAll('#tf-list-checks input').forEach(function (el) {
                if (all.checked) { el.checked = false; }
            });
        });
    }

    document.addEventListener('click', function (event) {
        var copy = event.target.closest('[data-tf-copy]');
        if (!copy) { return; }
        var source = document.getElementById(copy.getAttribute('data-tf-copy'));
        var text = source ? (source.value !== undefined ? source.value : source.textContent) : '';
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
            toast('El portapapeles no está disponible', 'warning');
            return;
        }
        navigator.clipboard.writeText(text)
            .then(function () { toast('Copiado al portapapeles', 'success'); })
            .catch(function () { toast('No se pudo copiar', 'error'); });
    });
})();
</script>
