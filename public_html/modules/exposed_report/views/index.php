<?php
/**
 * Vista: Equipos expuestos — informe de parcheo de servidores expuestos.
 *
 * La salida se presenta como una hoja de documento (blanca, independiente del
 * tema) para que se pueda copiar con formato a un email o Word, descargar en
 * Markdown/HTML o imprimir en PDF.
 *
 * @var Module_ExposedReport $module
 * @var array $profiles
 * @var int|null $defaultProfileId
 * @var int|null $profileId
 * @var bool $llmConfigured
 * @var bool $isAdmin
 * @var string $kql
 * @var array $columns
 * @var string $maxUploadLabel
 * @var int $maxRows
 * @var string|null $error
 * @var array $errors
 * @var array $warnings
 * @var int $warningsTotal
 * @var array|null $stats
 * @var string $reportMd
 * @var string $reportHtml
 * @var string $mode
 * @var string $filename
 * @var int $elapsedMs
 * @var string $downloadName
 * @var string $enrich
 * @var string|null $enrichNotice
 * @var array $enrichSources
 * @var bool $catalogAvailable
 * @var bool $inventoryAvailable
 */

$base = base_url('modules/exposed_report');
$inputClass = 'w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none';
$hasReport = trim((string)$reportMd) !== '';
$stats = is_array($stats ?? null) ? $stats : null;
$errors = is_array($errors ?? null) ? $errors : [];
$warnings = is_array($warnings ?? null) ? $warnings : [];
$profiles = is_array($profiles ?? null) ? $profiles : [];
$enrichSources = is_array($enrichSources ?? null) ? $enrichSources : [];
$profileId = (int)($profileId ?? 0);
$mode = ((string)($mode ?? 'compact')) === 'detailed' ? 'detailed' : 'compact';
$enrich = (string)($enrich ?? 'catalog');
$enrichNotice = $enrichNotice ?? null;
?>

<div class="page-header no-print">
    <h1>Equipos expuestos</h1>
    <p class="subtitle">
        Informe de parcheo para los servidores que Defender marca como expuestos a Internet. Se genera
        con el CSV que exportes de Advanced Hunting y, si lo pides, con el detalle de sus CVE.
    </p>
    <span class="spacer"></span>
    <?php if ($isAdmin): ?>
        <a class="btn btn-outline" href="<?= e(base_url('admin/prompts')) ?>">
            <?= icon('edit_note', 16) ?> Editar prompts
        </a>
    <?php endif; ?>
</div>

<?php if (!$llmConfigured): ?>
    <div class="alert alert-error no-print" role="status">
        La IA no está configurada. Revisa el perfil en
        <a href="<?= e(base_url('admin/apis')) ?>" class="underline">Admin → APIs</a>
        antes de generar informes.
    </div>
<?php endif; ?>

<?php if (!empty($error)): ?>
    <div class="alert alert-error no-print" role="status"><?= e((string)$error) ?></div>
<?php endif; ?>

<?php if ($errors !== []): ?>
    <div class="alert alert-error no-print" role="status">
        <strong>El CSV no se puede usar:</strong>
        <ul class="mt-2 mb-0 pl-5 list-disc">
            <?php foreach ($errors as $item): ?>
                <li><?= e((string)$item) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<!-- ============================================================
     Generar el informe
     ============================================================ -->
<div class="card mb-6 p-5 no-print">
    <h2 class="text-sm font-semibold mb-1">Generar el informe</h2>
    <p class="text-xs text-ink-muted mt-1 mb-4">
        Máximo <?= e($maxUploadLabel) ?> y <?= (int)$maxRows ?> servidores por informe.
        El CSV debe traer las <?= count($columns) ?> columnas del contrato, en ese orden.
    </p>

    <form method="POST" action="<?= e($base . '/generate') ?>" enctype="multipart/form-data" class="space-y-4">
        <?= Csrf::field() ?>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div>
                <label for="csv" class="block text-xs font-medium text-ink-muted mb-1">
                    CSV exportado por Advanced Hunting
                </label>
                <input id="csv" type="file" name="csv" accept=".csv,.txt,text/csv,text/plain" required
                       class="block w-full text-sm text-ink file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-brand-500 file:text-white file:text-xs file:font-semibold hover:file:bg-brand-600 border border-line-strong rounded-lg bg-input">
                <?php if ($filename !== '' && $stats !== null): ?>
                    <p class="mt-1 text-[11px] text-ink-soft">Último fichero: <?= e($filename) ?></p>
                <?php endif; ?>
            </div>

            <div>
                <label for="profile_id" class="block text-xs font-medium text-ink-muted mb-1">
                    Perfil de IA
                </label>
                <select id="profile_id" name="profile_id" class="<?= e($inputClass) ?>">
                    <option value="0">— Perfil predeterminado —</option>
                    <?php foreach ($profiles as $profile): ?>
                        <?php $pid = (int)($profile['id'] ?? 0); ?>
                        <option value="<?= $pid ?>" <?= $pid === $profileId ? 'selected' : '' ?>>
                            <?= e((string)($profile['name'] ?? ('Perfil ' . $pid))) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>

        <fieldset class="border-0 p-0 m-0">
            <legend class="text-xs font-medium text-ink-muted mb-2">Modo del informe</legend>
            <div class="flex flex-col sm:flex-row gap-3">
                <label class="flex items-start gap-2 px-4 py-3 rounded-lg border border-line cursor-pointer hover:bg-muted">
                    <input type="radio" name="mode" value="compact" class="mt-0.5" <?= $mode === 'compact' ? 'checked' : '' ?>>
                    <span>
                        <span class="block text-sm font-medium">Compacto</span>
                        <span class="block text-[11px] text-ink-soft">Resumen + tabla + 3 acciones. Para email y seguimiento interno.</span>
                    </span>
                </label>
                <label class="flex items-start gap-2 px-4 py-3 rounded-lg border border-line cursor-pointer hover:bg-muted">
                    <input type="radio" name="mode" value="detailed" class="mt-0.5" <?= $mode === 'detailed' ? 'checked' : '' ?>>
                    <span>
                        <span class="block text-sm font-medium">Detallado</span>
                        <span class="block text-[11px] text-ink-soft">8 secciones y anexos, con el JSON de especificación. Para cliente o dirección.</span>
                    </span>
                </label>
            </div>
        </fieldset>

        <div>
            <label for="enrich" class="block text-xs font-medium text-ink-muted mb-1">
                Detalle de CVE <span class="text-ink-soft">(solo en modo detallado)</span>
            </label>
            <select id="enrich" name="enrich" class="<?= e($inputClass) ?>">
                <?php foreach ($enrichSources as $key => $label): ?>
                    <?php
                    $isInventory = $key === 'inventory';
                    $disabled = $isInventory && !$inventoryAvailable;
                    $suffix = '';
                    if ($isInventory && !$inventoryAvailable) {
                        $suffix = ' — sin inventario sincronizado';
                    } elseif ($key === 'catalog' && !$catalogAvailable) {
                        $suffix = ' — catálogo vacío';
                    }
                    ?>
                    <option value="<?= e((string)$key) ?>"
                            <?= (string)$enrich === (string)$key ? 'selected' : '' ?>
                            <?= $disabled ? 'disabled' : '' ?>>
                        <?= e((string)$label . $suffix) ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <p class="mt-1 text-[11px] text-ink-soft">
                Añade un anexo con los datos de los CVE (severidad, CVSS, EPSS, KEV y exploit).
                El inventario del tenant requiere que el módulo Vulnerabilidades esté sincronizado.
            </p>
        </div>

        <div class="flex items-center gap-3 flex-wrap">
            <button type="submit" class="btn" <?= $llmConfigured ? '' : 'disabled' ?>>
                <?= icon('auto_awesome', 18) ?> Generar informe
            </button>
            <span class="text-[11px] text-ink-soft">
                La salida se muestra como documento y se puede copiar con formato, descargar o imprimir.
            </span>
        </div>
    </form>

    <details class="mt-4">
        <summary class="cursor-pointer text-xs font-medium text-ink-muted">Contrato de columnas (<?= count($columns) ?>)</summary>
        <div class="mt-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-1">
            <?php foreach ($columns as $index => $column): ?>
                <p class="text-[11px] m-0"><span class="text-ink-soft"><?= $index + 1 ?>.</span> <code class="font-mono"><?= e($column) ?></code></p>
            <?php endforeach; ?>
        </div>
    </details>
</div>

<!-- ============================================================
     Avisos de validación
     ============================================================ -->
<?php if ($warnings !== []): ?>
    <div class="alert alert-warning mb-6 no-print" role="status">
        <strong>Revisa los datos:</strong> el informe se ha generado igualmente, pero hay incoherencias.
        <?php if ($warningsTotal > count($warnings)): ?>
            Se muestran <?= count($warnings) ?> de <?= (int)$warningsTotal ?> avisos.
        <?php endif; ?>
        <ul class="mt-2 mb-0 pl-5 list-disc">
            <?php foreach (array_slice($warnings, 0, 12) as $item): ?>
                <li><?= e((string)$item) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<?php if ($hasReport && is_string($enrichNotice) && $enrichNotice !== ''): ?>
    <div class="alert alert-info mb-6 no-print" role="status"><?= e($enrichNotice) ?></div>
<?php endif; ?>

<!-- ============================================================
     Contexto del CSV (determinista, sin IA)
     ============================================================ -->
<?php if ($stats !== null && (int)($stats['servers'] ?? 0) > 0): ?>
    <div class="stat-strip mb-6 no-print">
        <div class="stat">
            <span class="stat-ico"><i class="material-icons icon-18" aria-hidden="true">dns</i></span>
            <div class="min-w-0">
                <p class="stat-num"><?= (int)$stats['servers'] ?></p>
                <p class="stat-label">Servidores · <?= (int)$stats['high'] ?> High / <?= (int)$stats['medium'] ?> Medium</p>
            </div>
        </div>
        <div class="stat">
            <span class="stat-ico warn"><i class="material-icons icon-18" aria-hidden="true">bolt</i></span>
            <div class="min-w-0">
                <p class="stat-num"><?= (int)$stats['with_exploit'] ?></p>
                <p class="stat-label">Con exploit público</p>
            </div>
        </div>
        <div class="stat">
            <span class="stat-ico info"><i class="material-icons icon-18" aria-hidden="true">bug_report</i></span>
            <div class="min-w-0">
                <p class="stat-num"><?= (int)$stats['cves_total'] ?></p>
                <p class="stat-label">CVEs · <?= (int)$stats['critical_total'] ?> críticos</p>
            </div>
        </div>
        <div class="stat">
            <span class="stat-ico ok"><i class="material-icons icon-18" aria-hidden="true">schedule</i></span>
            <div class="min-w-0">
                <p class="stat-num"><?= (int)$stats['max_days'] ?></p>
                <p class="stat-label">Días sin parchear (máx.)<?= ($stats['oldest_label'] ?? '') !== '' ? ' · desde ' . e((string)$stats['oldest_label']) : '' ?></p>
            </div>
        </div>
    </div>

    <?php if (!empty($stats['packages'])): ?>
        <div class="card mb-6 p-5 no-print">
            <h2 class="text-sm font-semibold mb-2">Ciclos de parcheo pendientes en el CSV</h2>
            <p class="text-xs text-ink-muted mt-1 mb-3">
                Paquetes mensuales deduplicados (se ignoran los sufijos «Last updated at …»).
            </p>
            <div class="flex flex-wrap gap-2">
                <?php foreach (array_slice((array)$stats['packages'], 0, 18) as $package): ?>
                    <span class="inline-flex px-2 py-1 text-[11px] rounded-lg bg-muted border border-line"><?= e((string)$package) ?></span>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endif; ?>
<?php endif; ?>

<!-- ============================================================
     Informe
     ============================================================ -->
<?php if ($hasReport): ?>
    <div class="card overflow-hidden doc-card">
        <div class="doc-toolbar no-print px-5 py-4 border-b border-line flex items-center justify-between gap-3 flex-wrap">
            <div class="min-w-0">
                <h2 class="text-sm font-semibold m-0">Informe generado</h2>
                <p class="text-xs text-ink-soft mt-1 mb-0">
                    Modo <?= $mode === 'detailed' ? 'detallado' : 'compacto' ?>
                    <?php if ($mode === 'detailed' && $enrich !== 'none'): ?>
                        · detalle de CVE: <?= e((string)($enrichSources[$enrich] ?? '')) ?>
                    <?php endif; ?>
                    <?php if ($filename !== ''): ?> · <?= e($filename) ?><?php endif; ?>
                    <?php if ($elapsedMs > 0): ?> · <?= (int)$elapsedMs ?> ms<?php endif; ?>
                </p>
            </div>
            <div class="flex items-center gap-2 flex-wrap">
                <div class="doc-views flex items-center gap-1 p-1 rounded-lg bg-muted" role="tablist" aria-label="Vista del informe">
                    <button type="button" id="doc-tab-document" onclick="showDocView('document')"
                            class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-surface text-ink shadow-sm">
                        Documento
                    </button>
                    <button type="button" id="doc-tab-markdown" onclick="showDocView('markdown')"
                            class="px-3 py-1.5 text-xs font-medium rounded-lg text-ink-muted hover:bg-muted">
                        Markdown
                    </button>
                </div>
                <button type="button" class="btn" onclick="copyRich()">
                    <?= icon('content_copy', 16) ?> Copiar informe
                </button>
                <button type="button" class="btn btn-outline" onclick="copyMarkdown()">
                    Copiar Markdown
                </button>
                <button type="button" class="btn btn-outline" onclick="downloadHtml()"
                        title="Descargar HTML con estilos: se abre en Word">
                    <?= icon('html', 16) ?> .html
                </button>
                <button type="button" class="btn btn-outline" onclick="downloadMd()"
                        title="Descargar Markdown">
                    <?= icon('download', 16) ?> .md
                </button>
                <button type="button" class="btn btn-outline" onclick="printReport()"
                        title="Imprimir o guardar como PDF">
                    <?= icon('print', 16) ?> PDF
                </button>
            </div>
        </div>

        <div class="doc-stage p-5">
            <div id="doc-view-document">
                <div id="doc-sheet" class="doc-sheet"><?= $reportHtml ?></div>
            </div>
            <div id="doc-view-markdown" hidden>
                <pre id="doc-raw" class="doc-raw"><?= e($reportMd) ?></pre>
            </div>
        </div>
    </div>
<?php endif; ?>

<!-- ============================================================
     Notas técnicas (KQL de origen)
     ============================================================ -->
<div class="card mt-6 overflow-hidden no-print">
    <details>
        <summary class="px-5 py-4 cursor-pointer text-sm font-semibold">
            Notas técnicas · consulta de origen (KQL)
        </summary>
        <div class="px-5 pb-5">
            <p class="text-xs text-ink-muted mt-0 mb-3">
                Ejecútala en <strong>Defender XDR → Hunting → Advanced Hunting</strong> y exporta el
                resultado con <em>Actions → Export (CSV)</em>. Es el origen de los datos del informe.
            </p>
            <pre id="kql-text" class="m-0 p-4 rounded-lg bg-muted border border-line overflow-x-auto text-xs font-mono leading-relaxed"><?= e($kql) ?></pre>
            <div class="mt-3 flex items-center gap-2">
                <button type="button" class="btn btn-outline" onclick="copyKql()">
                    <?= icon('content_copy', 16) ?> Copiar KQL
                </button>
                <button type="button" class="btn btn-outline" onclick="downloadKql()">
                    <?= icon('download', 16) ?> .kql
                </button>
            </div>
        </div>
    </details>
</div>

<script>
(function () {
    var KQL_TEXT = <?= json_encode($kql, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var REPORT_NAME = <?= json_encode((string)$downloadName, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var HTML_NAME = REPORT_NAME ? REPORT_NAME.replace(/\.md$/i, '.html') : 'informe-parcheo.html';

    var DOC_STYLES = {
        h1: 'font-size:22px;font-weight:700;color:#0f172a;margin:20px 0 8px;',
        h2: 'font-size:18px;font-weight:700;color:#0f172a;margin:20px 0 8px;border-bottom:1px solid #e5e7eb;padding-bottom:4px;',
        h3: 'font-size:16px;font-weight:700;color:#0f172a;margin:18px 0 6px;',
        h4: 'font-size:15px;font-weight:600;color:#0f172a;margin:16px 0 6px;',
        p: 'margin:10px 0;',
        table: 'width:100%;border-collapse:collapse;margin:14px 0;font-size:14px;',
        th: 'border:1px solid #d1d5db;background:#f3f4f6;padding:6px 9px;text-align:left;font-weight:600;',
        td: 'border:1px solid #d1d5db;padding:6px 9px;text-align:left;vertical-align:top;',
        strong: 'font-weight:600;color:#0f172a;',
        code: 'font-family:Consolas,Menlo,monospace;font-size:13px;background:#f3f4f6;padding:1px 4px;border-radius:3px;',
        pre: 'background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:10px;overflow:auto;',
        blockquote: 'margin:12px 0;padding:8px 14px;border-left:3px solid #f59e0b;background:#fffbeb;color:#78350f;',
        hr: 'border:0;border-top:1px solid #e5e7eb;margin:18px 0;',
        ul: 'margin:10px 0;padding-left:22px;list-style:disc;',
        ol: 'margin:10px 0;padding-left:22px;list-style:decimal;',
        li: 'margin:4px 0;',
        a: 'color:#b45309;text-decoration:none;'
    };

    function legacyCopy(text, okMessage) {
        var area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', 'readonly');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try {
            document.execCommand('copy');
            toast(okMessage, 'success');
        } catch (err) {
            toast('No se pudo copiar', 'error');
        }
        document.body.removeChild(area);
    }

    function copyText(text, okMessage) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(function () {
                toast(okMessage, 'success');
            }).catch(function () {
                legacyCopy(text, okMessage);
            });
            return;
        }
        legacyCopy(text, okMessage);
    }

    /* Fragmento HTML con estilos en línea: sirve para el portapapeles y para
       el .html. Se evita <style> porque algunos clientes de correo lo quitan. */
    function styledFragment() {
        var sheet = document.getElementById('doc-sheet');
        if (!sheet) { return ''; }
        var clone = sheet.cloneNode(true);
        Object.keys(DOC_STYLES).forEach(function (selector) {
            var nodes = clone.querySelectorAll(selector);
            for (var i = 0; i < nodes.length; i++) {
                nodes[i].setAttribute('style', DOC_STYLES[selector]);
            }
        });
        return '<div style="font-family:Calibri,Arial,Helvetica,sans-serif;font-size:15px;line-height:1.65;color:#111827;">'
            + clone.innerHTML + '</div>';
    }

    function legacyCopyNode(node) {
        if (!node) { return; }
        var range = document.createRange();
        range.selectNodeContents(node);
        var selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        try {
            document.execCommand('copy');
            toast('Informe copiado con formato', 'success');
        } catch (err) {
            toast('No se pudo copiar el informe', 'error');
        }
        selection.removeAllRanges();
    }

    window.copyRich = function () {
        var sheet = document.getElementById('doc-sheet');
        if (!sheet) { return; }
        var fragment = styledFragment();
        var plain = sheet.innerText || '';

        if (navigator.clipboard && window.ClipboardItem && window.isSecureContext) {
            try {
                var item = new ClipboardItem({
                    'text/html': new Blob([fragment], { type: 'text/html' }),
                    'text/plain': new Blob([plain], { type: 'text/plain' })
                });
                navigator.clipboard.write([item]).then(function () {
                    toast('Informe copiado con formato', 'success');
                }).catch(function () {
                    legacyCopyNode(sheet);
                });
                return;
            } catch (err) {
                // Sin ClipboardItem: copia del DOM renderizado.
            }
        }
        legacyCopyNode(sheet);
    };

    window.copyMarkdown = function () {
        var field = document.getElementById('doc-raw');
        if (!field) { return; }
        copyText(field.textContent, 'Markdown copiado al portapapeles');
    };

    window.downloadMd = function () {
        var field = document.getElementById('doc-raw');
        if (!field) { return; }
        App.downloadFile(field.textContent, REPORT_NAME || 'informe-parcheo.md', 'text/markdown');
    };

    window.downloadHtml = function () {
        var fragment = styledFragment();
        if (!fragment) { return; }
        var html = '<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">'
            + '<title>Informe de parcheo de equipos expuestos</title></head>'
            + '<body style="margin:24px;background:#ffffff;">' + fragment + '</body></html>';
        App.downloadFile(html, HTML_NAME, 'text/html');
    };

    window.printReport = function () {
        window.print();
    };

    window.showDocView = function (view) {
        var documentView = document.getElementById('doc-view-document');
        var markdownView = document.getElementById('doc-view-markdown');
        var documentTab = document.getElementById('doc-tab-document');
        var markdownTab = document.getElementById('doc-tab-markdown');
        if (!documentView || !markdownView || !documentTab || !markdownTab) { return; }

        var isDocument = view !== 'markdown';
        documentView.hidden = !isDocument;
        markdownView.hidden = isDocument;

        var activeClass = 'px-3 py-1.5 text-xs font-semibold rounded-lg bg-surface text-ink shadow-sm';
        var idleClass = 'px-3 py-1.5 text-xs font-medium rounded-lg text-ink-muted hover:bg-muted';
        documentTab.className = isDocument ? activeClass : idleClass;
        markdownTab.className = isDocument ? idleClass : activeClass;
    };

    window.copyKql = function () {
        copyText(KQL_TEXT, 'Consulta KQL copiada');
    };

    window.downloadKql = function () {
        App.downloadFile(KQL_TEXT, 'equipos-internet-exposed.kql', 'text/plain');
    };
})();
</script>
