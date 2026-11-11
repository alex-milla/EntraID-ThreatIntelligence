<?php
/**
 * Vista: Equipos expuestos — informe de parcheo de servidores expuestos.
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
 */

$base = base_url('modules/exposed_report');
$inputClass = 'w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none';
$hasReport = trim((string)$reportMd) !== '';
$stats = is_array($stats ?? null) ? $stats : null;
$errors = is_array($errors ?? null) ? $errors : [];
$warnings = is_array($warnings ?? null) ? $warnings : [];
$profiles = is_array($profiles ?? null) ? $profiles : [];
$profileId = (int)($profileId ?? 0);
$mode = ((string)($mode ?? 'compact')) === 'detailed' ? 'detailed' : 'compact';
?>

<div class="page-header">
    <h1>Equipos expuestos</h1>
    <p class="subtitle">
        Informe de parcheo para los servidores que Defender marca como expuestos a Internet. Se genera
        únicamente con el CSV que exportes de Advanced Hunting: no se consulta ninguna otra fuente.
    </p>
    <span class="spacer"></span>
    <?php if ($isAdmin): ?>
        <a class="btn btn-outline" href="<?= e(base_url('admin/prompts')) ?>">
            <?= icon('edit_note', 16) ?> Editar prompts
        </a>
    <?php endif; ?>
</div>

<?php if (!$llmConfigured): ?>
    <div class="alert alert-error" role="status">
        La IA no está configurada. Revisa el perfil en
        <a href="<?= e(base_url('admin/apis')) ?>" class="underline">Admin → APIs</a>
        antes de generar informes.
    </div>
<?php endif; ?>

<?php if (!empty($error)): ?>
    <div class="alert alert-error" role="status"><?= e((string)$error) ?></div>
<?php endif; ?>

<?php if ($errors !== []): ?>
    <div class="alert alert-error" role="status">
        <strong>El CSV no se puede usar:</strong>
        <ul class="mt-2 mb-0 pl-5 list-disc">
            <?php foreach ($errors as $item): ?>
                <li><?= e((string)$item) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<!-- ============================================================
     Paso 1 · Consulta de origen
     ============================================================ -->
<div class="card mb-6 overflow-hidden">
    <div class="px-5 py-4 border-b border-line flex items-center justify-between gap-3 flex-wrap">
        <div>
            <h2 class="text-sm font-semibold m-0">1 · Consulta de origen</h2>
            <p class="text-xs text-ink-muted mt-1 mb-0">
                Ejecútala en <strong>Defender XDR → Hunting → Advanced Hunting</strong> y exporta el
                resultado con <em>Actions → Export (CSV)</em>. También puedes descargar el <code>.kql</code>.
            </p>
        </div>
        <div class="flex items-center gap-2">
            <button type="button" class="btn btn-outline" onclick="copyKql()">
                <?= icon('content_copy', 16) ?> Copiar
            </button>
            <button type="button" class="btn btn-outline" onclick="downloadKql()">
                <?= icon('download', 16) ?> .kql
            </button>
        </div>
    </div>
    <div class="p-5">
        <pre id="kql-text" class="m-0 p-4 rounded-lg bg-muted border border-line overflow-x-auto text-xs font-mono leading-relaxed"><?= e($kql) ?></pre>
    </div>
</div>

<!-- ============================================================
     Paso 2 · CSV y modo
     ============================================================ -->
<div class="card mb-6 p-5">
    <h2 class="text-sm font-semibold mb-1">2 · Generar el informe</h2>
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

        <div class="flex items-center gap-3 flex-wrap">
            <button type="submit" class="btn" <?= $llmConfigured ? '' : 'disabled' ?>>
                <?= icon('auto_awesome', 18) ?> Generar informe
            </button>
            <span class="text-[11px] text-ink-soft">
                La salida se muestra aquí mismo y se puede copiar o descargar en Markdown.
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
    <div class="alert alert-warning mb-6" role="status">
        <strong>Revisa el CSV:</strong> el informe se ha generado igualmente, pero hay datos incoherentes.
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

<!-- ============================================================
     Contexto del CSV (determinista, sin IA)
     ============================================================ -->
<?php if ($stats !== null && (int)($stats['servers'] ?? 0) > 0): ?>
    <div class="stat-strip mb-6">
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
        <div class="card mb-6 p-5">
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
    <div class="card overflow-hidden">
        <div class="px-5 py-4 border-b border-line flex items-center justify-between gap-3 flex-wrap no-print">
            <div>
                <h2 class="text-sm font-semibold m-0">Informe generado</h2>
                <p class="text-xs text-ink-soft mt-1 mb-0">
                    Modo <?= $mode === 'detailed' ? 'detallado' : 'compacto' ?><?php if ($filename !== ''): ?> · <?= e($filename) ?><?php endif; ?><?php if ($elapsedMs > 0): ?> · <?= (int)$elapsedMs ?> ms<?php endif; ?>
                </p>
            </div>
            <div class="flex items-center gap-2">
                <button type="button" class="btn btn-outline" onclick="copyReport()">
                    <?= icon('content_copy', 16) ?> Copiar
                </button>
                <button type="button" class="btn" onclick="downloadReport()">
                    <?= icon('download', 16) ?> Descargar .md
                </button>
            </div>
        </div>
        <div class="p-5 md-body">
            <?= $reportHtml ?>
        </div>
    </div>
    <textarea id="report-md" class="hidden" readonly aria-hidden="true"><?= e($reportMd) ?></textarea>
<?php endif; ?>

<script>
(function () {
    var KQL_TEXT = <?= json_encode($kql, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var REPORT_NAME = <?= json_encode((string)$downloadName, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

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

    window.copyKql = function () {
        copyText(KQL_TEXT, 'Consulta KQL copiada');
    };

    window.downloadKql = function () {
        App.downloadFile(KQL_TEXT, 'equipos-internet-exposed.kql', 'text/plain');
    };

    window.copyReport = function () {
        var field = document.getElementById('report-md');
        if (!field) { return; }
        copyText(field.value, 'Informe copiado al portapapeles');
    };

    window.downloadReport = function () {
        var field = document.getElementById('report-md');
        if (!field) { return; }
        App.downloadFile(field.value, REPORT_NAME || 'informe-parcheo.md', 'text/markdown');
    };
})();
</script>
