<?php
/**
 * Vista: Equipos expuestos — grupo de análisis y plan de actuación.
 *
 * @var array|null $group
 * @var int $groupId
 * @var array $rows
 * @var array|null $plan
 * @var array $profiles
 * @var int $profileId
 * @var bool $llmConfigured
 * @var string|null $error
 * @var string|null $queueNotice
 * @var bool $planFresh
 * @var int $elapsedMs
 * @var array|null $planContext
 * @var int $maxAnalysis
 * @var string $downloadName
 */

$base = base_url('modules/exposed_report');
$group = is_array($group ?? null) ? $group : null;
$rows = is_array($rows ?? null) ? $rows : [];
$plan = is_array($plan ?? null) ? $plan : null;
$profiles = is_array($profiles ?? null) ? $profiles : [];
$profileId = (int)($profileId ?? 0);
$error = $error ?? null;
$queueNotice = $queueNotice ?? null;
$planFresh = !empty($planFresh);
$elapsedMs = (int)($elapsedMs ?? 0);
$planContext = is_array($planContext ?? null) ? $planContext : null;
$maxAnalysis = (int)($maxAnalysis ?? 20);

$sevClasses = [
    'critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'high'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'info'     => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
];
$sevLabels = [
    'critical' => 'Crítica',
    'high'     => 'Alta',
    'medium'   => 'Media',
    'low'      => 'Baja',
    'info'     => 'Informativa',
];

$planText = $plan !== null ? (string)($plan['content_text'] ?? '') : '';
$planHtml = '';
if ($planText !== '') {
    $planHtml = function_exists('render_ai_markdown')
        ? render_ai_markdown($planText)
        : (function_exists('render_markdown') ? render_markdown($planText) : '<pre>' . e($planText) . '</pre>');
}

$filters = [];
if ($group !== null && (string)($group['filters_json'] ?? '') !== '') {
    $decoded = safe_json_decode((string)$group['filters_json'], []);
    $filters = is_array($decoded) ? $decoded : [];
}
$filterText = [];
foreach ($filters as $key => $value) {
    if (is_array($value)) {
        $filterText[] = $key . ': ' . implode('/', array_map('strval', $value));
    } elseif ((string)$value !== '') {
        $filterText[] = $key . ': ' . (string)$value;
    }
}

$fmtDate = static function (?string $value, string $format = 'd/m/Y H:i'): string {
    $value = trim((string)$value);
    if ($value === '') {
        return '—';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date($format, $ts);
};

$flashData = function_exists('flash') ? flash() : [];
$flashData = is_array($flashData) ? $flashData : [];
?>

<?php foreach (['success' => 'alert-success', 'error' => 'alert-error', 'info' => 'alert-info', 'warning' => 'alert-warning'] as $flashKey => $flashClass): ?>
    <?php if (!empty($flashData[$flashKey])): ?>
        <div class="alert <?= $flashClass ?> mb-5 no-print" role="status"><?= e((string)$flashData[$flashKey]) ?></div>
    <?php endif; ?>
<?php endforeach; ?>

<div class="page-header no-print">
    <div class="min-w-0">
        <a href="<?= e($base) ?>" class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline inline-flex items-center gap-1 mb-1">
            <?= icon('arrow_back', 13) ?> Volver a la consola
        </a>
        <h1 class="truncate"><?= e((string)($group['name'] ?? 'Grupo de análisis')) ?></h1>
        <p class="subtitle">
            <?= count($rows) ?> CVE
            <?php if ($filterText !== []): ?>
                · filtro: <?= e(implode(' · ', $filterText)) ?>
            <?php endif; ?>
        </p>
    </div>
    <span class="spacer"></span>
    <?php if ($group !== null): ?>
        <form method="POST" action="<?= e($base . '/group/' . (int)$group['id'] . '/delete') ?>"
              onsubmit="return confirm('¿Eliminar el grupo y su plan de actuación? Los CVE del catálogo no se tocan.');">
            <?= Csrf::field() ?>
            <button type="submit"
                    class="inline-flex items-center gap-1.5 px-3 py-2 border border-danger-border text-danger text-xs font-medium rounded-lg hover:bg-danger-bg transition-colors">
                <?= icon('delete', 14) ?> Eliminar grupo
            </button>
        </form>
    <?php endif; ?>
</div>

<?php if (is_string($error) && $error !== ''): ?>
    <div class="alert alert-error mb-5" role="status"><?= e($error) ?></div>
<?php endif; ?>

<?php if (is_string($queueNotice) && $queueNotice !== ''): ?>
    <div class="alert alert-info mb-5" role="status"><?= e($queueNotice) ?></div>
<?php endif; ?>

<?php if ($group !== null): ?>

    <!-- ============================================================
         Acciones del grupo
         ============================================================ -->
    <div class="card p-5 mb-6 no-print">
        <div class="flex items-start justify-between gap-4 flex-wrap">
            <div class="min-w-0 max-w-xl">
                <h2 class="text-sm font-semibold m-0">Plan de actuación del grupo</h2>
                <p class="text-xs text-ink-muted mt-1 mb-0">
                    La IA recibe el contexto TVM del grupo (severidad, antigüedad, equipos expuestos,
                    exploit/amenazas y software) y devuelve un plan por fases. La aplicación añade después el
                    anexo con todos los CVE y sus datos, para que cada cifra sea rastreable al export.
                </p>
                <?php if ($planContext !== null): ?>
                    <p class="text-[11px] text-ink-soft mt-2 mb-0">
                        Contexto enviado: <?= (int)($planContext['detailed'] ?? 0) ?> CVE en detalle de
                        <?= (int)($planContext['total'] ?? 0) ?>
                        <?php if ((int)($planContext['truncated'] ?? 0) > 0): ?>
                            · <?= (int)$planContext['truncated'] ?> quedan solo en el anexo
                        <?php endif; ?>
                        <?php if ($elapsedMs > 0): ?> · <?= (int)$elapsedMs ?> ms<?php endif; ?>
                    </p>
                <?php endif; ?>
            </div>

            <div class="flex items-end gap-2 flex-wrap">
                <form method="POST" action="<?= e($base . '/group/' . (int)$group['id'] . '/plan') ?>"
                      class="flex items-end gap-2 flex-wrap">
                    <?= Csrf::field() ?>
                    <div>
                        <label for="exposed-plan-profile" class="block text-[10px] uppercase tracking-wide text-ink-soft mb-1">Perfil de IA</label>
                        <select id="exposed-plan-profile" name="profile_id"
                                class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs">
                            <option value="0">— Predeterminado de la tarea —</option>
                            <?php foreach ($profiles as $profile): ?>
                                <?php $pid = (int)($profile['id'] ?? 0); ?>
                                <option value="<?= $pid ?>" <?= $pid === $profileId ? 'selected' : '' ?>>
                                    <?= e((string)($profile['name'] ?? ('Perfil ' . $pid))) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <button type="submit" class="btn" <?= $llmConfigured ? '' : 'disabled' ?>>
                        <?= icon('auto_awesome', 16) ?>
                        <?= $planText !== '' ? 'Regenerar plan' : 'Generar plan de actuación' ?>
                    </button>
                </form>

                <form method="POST" action="<?= e($base . '/group/' . (int)$group['id'] . '/analyze') ?>">
                    <?= Csrf::field() ?>
                    <button type="submit" class="btn btn-outline"
                            title="Encola el informe IA de los CVE del grupo que están en el catálogo local (máximo <?= $maxAnalysis ?>)">
                        <?= icon('psychology', 16) ?> Informes por CVE
                    </button>
                </form>
            </div>
        </div>
        <?php if (!$llmConfigured): ?>
            <p class="text-[11px] text-amber-700 dark:text-amber-300 mt-3 mb-0">
                La IA no está configurada. Revisa el perfil en
                <a class="underline" href="<?= e(base_url('admin/apis')) ?>">Admin → APIs</a>.
            </p>
        <?php endif; ?>
    </div>

    <?php if ($planText === ''): ?>
        <div class="card p-6 mb-6">
            <div class="flex items-start gap-3">
                <span class="inline-flex items-center justify-center w-9 h-9 rounded-lg bg-brand-100 dark:bg-brand-900/30 text-brand-600 dark:text-brand-300">
                    <?= icon('description', 20) ?>
                </span>
                <div>
                    <h3 class="text-sm font-semibold m-0">Todavía no hay plan</h3>
                    <p class="text-xs text-ink-muted mt-1 mb-0 max-w-2xl">
                        Pulsa <strong>Generar plan de actuación</strong>. El plan se guarda con el grupo, así que
                        volverás a verlo al abrir esta ficha. Si el grupo cambia, puedes regenerarlo.
                    </p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- ============================================================
         Plan guardado (documento)
         ============================================================ -->
    <?php if ($planText !== ''): ?>
        <div class="card overflow-hidden mb-6" id="exposed-plan-card">
            <div class="px-5 py-4 border-b border-line flex items-center justify-between gap-3 flex-wrap no-print">
                <div class="min-w-0">
                    <h2 class="text-sm font-semibold m-0">Plan de actuación</h2>
                    <p class="text-[11px] text-ink-soft m-0 mt-1">
                        Generado el <?= e($fmtDate((string)($plan['generated_at'] ?? ''))) ?>
                        · <?= (int)($plan['cve_count'] ?? 0) ?> CVE
                        <?php if (!empty($plan['model'])): ?> · <?= e((string)$plan['model']) ?><?php endif; ?>
                        <?php if ($planFresh): ?>
                            <span class="ml-1 inline-flex px-1.5 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300 text-[9px] font-semibold">recién generado</span>
                        <?php endif; ?>
                    </p>
                </div>
                <div class="flex items-center gap-2 flex-wrap">
                    <div class="doc-views flex items-center gap-1 p-1 rounded-lg bg-muted" role="tablist">
                        <button type="button" id="exposed-doc-tab-document" onclick="exposedDocView('document')"
                                class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-surface text-ink shadow-sm">Documento</button>
                        <button type="button" id="exposed-doc-tab-markdown" onclick="exposedDocView('markdown')"
                                class="px-3 py-1.5 text-xs font-medium rounded-lg text-ink-muted hover:bg-muted">Markdown</button>
                    </div>
                    <button type="button" class="btn" onclick="exposedCopyRich()"><?= icon('content_copy', 16) ?> Copiar informe</button>
                    <button type="button" class="btn btn-outline" onclick="exposedCopyMarkdown()">Copiar Markdown</button>
                    <button type="button" class="btn btn-outline" onclick="exposedDownloadHtml()"><?= icon('html', 16) ?> .html</button>
                    <button type="button" class="btn btn-outline" onclick="exposedDownloadMd()"><?= icon('download', 16) ?> .md</button>
                    <button type="button" class="btn btn-outline" onclick="exposedPrint()"><?= icon('print', 16) ?> PDF</button>
                </div>
            </div>
            <div class="doc-stage p-5">
                <div id="exposed-plan-document">
                    <div id="exposed-plan-sheet" class="doc-sheet md-body"><?= $planHtml ?></div>
                </div>
                <div id="exposed-plan-markdown" hidden>
                    <pre id="exposed-plan-raw" class="doc-raw"><?= e($planText) ?></pre>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- ============================================================
         CVE del grupo
         ============================================================ -->
    <div class="card overflow-hidden no-print">
        <div class="px-5 py-4 border-b border-line flex items-start justify-between gap-3 flex-wrap">
            <div>
                <h2 class="text-sm font-semibold m-0">CVE del grupo</h2>
                <p class="text-[11px] text-ink-soft m-0 mt-1">
                    Ordenados por severidad, equipos expuestos y antigüedad. Quitar un CVE no lo borra del
                    catálogo ni del snapshot.
                </p>
            </div>
            <span class="text-[11px] text-ink-soft"><?= count($rows) ?> CVE</span>
        </div>

        <?php if ($rows === []): ?>
            <p class="p-5 text-sm text-ink-muted m-0">Este grupo no tiene CVE.</p>
        <?php else: ?>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead class="bg-muted text-ink-muted">
                        <tr>
                            <th class="px-3 py-2 text-left">CVE</th>
                            <th class="px-3 py-2 text-left">Severidad</th>
                            <th class="px-3 py-2 text-right">CVSS</th>
                            <th class="px-3 py-2 text-right">EPSS</th>
                            <th class="px-3 py-2 text-right">Edad</th>
                            <th class="px-3 py-2 text-right">Equipos</th>
                            <th class="px-3 py-2 text-left">Señales</th>
                            <th class="px-3 py-2 text-left">Software</th>
                            <th class="px-3 py-2 text-right"></th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-line">
                        <?php foreach ($rows as $row): ?>
                            <?php
                            $cveId = (string)($row['cve_id'] ?? '');
                            $severity = (string)($row['severity'] ?? '');
                            $hasTvm = ($row['last_seen_at'] ?? null) !== null;
                            $signals = [];
                            if ((int)($row['has_exploit'] ?? 0) === 1) {
                                $signals[] = ['exploit', 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'];
                            }
                            if ((int)($row['has_known_threats'] ?? 0) === 1) {
                                $signals[] = ['amenaza', 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'];
                            }
                            if ((int)($row['is_kev'] ?? 0) === 1) {
                                $signals[] = ['KEV', 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'];
                            }
                            if ((int)($row['zero_day'] ?? 0) === 1) {
                                $signals[] = ['zero-day', 'bg-fuchsia-100 text-fuchsia-700 dark:bg-fuchsia-900/30 dark:text-fuchsia-300'];
                            }
                            if ((int)($row['no_security_update'] ?? 0) === 1) {
                                $signals[] = ['sin update', 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'];
                            }
                            ?>
                            <tr class="hover:bg-muted/50">
                                <td class="px-3 py-2">
                                    <a href="<?= e(base_url('modules/cve/detail/' . urlencode($cveId))) ?>"
                                       class="font-mono font-medium text-brand-600 dark:text-brand-300 hover:underline">
                                        <?= e($cveId) ?>
                                    </a>
                                </td>
                                <td class="px-3 py-2">
                                    <?php if ($hasTvm): ?>
                                        <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold <?= $sevClasses[$severity] ?? $sevClasses['info'] ?>">
                                            <?= e($sevLabels[$severity] ?? ($severity !== '' ? ucfirst($severity) : '—')) ?>
                                        </span>
                                    <?php else: ?>
                                        <span class="text-ink-soft">sin datos</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-3 py-2 text-right font-mono"><?= $row['cvss'] !== null ? number_format((float)$row['cvss'], 1) : '—' ?></td>
                                <td class="px-3 py-2 text-right font-mono"><?= $row['epss'] !== null ? number_format((float)$row['epss'], 4) : '—' ?></td>
                                <td class="px-3 py-2 text-right font-mono whitespace-nowrap"><?= $row['age_days'] !== null ? (int)$row['age_days'] . ' d' : '—' ?></td>
                                <td class="px-3 py-2 text-right font-mono"><?= (int)($row['exposed_machines'] ?? 0) ?></td>
                                <td class="px-3 py-2">
                                    <div class="flex flex-wrap gap-1">
                                        <?php if ($signals === []): ?>
                                            <span class="text-ink-soft">—</span>
                                        <?php else: ?>
                                            <?php foreach ($signals as [$label, $class]): ?>
                                                <span class="inline-flex px-1 py-0.5 rounded text-[9px] font-semibold <?= $class ?>"><?= e($label) ?></span>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td class="px-3 py-2 max-w-[220px] text-ink-muted">
                                    <?= e((string)($row['software_labels'] ?? '—')) ?>
                                </td>
                                <td class="px-3 py-2 text-right">
                                    <form method="POST" action="<?= e($base . '/group/' . (int)$group['id'] . '/remove-cve') ?>"
                                          class="m-0" onsubmit="return confirm('¿Quitar <?= e($cveId) ?> del grupo?');">
                                        <?= Csrf::field() ?>
                                        <input type="hidden" name="cve_id" value="<?= e($cveId) ?>">
                                        <button type="submit" class="text-ink-soft hover:text-danger" title="Quitar del grupo">
                                            <?= icon('close', 14) ?>
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>

<?php endif; ?>

<?php if ($group !== null && $planText !== ''): ?>
<style>
    @media print {
        body * { visibility: hidden !important; }
        #exposed-plan-sheet, #exposed-plan-sheet * { visibility: visible !important; }
        #exposed-plan-sheet {
            position: absolute; left: 0; top: 0; width: 100%; margin: 0 !important;
            border: 0 !important; box-shadow: none !important; background: #fff !important;
            color: #000 !important; font-size: 10pt; line-height: 1.45;
        }
        #exposed-plan-sheet a { color: #000 !important; text-decoration: underline; }
    }
</style>
<script>
(function () {
    var PLAN_NAME = <?= json_encode((string)($downloadName ?? 'plan-actuacion.md'), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var PLAN_MD = <?= json_encode($planText, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var SHEET = document.getElementById('exposed-plan-sheet');

    var STYLES = {
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
        li: 'margin:4px 0;'
    };

    function applyStyles(root) {
        Object.keys(STYLES).forEach(function (tag) {
            root.querySelectorAll(tag).forEach(function (node) {
                node.setAttribute('style', STYLES[tag]);
            });
        });
    }

    function notify(message) {
        if (typeof toast === 'function') {
            toast(message, 'success');
        }
    }

    window.exposedDocView = function (which) {
        var doc = document.getElementById('exposed-plan-document');
        var md = document.getElementById('exposed-plan-markdown');
        if (!doc || !md) { return; }
        doc.hidden = which !== 'document';
        md.hidden = which !== 'markdown';
        var bd = document.getElementById('exposed-doc-tab-document');
        var bm = document.getElementById('exposed-doc-tab-markdown');
        if (bd) { bd.className = which === 'document' ? 'px-3 py-1.5 text-xs font-semibold rounded-lg bg-surface text-ink shadow-sm' : 'px-3 py-1.5 text-xs font-medium rounded-lg text-ink-muted hover:bg-muted'; }
        if (bm) { bm.className = which === 'markdown' ? 'px-3 py-1.5 text-xs font-semibold rounded-lg bg-surface text-ink shadow-sm' : 'px-3 py-1.5 text-xs font-medium rounded-lg text-ink-muted hover:bg-muted'; }
    };

    window.exposedCopyMarkdown = function () {
        var text = PLAN_MD;
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(function () { notify('Markdown copiado'); });
            return;
        }
        var area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try { document.execCommand('copy'); notify('Markdown copiado'); } catch (e) {}
        document.body.removeChild(area);
    };

    window.exposedCopyRich = function () {
        if (!SHEET) { return; }
        var clone = SHEET.cloneNode(true);
        applyStyles(clone);
        var html = clone.innerHTML;
        if (navigator.clipboard && window.ClipboardItem && window.isSecureContext) {
            var item = new ClipboardItem({
                'text/html': new Blob([html], { type: 'text/html' }),
                'text/plain': new Blob([PLAN_MD], { type: 'text/plain' })
            });
            navigator.clipboard.write([item]).then(function () { notify('Informe copiado con formato'); });
            return;
        }
        window.exposedCopyMarkdown();
    };

    function saveFile(name, content, type) {
        var blob = new Blob([content], { type: type });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    window.exposedDownloadMd = function () {
        saveFile(PLAN_NAME, PLAN_MD, 'text/markdown;charset=utf-8');
    };

    window.exposedDownloadHtml = function () {
        var clone = SHEET ? SHEET.cloneNode(true) : document.createElement('div');
        applyStyles(clone);
        var html = '<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Plan de actuación</title></head>'
            + '<body style="font-family:Segoe UI,Arial,sans-serif;color:#0f172a;max-width:900px;margin:24px auto;">'
            + clone.innerHTML + '</body></html>';
        saveFile(PLAN_NAME.replace(/\.md$/i, '.html'), html, 'text/html;charset=utf-8');
    };

    window.exposedPrint = function () {
        window.print();
    };
})();
</script>
<?php endif; ?>
