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

// Anexo B: fichas técnicas por CVE (deterministas + informes de la app).
$dossier = is_array($dossier ?? null) ? $dossier : [];
$dossierMd = trim((string)($dossier['markdown'] ?? ''));
$dossierHtml = (string)($dossier['html'] ?? '');
$dossierWith = (int)($dossier['with_report'] ?? 0);
$dossierWithout = (int)($dossier['without'] ?? 0);

$documentMd = $dossierMd;
$documentHtml = $dossierHtml;
$hasDocument = $documentMd !== '';
$orgs = is_array($orgs ?? null) ? $orgs : [];
$singleCve = strtoupper(trim((string)($singleCve ?? '')));
$backUrl = (string)($backUrl ?? $base);
$currentBack = (string)($_GET['back'] ?? '');
$groupReports = is_array($groupReports ?? null) ? $groupReports : ['rows' => [], 'total' => 0, 'processed' => 0, 'done' => 0, 'failed' => 0, 'pending' => 0, 'has_job' => false];
$backQuery = $currentBack !== '' ? '&back=' . rawurlencode($currentBack) : '';

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
        <a href="<?= e($backUrl) ?>" class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline inline-flex items-center gap-1 mb-1">
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
                    exploit/amenazas y software) y devuelve una lectura del riesgo. Si el grupo es grande,
                    se analiza <strong>por partes</strong> y se fusiona el resultado: ninguna petición lleva
                    el grupo entero. La aplicación añade después el anexo con todos los CVE.
                </p>
                <?php if ($planContext !== null): ?>
                    <p class="text-[11px] text-ink-soft mt-2 mb-0">
                        <?php if (($planContext['mode'] ?? '') === 'pipeline'): ?>
                            Analizado por partes: <?= (int)($planContext['parts'] ?? 0) ?> llamadas para
                            <?= (int)($planContext['total'] ?? 0) ?> CVE
                            <?php if ((int)($planContext['failed_parts'] ?? 0) > 0): ?>
                                · <?= (int)$planContext['failed_parts'] ?> parte(s) con error (se fusionó lo disponible)
                            <?php endif; ?>
                        <?php else: ?>
                            Contexto enviado: <?= (int)($planContext['detailed'] ?? 0) ?> CVE en detalle de
                            <?= (int)($planContext['total'] ?? 0) ?>
                            <?php if ((int)($planContext['truncated'] ?? 0) > 0): ?>
                                · <?= (int)$planContext['truncated'] ?> quedan solo en el anexo
                            <?php endif; ?>
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

                <form method="POST" action="<?= e($base . '/group/' . (int)$group['id'] . '/analyze') ?>"
                      class="flex items-end gap-2 flex-wrap">
                    <?= Csrf::field() ?>
                    <div>
                        <label for="exposed-report-mode" class="block text-[10px] uppercase tracking-wide text-ink-soft mb-1">
                            Informes
                        </label>
                        <select id="exposed-report-mode" name="report_mode"
                                class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs">
                            <option value="per_cve">Uno por CVE (recomendado si no hay racimo)</option>
                            <option value="joint">Un informe conjunto</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-outline"
                            title="Encola el informe IA de los CVE del grupo que están en el catálogo local (máximo <?= $maxAnalysis ?>)">
                        <?= icon('psychology', 16) ?> Generar análisis
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

        <?php if (($groupReports['rows'] ?? []) !== []): ?>
            <?php
            $rTotal = (int)($groupReports['total'] ?? 0);
            $rProcessed = (int)($groupReports['processed'] ?? 0);
            $rPending = (int)($groupReports['pending'] ?? 0);
            $rFailed = (int)($groupReports['failed'] ?? 0);
            $rTimeout = !empty($groupReports['timeout']);
            $rPct = $rTotal > 0 ? max(0, min(100, (int)round($rProcessed * 100 / $rTotal))) : 0;
            $firstReport = (int)($groupReports['rows'][0]['id'] ?? 0);
            $statusLabels = [
                'pending' => 'En cola', 'running' => 'Generando', 'done' => 'Listo',
                'error' => 'Error', 'canceled' => 'Cancelado',
            ];
            $statusClasses = [
                'pending' => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
                'running' => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
                'done' => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
                'error' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
                'canceled' => 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
            ];
            $partialClass = 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300';
            ?>
            <div class="mt-4 pt-4 border-t border-line" id="exposed-group-reports">
                <div class="flex items-start justify-between gap-3 flex-wrap">
                    <div class="min-w-0 flex-1">
                        <p class="text-xs font-semibold m-0">Análisis por CVE</p>
                        <p class="text-[11px] text-ink-soft m-0 mt-0.5">
                            <?= $rProcessed ?>/<?= $rTotal ?> generados
                            <?php if ($rPending > 0): ?> · <?= $rPending ?> en cola<?php endif; ?>
                            <?php if ($rFailed > 0): ?> · <?= $rFailed ?> con error<?php endif; ?>
                            <?php if ($rPending > 0): ?>
                                · se actualiza solo
                            <?php elseif ($rFailed > 0): ?>
                                · <span class="text-amber-700 dark:text-amber-300">completado con errores</span>
                            <?php else: ?>
                                · completado
                            <?php endif; ?>
                        </p>
                        <div class="mt-2 h-1.5 w-full max-w-md rounded-full bg-muted overflow-hidden">
                            <div class="h-full <?= $rFailed > 0 ? 'bg-amber-500' : 'bg-brand-500' ?> transition-all" style="width: <?= $rPct ?>%"></div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2 flex-wrap">
                        <?php if ($rFailed > 0): ?>
                            <form method="POST" action="<?= e($base . '/group/' . (int)$group['id'] . '/analyze-retry') ?>" class="m-0">
                                <?= Csrf::field() ?>
                                <button type="submit" class="btn btn-outline"
                                        title="Vuelve a lanzar solo los CVE que fallaron; los que ya están listos no se tocan">
                                    <?= icon('refresh', 14) ?> Reintentar los <?= $rFailed ?> fallidos
                                </button>
                            </form>
                        <?php endif; ?>
                        <?php if ($firstReport > 0): ?>
                            <a href="<?= e(base_url('modules/cve/report-ai/' . $firstReport)) ?>"
                               class="text-[11px] text-brand-600 dark:text-brand-300 hover:underline whitespace-nowrap">
                                <?= icon('open_in_new', 13) ?> Abrir en el módulo CVE
                            </a>
                        <?php endif; ?>
                    </div>
                </div>

                <?php if ($rTimeout): ?>
                    <p class="text-[11px] text-amber-700 dark:text-amber-300 m-0 mt-2">
                        El modelo tardó más que el tiempo de espera del perfil de IA. Súbelo en
                        <a class="underline" href="<?= e(base_url('admin/apis')) ?>">Admin → APIs</a>
                        o usa un perfil más rápido para los análisis por CVE, y pulsa «Reintentar».
                    </p>
                <?php endif; ?>

                <div class="mt-2 space-y-1">
                    <?php foreach ($groupReports['rows'] as $reportRow): ?>
                        <?php
                        $rStatus = (string)($reportRow['status'] ?? 'pending');
                        $rFailedItems = (int)($reportRow['failed_items'] ?? 0);
                        $rErrorCves = is_array($reportRow['error_cves'] ?? null) ? $reportRow['error_cves'] : [];
                        $rCves = is_array($reportRow['cve_list'] ?? null) ? $reportRow['cve_list'] : [];
                        $rLabel = $rCves === [] ? 'Conjunto' : (count($rCves) === 1 ? $rCves[0] : count($rCves) . ' CVE');
                        $rBadgeLabel = $statusLabels[$rStatus] ?? $rStatus;
                        $rBadgeClass = $statusClasses[$rStatus] ?? $statusClasses['pending'];
                        if ($rStatus === 'done' && $rFailedItems > 0) {
                            $rBadgeLabel = 'Parcial';
                            $rBadgeClass = $partialClass;
                        }
                        ?>
                        <div class="text-[11px]">
                            <div class="flex items-center justify-between gap-2">
                                <span class="min-w-0 truncate">
                                    <span class="font-mono"><?= e($rLabel) ?></span>
                                    <?php if ($rStatus === 'error' && (string)($reportRow['ai_error'] ?? '') !== '' && $rErrorCves === []): ?>
                                        <span class="text-danger"> · <?= e((string)$reportRow['ai_error']) ?></span>
                                    <?php endif; ?>
                                </span>
                                <span class="flex items-center gap-2 shrink-0">
                                    <span class="px-2 py-0.5 rounded-full text-[10px] font-medium <?= $rBadgeClass ?>">
                                        <?= e($rBadgeLabel) ?>
                                    </span>
                                    <a href="<?= e(base_url('modules/cve/report-ai/' . (int)$reportRow['id'])) ?>"
                                       class="text-brand-600 dark:text-brand-300 hover:underline">#<?= (int)$reportRow['id'] ?></a>
                                </span>
                            </div>
                            <?php if ($rErrorCves !== []): ?>
                                <ul class="m-0 mt-0.5 pl-4 text-danger">
                                    <?php foreach (array_slice($rErrorCves, 0, 8) as $errorCve): ?>
                                        <li>
                                            <span class="font-mono"><?= e((string)($errorCve['cve_id'] ?? '')) ?></span>
                                            <?php if ((string)($errorCve['error'] ?? '') !== ''): ?>
                                                · <?= e(function_exists('mb_substr')
                                                    ? mb_substr((string)$errorCve['error'], 0, 180)
                                                    : substr((string)$errorCve['error'], 0, 180)) ?>
                                            <?php endif; ?>
                                        </li>
                                    <?php endforeach; ?>
                                    <?php if (count($rErrorCves) > 8): ?>
                                        <li>… y <?= count($rErrorCves) - 8 ?> más</li>
                                    <?php endif; ?>
                                </ul>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
                <?php if (!empty($groupReports['has_job'])): ?>
                    <script>setTimeout(function () { window.location.reload(); }, 8000);</script>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="mt-4 pt-4 border-t border-line flex items-end justify-between gap-3 flex-wrap">
            <div class="min-w-0 max-w-xl">
                <p class="text-xs font-semibold m-0">Enviar a Remediación</p>
                <p class="text-[11px] text-ink-soft m-0 mt-0.5">
                    Crea una tarea por CVE en el módulo Remediación (con su SLA y checklist) para
                    que el equipo de sistemas las ejecute y las marque como verificadas.
                </p>
            </div>
            <form method="POST" action="<?= e($base . '/group/' . (int)$group['id'] . '/remediation') ?>"
                  class="flex items-end gap-2 flex-wrap">
                <?= Csrf::field() ?>
                <div>
                    <label for="exposed-org" class="block text-[10px] uppercase tracking-wide text-ink-soft mb-1">Organización</label>
                    <select id="exposed-org" name="org_id"
                            class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs">
                        <option value="0">— Primera / crear automática —</option>
                        <?php foreach ($orgs as $org): ?>
                            <option value="<?= (int)$org['id'] ?>"><?= e((string)$org['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label for="exposed-org-name" class="block text-[10px] uppercase tracking-wide text-ink-soft mb-1">…o nueva</label>
                    <input id="exposed-org-name" type="text" name="org_name" maxlength="120"
                           placeholder="Nombre de la organización"
                           class="px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-xs w-56">
                </div>
                <button type="submit" class="btn btn-outline">
                    <?= icon('assignment_turned_in', 16) ?> Crear tareas
                </button>
            </form>
        </div>
    </div>

    <?php if ($singleCve !== ''): ?>
        <div class="alert alert-info mb-4 no-print" role="status">
            Mostrando solo <strong class="font-mono"><?= e($singleCve) ?></strong>.
            <a class="underline" href="<?= e($base . '/group/' . (int)$group['id']) ?>">Ver el grupo completo</a>.
        </div>
    <?php endif; ?>

    <?php if ($planText === '' && $hasDocument): ?>
        <div class="alert alert-info mb-4 no-print" role="status">
            <strong>Esto todavía no es el análisis de la IA.</strong>
            El informe muestra los datos importados de Defender y la prioridad calculada por la
            aplicación. Pulsa <strong>Generar plan de actuación</strong> si quieres además la lectura
            del riesgo de tu modelo local.
        </div>
    <?php endif; ?>

    <!-- ============================================================
         Dossier (plan + fichas por CVE)
         ============================================================ -->
    <?php if ($hasDocument): ?>
        <?php if (count($rows) > 1): ?>
            <div class="flex items-center gap-2 mb-3 no-print flex-wrap">
                <span class="text-[11px] text-ink-soft">Vista:</span>
                <a href="<?= e($base . '/group/' . (int)$group['id'] . ($currentBack !== '' ? '?back=' . rawurlencode($currentBack) : '')) ?>"
                   class="px-3 py-1.5 rounded-lg text-xs font-medium <?= $singleCve === ''
                        ? 'bg-brand-500 text-white'
                        : 'border border-line text-ink-muted hover:bg-muted' ?>">
                    Conjunto
                </a>
                <form method="GET" action="<?= e($base . '/group/' . (int)$group['id']) ?>" class="m-0">
                    <?php if ($currentBack !== ''): ?>
                        <input type="hidden" name="back" value="<?= e($currentBack) ?>">
                    <?php endif; ?>
                    <select name="cve" onchange="this.form.submit()"
                            class="px-3 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                        <option value="">Por CVE…</option>
                        <?php foreach ($rows as $rowOption): ?>
                            <?php $optId = (string)($rowOption['cve_id'] ?? ''); ?>
                            <option value="<?= e($optId) ?>" <?= $singleCve === strtoupper($optId) ? 'selected' : '' ?>>
                                <?= e($optId) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </form>
            </div>
        <?php endif; ?>
        <div class="card overflow-hidden mb-6" id="exposed-plan-card">
            <div class="px-5 py-4 border-b border-line flex items-center justify-between gap-3 flex-wrap no-print">
                <div class="min-w-0">
                    <h2 class="text-sm font-semibold m-0">Informe de vulnerabilidad</h2>
                    <p class="text-[11px] text-ink-soft m-0 mt-1">
                        Grupo: <strong><?= e((string)($group['name'] ?? '')) ?></strong>
                        <?php if ($singleCve !== ''): ?>
                            · vista de <span class="font-mono"><?= e($singleCve) ?></span>
                        <?php endif; ?>
                        <?php if ($planText !== ''): ?>
                            <span class="ml-1 inline-flex px-1.5 py-0.5 rounded bg-brand-100 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300 text-[9px] font-semibold">Lectura del riesgo IA</span>
                            <?= e($fmtDate((string)($plan['generated_at'] ?? ''))) ?>
                            <?php if (!empty($plan['model'])): ?> · <?= e((string)$plan['model']) ?><?php endif; ?>
                        <?php else: ?>
                            <span class="ml-1 inline-flex px-1.5 py-0.5 rounded bg-muted text-ink-muted text-[9px] font-semibold uppercase tracking-wide">Sin análisis IA</span>
                        <?php endif; ?>
                        <?php if ((string)($dossier['max_priority'] ?? '') !== ''): ?>
                            · prioridad máx. <strong><?= e((string)$dossier['max_priority']) ?></strong>
                        <?php endif; ?>
                        · <?= (int)($dossier['kev'] ?? 0) ?> en KEV
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
                    <div id="exposed-plan-sheet" class="doc-sheet"><?= $documentHtml ?></div>
                </div>
                <div id="exposed-plan-markdown" hidden>
                    <pre id="exposed-plan-raw" class="doc-raw"><?= e($documentMd) ?></pre>
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
                                    <a href="<?= e($base . '/group/' . (int)$group['id'] . '?cve=' . urlencode($cveId)
                                        . ($currentBack !== '' ? '&back=' . rawurlencode($currentBack) : '')) ?>"
                                       class="mr-2 text-[11px] text-brand-600 dark:text-brand-300 hover:underline"
                                       title="Ver solo esta vulnerabilidad">
                                        Informe
                                    </a>
                                    <form method="POST" action="<?= e($base . '/group/' . (int)$group['id'] . '/remove-cve') ?>"
                                          class="inline m-0" onsubmit="return confirm('¿Quitar <?= e($cveId) ?> del grupo?');">
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

<?php if ($group !== null && $hasDocument): ?>
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
    var PLAN_MD = <?= json_encode($documentMd, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var SHEET = document.getElementById('exposed-plan-sheet');

    function notify(message, type) {
        if (typeof toast === 'function') {
            toast(message, type || 'success');
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
        if (!text) {
            notify('No hay informe que copiar.', 'error');
            return;
        }
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
        if (!SHEET) {
            notify('No hay informe que copiar.', 'error');
            return;
        }
        if (window.ReportDoc) {
            ReportDoc.copyRich('exposed-plan-sheet', { markdown: PLAN_MD, message: 'Informe copiado con formato' });
            return;
        }
        notify('No se pudo preparar el portapapeles.', 'error');
    };

    window.exposedDownloadMd = function () {
        if (!PLAN_MD) {
            notify('No hay informe que exportar.', 'error');
            return;
        }
        if (window.ReportDoc) {
            ReportDoc.downloadMarkdown(PLAN_NAME, PLAN_MD);
            return;
        }
        notify('No se pudo exportar el informe.', 'error');
    };

    window.exposedDownloadHtml = function () {
        if (!SHEET) {
            notify('No hay informe que exportar.', 'error');
            return;
        }
        if (window.ReportDoc) {
            ReportDoc.downloadHtml('exposed-plan-sheet', PLAN_NAME.replace(/\.md$/i, '.html'), 'Informe de vulnerabilidad');
            return;
        }
        notify('No se pudo exportar el informe.', 'error');
    };

    window.exposedPrint = function () {
        if (!SHEET) {
            notify('No hay informe que imprimir.', 'error');
            return;
        }
        window.print();
    };
})();
</script>
<?php endif; ?>
