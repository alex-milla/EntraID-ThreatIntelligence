<?php
/**
 * Parcial: lista de informes con IA.
 * Variables: $aiReports, $isAdmin, $selectedAiId.
 */

$aiStatusLabels = $aiStatusLabels ?? [
    'pending'  => 'En cola',
    'running'  => 'Generando',
    'done'     => 'Listo',
    'error'    => 'Error IA',
    'canceled' => 'Cancelado',
];
$aiStatusDots = $aiStatusDots ?? [
    'pending'  => 'bg-gray-400',
    'running'  => 'bg-blue-500',
    'done'     => 'bg-green-500',
    'error'    => 'bg-red-500',
    'canceled' => 'bg-amber-500',
];
$aiStatusText = $aiStatusText ?? [
    'pending'  => 'text-gray-500',
    'running'  => 'text-blue-600 dark:text-blue-400',
    'done'     => 'text-green-600 dark:text-green-400',
    'error'    => 'text-red-600 dark:text-red-400',
    'canceled' => 'text-amber-600 dark:text-amber-400',
];
$aiReports = is_array($aiReports ?? null) ? $aiReports : [];
$selectedAiId = (int)($selectedAiId ?? 0);
$isAdmin = !empty($isAdmin);
$llmProfiles = is_array($llmProfiles ?? null) ? $llmProfiles : [];
$profileMap = [];
foreach ($llmProfiles as $llmProfile) {
    $profileMap[(int)($llmProfile['id'] ?? 0)] = $llmProfile;
}
?>
<?php if (empty($aiReports)): ?>
    <div class="p-5 text-center text-xs text-ink-muted">
        No hay informes en esta vista.
    </div>
<?php else: ?>
    <?php foreach ($aiReports as $aiRow): ?>
        <?php
        $aiRowId = (int)$aiRow['id'];
        $aiRowStatus = (string)($aiRow['status'] ?? 'pending');
        $aiRowIds = safe_json_decode((string)($aiRow['cve_ids'] ?? ''), []);
        if (!is_array($aiRowIds)) {
            $aiRowIds = [];
        }
        $aiRowLabel = count($aiRowIds) === 1
            ? (string)($aiRowIds[0] ?? '')
            : count($aiRowIds) . ' CVEs';
        $aiSearch = strtolower(implode(' ', array_map('strval', $aiRowIds)) . ' ' . (string)$aiRow['title']);
        $aiRowTags = CveReportAi::decodeTags((string)($aiRow['tags'] ?? ''));
        $aiErrorText = trim((string)($aiRow['ai_error'] ?? ''));
        $aiRowProfileId = (int)($aiRow['ai_profile_id'] ?? 0);
        $aiRowProfile = $profileMap[$aiRowProfileId] ?? null;
        $aiRowProfileName = $aiRowProfile !== null
            ? (string)($aiRowProfile['name'] ?? '')
            : ($aiRowProfileId > 0 ? 'Perfil #' . $aiRowProfileId : 'Automático');
        $aiRowProfileModel = $aiRowProfile !== null ? trim((string)($aiRowProfile['model'] ?? '')) : '';
        $aiRowModel = trim((string)($aiRow['ai_model'] ?? ''));
        $aiRowModelLabel = $aiRowModel !== '' ? $aiRowModel : $aiRowProfileModel;
        $aiRowFailedLabel = $aiRowProfileName . ($aiRowModelLabel !== '' ? ' · ' . $aiRowModelLabel : '');
        ?>
        <div class="ai-report-item group border-b border-gray-100 dark:border-gray-800 px-3 py-2.5 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/40 <?= $selectedAiId === $aiRowId ? 'bg-brand-50 dark:bg-brand-950/40' : '' ?>"
             data-id="<?= $aiRowId ?>"
             data-status="<?= e($aiRowStatus) ?>"
             data-profile-id="<?= $aiRowProfileId ?>"
             data-ai-profile-name="<?= e($aiRowProfileName) ?>"
             data-ai-profile-model="<?= e($aiRowProfileModel) ?>"
             data-ai-model="<?= e($aiRowModel) ?>"
             data-ai-error="<?= e($aiErrorText) ?>"
             data-search="<?= e($aiSearch) ?>"
             role="button" tabindex="0"
             onclick="cveAiSelect(<?= $aiRowId ?>)"
             onkeydown="if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); cveAiSelect(<?= $aiRowId ?>); }">
            <div class="flex items-center gap-2">
                <?php if ($isAdmin): ?>
                    <input type="checkbox" class="ai-report-check rounded border-line-strong text-brand-500 focus:ring-brand-500 shrink-0"
                           data-id="<?= $aiRowId ?>" title="Seleccionar informe"
                           onclick="event.stopPropagation()" onkeydown="event.stopPropagation()">
                <?php endif; ?>
                <span class="ai-status-dot w-2 h-2 rounded-full shrink-0 <?= $aiStatusDots[$aiRowStatus] ?? $aiStatusDots['pending'] ?>"></span>
                <span class="text-xs font-mono font-medium truncate"><?= e($aiRowLabel) ?></span>
                <span class="ml-auto text-[10px] text-ink-soft shrink-0"><?= e(format_db_date((string)($aiRow['created_at'] ?? ''), 'd/m H:i')) ?></span>
            </div>
            <div class="flex items-center gap-2 mt-1 pl-4">
                <span class="ai-status-text text-[10px] font-medium <?= $aiStatusText[$aiRowStatus] ?? $aiStatusText['pending'] ?>"
                      <?= $aiErrorText !== '' ? 'title="' . e(truncate($aiErrorText, 400)) . '"' : '' ?>>
                    <?= e($aiStatusLabels[$aiRowStatus] ?? $aiRowStatus) ?>
                </span>
                <?php if (in_array($aiRowStatus, ['pending', 'running'], true) && (int)($aiRow['total_items'] ?? 0) > 0): ?>
                    <span class="ai-status-progress text-[10px] text-ink-soft">
                        <?= (int)($aiRow['processed_items'] ?? 0) ?>/<?= (int)$aiRow['total_items'] ?>
                    </span>
                <?php endif; ?>
                <span class="text-[10px] text-ink-soft truncate">
                    <?= e($aiRowModelLabel) ?>
                </span>
                <?php if ((int)($aiRow['revision'] ?? 1) > 1): ?>
                    <span class="text-[10px] font-semibold text-ink-muted shrink-0">v<?= (int)$aiRow['revision'] ?></span>
                <?php endif; ?>
                <?php if (!empty($aiRow['group_name'])): ?>
                    <span class="text-[10px] text-ink-soft truncate">
                        · <?= (string)($aiRow['group_kind'] ?? '') === 'company' ? 'Empresa' : 'Grupo' ?>:
                        <?= e((string)$aiRow['group_name']) ?>
                    </span>
                <?php endif; ?>
                <?php if (!empty($aiRow['item_groups'])): ?>
                    <span class="text-[10px] text-ink-soft truncate">· <?= e((string)$aiRow['item_groups']) ?></span>
                <?php endif; ?>
                <?php if (!empty($aiRow['has_defender'])): ?>
                    <span class="px-1.5 py-0.5 rounded bg-info-bg text-info text-[10px] font-semibold shrink-0">Defender</span>
                <?php endif; ?>
                <span class="ml-auto flex items-center gap-1 shrink-0">
                    <?php if ($isAdmin && in_array($aiRowStatus, ['pending', 'running'], true)): ?>
                        <button type="button" title="Cancelar" onclick="event.stopPropagation(); cveAiCancel(<?= $aiRowId ?>)"
                                class="p-1 rounded text-ink-soft hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20">
                            <i class="material-icons icon-14" aria-hidden="true">close</i>
                        </button>
                    <?php endif; ?>
                    <?php if ($isAdmin && in_array($aiRowStatus, ['error', 'canceled'], true)): ?>
                        <button type="button" title="Reintentar" onclick="event.stopPropagation(); cveAiRetry(<?= $aiRowId ?>)"
                                class="p-1 rounded text-ink-soft hover:text-brand-600 hover:bg-brand-50 dark:hover:bg-brand-950">
                            <i class="material-icons icon-14" aria-hidden="true">refresh</i>
                        </button>
                    <?php endif; ?>
                    <?php if ($isAdmin && count($aiRowIds) > 1 && $aiRowStatus !== 'running'): ?>
                        <button type="button" title="Separar en informes individuales"
                                onclick="event.stopPropagation(); cveAiSplit(<?= $aiRowId ?>)"
                                class="px-1.5 py-1 rounded text-[10px] font-medium text-ink-muted hover:text-brand-600 hover:bg-brand-50 dark:hover:bg-brand-950">
                            Separar
                        </button>
                    <?php endif; ?>
                    <?php if ($isAdmin): ?>
                        <button type="button" title="Eliminar" onclick="event.stopPropagation(); cveAiDelete(<?= $aiRowId ?>)"
                                class="p-1 rounded text-ink-soft hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20">
                            <i class="material-icons icon-14" aria-hidden="true">delete</i>
                        </button>
                    <?php endif; ?>
                </span>
            </div>
            <?php if ($aiRowStatus === 'error'): ?>
                <p class="text-[10px] text-danger mt-1 pl-4 truncate"
                   title="Modelo que falló: <?= e($aiRowFailedLabel) ?>">
                    Falló: <?= e($aiRowFailedLabel) ?>
                </p>
            <?php endif; ?>
            <?php if ($aiRowTags !== []): ?>
                <div class="flex items-center gap-1.5 flex-wrap mt-1 pl-4">
                    <?php foreach ($aiRowTags as $tag): ?>
                        <span class="text-[9px] font-medium text-primary">#<?= e($tag) ?></span>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
<?php endif; ?>
