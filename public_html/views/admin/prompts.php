<?php
/**
 * Vista: Plantillas de prompts (Admin → Plantillas de prompts).
 * Variables: $prompts (catálogo + estado), $success, $error
 *
 * Cada prompt tiene su botón ⋮ para editarlo. Los marcados como "contrato"
 * son de solo lectura: los usa un parser y cambiarlos rompería el formato.
 */
$promptGroups = [];
foreach (($prompts ?? []) as $p) {
    $promptGroups[(string)($p['scope_label'] ?? 'Otros')][] = $p;
}
$editedCount = 0;
foreach (($prompts ?? []) as $p) {
    if (!empty($p['edited'])) { $editedCount++; }
}
?>

<div class="page-header">
    <h1>Plantillas de prompts</h1>
    <span class="count-chip"><?= count($prompts ?? []) ?></span>
    <?php if ($editedCount > 0): ?>
        <span class="status-badge status-running"><?= $editedCount ?> personalizado<?= $editedCount === 1 ? '' : 's' ?></span>
    <?php endif; ?>
    <p class="subtitle">
        Ajusta los prompts que usa la IA sin tocar el código ni publicar una release.
        Los cambios son globales: afectan a todos los tenants y se aplican en la siguiente llamada a la IA.
    </p>
</div>

<?php if (!empty($success)): ?>
    <div class="alert alert-success"><?= e($success) ?></div>
<?php endif; ?>
<?php if (!empty($error)): ?>
    <div class="alert alert-error"><?= e($error) ?></div>
<?php endif; ?>

<div class="hint-bar">
    <span class="hint">
        <?= icon('edit', 14) ?>
        Pulsa <strong>⋮</strong> en cualquier prompt para editarlo.
    </span>
    <span class="hint">
        <?= icon('lock', 14) ?>
        Los marcados como <strong>contrato</strong> definen el formato que lee el sistema y no se editan.
    </span>
</div>

<?php foreach ($promptGroups as $groupLabel => $items): ?>
    <div class="card mb-6 overflow-hidden">
        <div class="px-5 py-4 border-b border-line flex items-center justify-between gap-3">
            <h2 class="text-sm font-semibold m-0"><?= e($groupLabel) ?></h2>
            <span class="text-xs text-ink-soft"><?= count($items) ?> prompt<?= count($items) === 1 ? '' : 's' ?></span>
        </div>
        <ul class="m-0 p-0 list-none divide-y divide-line-subtle">
            <?php foreach ($items as $p): ?>
                <li class="px-5 py-3 flex items-start gap-3">
                    <div class="min-w-0 flex-1">
                        <p class="text-sm font-medium m-0 flex items-center gap-2 flex-wrap">
                            <?= e((string)$p['label']) ?>
                            <?php if (!empty($p['is_locked'])): ?>
                                <span class="status-badge" title="Contrato de formato: no editable">contrato</span>
                            <?php elseif (!empty($p['edited'])): ?>
                                <span class="status-badge status-running">editado</span>
                            <?php endif; ?>
                        </p>
                        <p class="text-xs text-ink-muted mt-0.5 mb-0"><?= e((string)$p['description']) ?></p>
                        <p class="text-[11px] text-ink-soft mt-1 mb-0 mono"><?= e((string)$p['key']) ?></p>
                    </div>

                    <?php if (!empty($p['is_locked'])): ?>
                        <span class="icon-btn" title="Contrato de formato: solo lectura" aria-label="Solo lectura">
                            <?= icon('lock', 18) ?>
                        </span>
                    <?php else: ?>
                        <button type="button"
                                class="icon-btn"
                                data-prompt-edit="<?= e((string)$p['key']) ?>"
                                aria-label="Editar <?= e((string)$p['label']) ?>"
                                title="Editar prompt">
                            <?= icon('more_vert', 20) ?>
                        </button>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endforeach; ?>

<?php require VIEWS_PATH . '/partials/llm_prompts_editor.php'; ?>
