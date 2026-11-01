<?php
/**
 * Parcial: hallazgos locales del caso (v0.3.9).
 *
 * Variables: $vmFindingCaseId, $vmFindingCve, $vmFindings.
 * Cada hallazgo es un activo/servicio; los campos sin dato se muestran como
 * «sin datos». No se inventan activos, versiones ni entornos.
 */

$vmFindingCaseId = (int)($vmFindingCaseId ?? 0);
$vmFindingCve = (string)($vmFindingCve ?? '');
$vmFindings = is_array($vmFindings ?? null) ? $vmFindings : [];
$statusLabels = VmCases::STATUSES;
$sourceLabels = VmCases::FINDING_SOURCES;
$saveUrl = base_url('modules/cve/vm/' . $vmFindingCaseId . '/findings/save');

$fmtDate = static function (?string $value): string {
    $value = trim((string)$value);
    if ($value === '') {
        return 'sin datos';
    }
    $ts = strtotime($value);
    return $ts === false ? $value : date('d/m/Y', $ts);
};
$orDash = static fn(?string $value): string => trim((string)$value) !== '' ? (string)$value : 'sin datos';

$renderFields = static function (array $finding) use ($statusLabels, $sourceLabels): void {
    $id = (int)($finding['id'] ?? 0);
    ?>
    <input type="hidden" name="finding_id" value="<?= $id ?>">
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <label class="block">
            <span class="text-[10px] font-medium text-ink-muted">Activo o servicio</span>
            <input type="text" name="asset_or_service" maxlength="200" placeholder="p. ej. srv-01, API de clientes…"
                   value="<?= e((string)($finding['asset_or_service'] ?? '')) ?>"
                   class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
        </label>
        <label class="block">
            <span class="text-[10px] font-medium text-ink-muted">Entorno</span>
            <input type="text" name="environment" maxlength="120" placeholder="Producción, DMZ, Oficina…"
                   value="<?= e((string)($finding['environment'] ?? '')) ?>"
                   class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
        </label>
        <label class="block">
            <span class="text-[10px] font-medium text-ink-muted">Producto</span>
            <input type="text" name="product" maxlength="200" value="<?= e((string)($finding['product'] ?? '')) ?>"
                   class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
        </label>
        <label class="block">
            <span class="text-[10px] font-medium text-ink-muted">Versión detectada</span>
            <input type="text" name="product_version" maxlength="120" placeholder="Solo si se conoce"
                   value="<?= e((string)($finding['product_version'] ?? '')) ?>"
                   class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
        </label>
        <label class="block">
            <span class="text-[10px] font-medium text-ink-muted">Responsable / equipo</span>
            <input type="text" name="owner_name" maxlength="120" value="<?= e((string)($finding['owner_name'] ?? '')) ?>"
                   class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
        </label>
        <label class="block">
            <span class="text-[10px] font-medium text-ink-muted">Estado del hallazgo</span>
            <select name="status" class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                <?php foreach ($statusLabels as $key => $label): ?>
                    <option value="<?= e($key) ?>" <?= (string)($finding['status'] ?? 'detected') === $key ? 'selected' : '' ?>>
                        <?= e($label) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </label>
        <label class="block">
            <span class="text-[10px] font-medium text-ink-muted">Fuente</span>
            <select name="source" class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
                <?php foreach ($sourceLabels as $key => $label): ?>
                    <option value="<?= e($key) ?>" <?= (string)($finding['source'] ?? 'manual') === $key ? 'selected' : '' ?>>
                        <?= e($label) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </label>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <label class="block">
                <span class="text-[10px] font-medium text-ink-muted">Primera detección</span>
                <input type="date" name="first_detected_at" value="<?= e(substr((string)($finding['first_detected_at'] ?? ''), 0, 10)) ?>"
                       class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
            </label>
            <label class="block">
                <span class="text-[10px] font-medium text-ink-muted">Última detección</span>
                <input type="date" name="last_detected_at" value="<?= e(substr((string)($finding['last_detected_at'] ?? ''), 0, 10)) ?>"
                       class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs">
            </label>
        </div>
    </div>
    <label class="block">
        <span class="text-[10px] font-medium text-ink-muted">Notas</span>
        <textarea name="notes" rows="2" maxlength="4000"
                  class="mt-0.5 w-full px-2 py-1.5 rounded-lg border border-line-strong bg-input text-ink text-xs"><?= e((string)($finding['notes'] ?? '')) ?></textarea>
    </label>
    <button type="submit"
            class="inline-flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-[11px] font-semibold rounded-lg transition-colors">
        <i class="material-icons icon-12" aria-hidden="true">save</i>
        Guardar hallazgo
    </button>
    <?php
};
?>
<div class="space-y-3">
    <p class="text-[11px] text-ink-soft">
        Un hallazgo = un activo o servicio afectado por <span class="font-mono"><?= e($vmFindingCve) ?></span>.
        Los campos sin dato se muestran como «sin datos»; no se rellenan automáticamente.
    </p>

    <?php if ($vmFindings === []): ?>
        <p class="text-[11px] text-ink-muted">Todavía no hay hallazgos registrados para este caso.</p>
    <?php else: ?>
        <?php foreach ($vmFindings as $index => $finding): ?>
            <?php
            $findingStatus = (string)($finding['status'] ?? 'detected');
            $asset = trim((string)($finding['asset_or_service'] ?? ''));
            $product = trim((string)($finding['product'] ?? ''));
            $version = trim((string)($finding['product_version'] ?? ''));
            ?>
            <details class="rounded-lg border border-line" <?= $index === 0 ? 'open' : '' ?>>
                <summary class="px-3 py-2 cursor-pointer flex items-center justify-between gap-2 flex-wrap">
                    <span class="text-[11px] font-medium">
                        <?= e($asset !== '' ? $asset : 'Sin activo identificado') ?>
                        <span class="text-ink-soft font-normal">
                            · <?= e($product !== '' ? $product : 'sin producto') ?><?= $version !== '' ? ' ' . e($version) : '' ?>
                        </span>
                    </span>
                    <span class="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium bg-muted text-ink-muted">
                        <?= e($statusLabels[$findingStatus] ?? $findingStatus) ?>
                    </span>
                </summary>
                <form data-vm-finding-form method="post" action="<?= e($saveUrl) ?>"
                      class="px-3 pb-3 pt-2 border-t border-line space-y-2">
                    <?= Csrf::field() ?>
                    <?php $renderFields($finding); ?>
                </form>
                <div class="px-3 pb-3 text-[10px] text-ink-soft">
                    Fuente: <?= e($sourceLabels[(string)($finding['source'] ?? 'manual')] ?? '—') ?>
                    · Primera detección: <?= e($fmtDate((string)($finding['first_detected_at'] ?? ''))) ?>
                    · Última: <?= e($fmtDate((string)($finding['last_detected_at'] ?? ''))) ?>
                    · Entorno: <?= e($orDash((string)($finding['environment'] ?? ''))) ?>
                </div>
            </details>
        <?php endforeach; ?>
    <?php endif; ?>

    <details class="rounded-lg border border-dashed border-line-strong">
        <summary class="px-3 py-2 cursor-pointer text-[11px] font-medium text-brand-600 dark:text-brand-300">
            + Añadir hallazgo (activo o servicio)
        </summary>
        <form data-vm-finding-form method="post" action="<?= e($saveUrl) ?>"
              class="px-3 pb-3 pt-2 space-y-2">
            <?= Csrf::field() ?>
            <?php $renderFields(['status' => 'detected', 'source' => 'manual']); ?>
        </form>
    </details>
</div>
