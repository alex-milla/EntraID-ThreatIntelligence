<?php
/**
 * Parcial: fallback de información del CVE cuando no hay datos locales.
 *
 * Variables: $case, $cveId, $report (fila de cve_ai_reports o null).
 * Se carga dentro del caso, debajo del historial.
 */

$case = is_array($case ?? null) ? $case : [];
$cveId = (string)($cveId ?? ($case['cve_id'] ?? ''));
$report = is_array($report ?? null) ? $report : null;
$caseId = (int)($case['id'] ?? 0);
?>

<div class="space-y-2">
    <div class="rounded-lg bg-muted px-3 py-2">
        <p class="text-[11px] text-ink-muted">
            No hay datos de catálogo para <span class="font-mono font-medium"><?= e($cveId) ?></span>.
            La ficha se completará al sincronizarlo desde NVD o al generar un informe.
        </p>
    </div>

    <?php if ($report !== null): ?>
        <button type="button"
                data-vm-report-url="<?= base_url('modules/cve/report-ai/' . (int)$report['id'] . '/panel') ?>"
                data-vm-report-title="Informe <?= e($cveId) ?>"
                class="inline-flex items-center gap-2 px-3 py-1.5 border border-line-strong text-ink text-xs font-medium rounded-lg hover:bg-muted transition-colors">
            <i class="material-icons icon-14" aria-hidden="true">description</i>
            Ver informe del CVE (#<?= (int)$report['id'] ?> · <?= e((string)($report['status'] ?? '')) ?>)
        </button>
    <?php else: ?>
        <form data-vm-ai-form method="post"
              action="<?= base_url('modules/cve/vm/' . $caseId . '/ai-report') ?>"
              class="flex items-center gap-2 flex-wrap">
            <?= Csrf::field() ?>
            <button type="submit" name="no_ai" value="0"
                    class="inline-flex items-center gap-2 px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold rounded-lg transition-colors">
                <i class="material-icons icon-14" aria-hidden="true">auto_awesome</i>
                Generar informe con IA
            </button>
            <button type="submit" name="no_ai" value="1"
                    class="inline-flex items-center gap-2 px-3 py-1.5 border border-line-strong text-ink text-xs font-medium rounded-lg hover:bg-muted transition-colors">
                Solo datos locales
            </button>
        </form>
        <p class="text-[10px] text-ink-soft">
            La IA solo redacta a partir de los datos guardados. No cierra el caso ni confirma parches:
            eso sigue exigiendo la verificación manual.
        </p>
    <?php endif; ?>
</div>
