<?php
/**
 * Parcial: contenido de la ficha de un CVE.
 * Variables: $cveId, $cve, $products, $references, $cwes, $kev, $epss.
 * Opcional: $isInline (panel desplegable del catálogo).
 */

$isInline = $isInline ?? false;
$severity = (string)($cve['severity'] ?? '');
$severityClasses = [
    'Critical' => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    'High'     => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    'Medium'   => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    'Low'      => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
];
$severityClass = $severityClasses[$severity] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300';

$remediationActive = false;
try {
    $remediationActive = (bool)(Database::fetchOne(
        "SELECT is_active FROM modules WHERE module_key = 'remediation'"
    )['is_active'] ?? 0);
} catch (Throwable $e) {
    $remediationActive = false;
}
?>
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 <?= $isInline ? 'p-5 mb-4' : 'p-6 mb-6' ?>">
    <div class="flex items-start justify-between gap-4 flex-wrap">
        <div>
            <div class="flex items-center gap-3 flex-wrap">
                <h1 class="<?= $isInline ? 'text-xl' : 'text-2xl' ?> font-bold font-mono"><?= e((string)$cve['cve_id']) ?></h1>
                <span class="inline-flex px-2.5 py-0.5 text-xs rounded-full <?= $severityClass ?>"><?= e($severity !== '' ? $severity : 'Sin severidad') ?></span>
                <?php if (!empty($kev)): ?>
                    <span class="text-xs dark:bg-red-900/30 dark:text-red-300 status-failed">KEV</span>
                <?php endif; ?>
            </div>
            <p class="text-xs text-ink-soft mt-2">
                Publicado: <?= e(format_date($cve['published_at'] ?? null, 'd/m/Y')) ?>
                · Modificado: <?= e(format_date($cve['last_modified_at'] ?? null, 'd/m/Y')) ?>
                · Estado: <?= e((string)($cve['vuln_status'] ?? '—')) ?>
                <?php if (!empty($cve['source_identifier'])): ?> · Fuente: <?= e((string)$cve['source_identifier']) ?><?php endif; ?>
            </p>
        </div>
        <div class="flex items-center gap-2 flex-wrap justify-end">
            <?php if ($isInline): ?>
                <a href="<?= base_url('modules/cve/detail/' . rawurlencode((string)$cve['cve_id'])) ?>"
                   target="_blank" rel="noopener noreferrer"
                   class="inline-flex items-center gap-1.5 px-3 py-2 border border-line text-sm font-medium rounded-lg hover:bg-muted transition-colors">
                    Abrir ficha completa ↗
                </a>
            <?php endif; ?>
            <?php if (Auth::isAdmin()): ?>
                <a href="<?= base_url('modules/cve?tab=reports&new_cves=' . rawurlencode((string)$cve['cve_id'])) ?>"
                   title="Abre Informes con este CVE preparado. Al terminar podrás enviarlo a una empresa o grupo."
                   class="inline-flex items-center gap-1.5 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                    Enviar a Análisis de CVE de Informes
                </a>
            <?php endif; ?>
            <?php if ($remediationActive): ?>
                <a href="<?= base_url('modules/remediation?tab=tasks&new_cve=' . urlencode((string)$cve['cve_id'])) ?>"
                   class="inline-flex items-center gap-1.5 px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                    Crear tarea de remediación
                </a>
                <a href="<?= base_url('modules/remediation?tab=assistant&cve=' . urlencode((string)$cve['cve_id'])) ?>"
                   class="inline-flex items-center gap-1.5 px-3 py-2 border border-line text-sm font-medium rounded-lg hover:bg-muted transition-colors">
                    Preguntar a la IA
                </a>
            <?php endif; ?>
            <a href="<?= e((string)($cve['nvd_url'] ?? ('https://nvd.nist.gov/vuln/detail/' . $cve['cve_id']))) ?>"
               target="_blank" rel="noopener noreferrer"
               class="inline-flex items-center gap-1.5 px-3 py-2 border border-line text-sm font-medium rounded-lg hover:bg-muted transition-colors">
                Ver en NVD ↗
            </a>
            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer"
               class="inline-flex items-center gap-1.5 px-3 py-2 border border-line text-sm font-medium rounded-lg hover:bg-muted transition-colors">
                CISA KEV ↗
            </a>
        </div>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <div class="lg:col-span-2 space-y-6">
        <div class="card p-6">
            <h2 class="text-sm font-semibold mb-3">Descripción</h2>
            <?php if (!empty($cve['description_display'])): ?>
                <p class="text-sm text-ink whitespace-pre-line leading-relaxed"><?= e((string)$cve['description_display']) ?></p>
                <?php if (($cve['description_display_lang'] ?? '') !== 'es'): ?>
                    <p class="text-xs text-ink-soft mt-3">Descripción original en inglés; se traducirá al generar un informe con IA.</p>
                <?php endif; ?>
            <?php else: ?>
                <p class="text-sm text-ink-muted">NVD no devolvió descripción para este CVE.</p>
            <?php endif; ?>
        </div>

        <div class="card p-6">
            <h2 class="text-sm font-semibold mb-3">Productos afectados (CPE)</h2>
            <?php if (empty($products)): ?>
                <p class="text-sm text-ink-muted">NVD no devolvió productos CPE para este CVE.</p>
            <?php else: ?>
                <div class="flex flex-wrap gap-2">
                    <?php foreach ($products as $product): ?>
                        <span class="inline-flex px-2.5 py-1 text-xs rounded-lg bg-muted text-ink font-mono">
                            <?= e(trim(($product['vendor'] ?? '') . ':' . ($product['product'] ?? ''), ':')) ?>
                        </span>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <div class="card p-6">
            <h2 class="text-sm font-semibold mb-3">Referencias</h2>
            <?php if (empty($references)): ?>
                <p class="text-sm text-ink-muted">Sin referencias.</p>
            <?php else: ?>
                <ul class="space-y-2">
                    <?php foreach ($references as $url): ?>
                        <?php if (is_string($url) && $url !== ''): ?>
                            <li class="text-sm break-all">
                                <a href="<?= e($url) ?>" target="_blank" rel="noopener noreferrer" class="text-primary hover:underline"><?= e($url) ?></a>
                            </li>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </div>

    <div class="space-y-6">
        <div class="card p-6">
            <h2 class="text-sm font-semibold mb-3">Puntuación</h2>
            <dl class="space-y-3 text-sm">
                <div class="flex justify-between gap-3">
                    <dt class="text-ink-muted">CVSS v3</dt>
                    <dd class="font-semibold"><?= $cve['cvss_v3_score'] !== null ? e(number_format((float)$cve['cvss_v3_score'], 1)) : '—' ?></dd>
                </div>
                <div class="flex justify-between gap-3">
                    <dt class="text-ink-muted">Severidad</dt>
                    <dd><span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $severityClass ?>"><?= e($severity !== '' ? $severity : '—') ?></span></dd>
                </div>
                <?php if (!empty($cve['cvss_v3_vector'])): ?>
                    <div>
                        <dt class="text-ink-muted mb-1">Vector</dt>
                        <dd class="font-mono text-xs break-all text-ink-muted"><?= e((string)$cve['cvss_v3_vector']) ?></dd>
                    </div>
                <?php endif; ?>
                <?php if ($cve['cvss_v2_score'] !== null): ?>
                    <div class="flex justify-between gap-3">
                        <dt class="text-ink-muted">CVSS v2</dt>
                        <dd class="font-semibold"><?= e(number_format((float)$cve['cvss_v2_score'], 1)) ?></dd>
                    </div>
                <?php endif; ?>
                <?php if (!empty($epss)): ?>
                    <div class="flex justify-between gap-3">
                        <dt class="text-ink-muted">EPSS</dt>
                        <dd class="font-semibold text-right">
                            <?= e(number_format((float)$epss['epss'], 3)) ?>
                            <span class="text-xs text-ink-soft">(<?= e(number_format((float)$epss['percentile'], 2)) ?>)</span>
                            <?php if (!empty($epss['score_date'])): ?>
                                <span class="block text-[10px] text-ink-soft font-normal"><?= e((string)$epss['score_date']) ?></span>
                            <?php endif; ?>
                        </dd>
                    </div>
                <?php endif; ?>
            </dl>
        </div>

        <div class="card p-6">
            <h2 class="text-sm font-semibold mb-3">CWE</h2>
            <?php if (empty($cwes)): ?>
                <p class="text-sm text-ink-muted">Sin CWE.</p>
            <?php else: ?>
                <div class="flex flex-wrap gap-2">
                    <?php foreach ($cwes as $cwe): ?>
                        <span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-muted text-ink-muted font-mono"><?= e((string)$cwe) ?></span>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <div class="card p-6">
            <h2 class="text-sm font-semibold mb-3">Explotación</h2>
            <?php if (!empty($kev)): ?>
                <p class="text-sm text-danger font-medium">En CISA KEV</p>
                <p class="text-xs text-ink-muted mt-1">Añadido: <?= e((string)($kev['date_added'] ?? '—')) ?> · Vence: <?= e((string)($kev['due_date'] ?? '—')) ?></p>
                <p class="text-xs text-ink-muted mt-1">Ransomware: <?= e((string)($kev['known_ransomware'] ?? '—')) ?></p>
                <?php if (!empty($kev['required_action'])): ?>
                    <p class="text-xs text-ink-muted mt-2 line-clamp-4"><?= e((string)$kev['required_action']) ?></p>
                <?php endif; ?>
            <?php else: ?>
                <p class="text-sm text-ink-muted">No consta en CISA KEV.</p>
            <?php endif; ?>
        </div>
    </div>
</div>
