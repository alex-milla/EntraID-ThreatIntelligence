<?php
/**
 * Vista: historial de informes con IA sobre publicaciones Unit 42.
 */

$reports = is_array($reports ?? null) ? $reports : [];
$kinds = is_array($kinds ?? null) ? $kinds : [];
$tenantId = (int)($selectedTenant ?? 0);
$labels = [
    'pending'  => ['En cola', 'bg-gray-100 text-gray-600'],
    'running'  => ['Generando', 'bg-blue-100 text-blue-700'],
    'done'     => ['Listo', 'bg-green-100 text-green-700'],
    'error'    => ['Error', 'bg-red-100 text-red-700'],
    'canceled' => ['Cancelado', 'bg-amber-100 text-amber-700'],
];
?>
<div class="space-y-4">
    <div class="card p-4">
        <div class="flex items-start justify-between gap-4 flex-wrap">
            <div>
                <h2 class="text-sm font-semibold">Informes con IA · Unit 42</h2>
                <p class="text-xs text-ink-muted mt-1">
                    Generados a partir de las publicaciones que selecciones en el listado.
                    Cada informe cita sus fuentes y no inventa datos.
                </p>
            </div>
            <a href="<?= e(base_url('modules/unit42')) ?>?tenant=<?= $tenantId ?>"
               class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">← Publicaciones</a>
        </div>
    </div>

    <div class="card overflow-hidden">
        <?php if ($reports === []): ?>
            <p class="p-8 text-center text-sm text-ink-muted">
                Todavía no hay informes. Selecciona publicaciones en el listado y pulsa «Informe con IA».
            </p>
        <?php else: ?>
            <div class="divide-y divide-line-subtle">
                <?php foreach ($reports as $report): ?>
                    <?php
                    $status = (string)($report['status'] ?? 'pending');
                    $label = $labels[$status] ?? [$status, 'bg-gray-100 text-gray-600'];
                    $kindLabel = $kinds[(string)($report['kind'] ?? '')]['label'] ?? (string)($report['kind'] ?? '');
                    ?>
                    <a href="<?= e(base_url('modules/unit42/report/' . (int)$report['id'])) ?>?tenant=<?= $tenantId ?>"
                       class="block px-4 py-3 hover:bg-muted/50">
                        <div class="flex items-start justify-between gap-3 flex-wrap">
                            <div class="min-w-0">
                                <p class="text-sm font-medium break-words"><?= e((string)($report['title'] ?? '')) ?></p>
                                <p class="text-[11px] text-ink-muted mt-1">
                                    <?= e($kindLabel) ?> · <?= count(json_decode((string)($report['article_ids_json'] ?? '[]'), true) ?: []) ?> publicaciones
                                    · <?= e((string)($report['created_at'] ?? '')) ?>
                                    <?php if (!empty($report['model'])): ?> · <?= e((string)$report['model']) ?><?php endif; ?>
                                </p>
                                <?php if (!empty($report['error'])): ?>
                                    <p class="text-[11px] text-danger mt-1"><?= e((string)$report['error']) ?></p>
                                <?php endif; ?>
                            </div>
                            <span class="px-2 py-0.5 rounded-full text-[10px] font-medium <?= $label[1] ?>"><?= e($label[0]) ?></span>
                        </div>
                    </a>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</div>
