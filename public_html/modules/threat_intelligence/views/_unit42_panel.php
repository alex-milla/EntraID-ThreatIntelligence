<?php
/**
 * Parcial reutilizable: cuerpo de un artículo de Unit 42.
 *
 * Lo usan la ficha completa (unit42_article.php) y el panel que se despliega
 * en línea desde el listado (ruta GET unit42/{id}/panel). Así el marcado de
 * secciones, IOCs y botones de estado existe una sola vez.
 *
 * Variables de entrada: $article, $tenantId, $isRead, $isFavorite, $panelMode,
 * $reports (informes con IA ya generados sobre esta publicación).
 */
$article = is_array($article ?? null) ? $article : [];
$articleId = (int)($article['id'] ?? 0);
$tenantId = (int)($tenantId ?? 0);
$isRead = !empty($isRead);
$isFavorite = !empty($isFavorite);
$panelMode = !empty($panelMode);
$reports = is_array($reports ?? null) ? $reports : [];
$fresh = Unit42Feed::freshness($article);
$updatedAt = (string)($article['updated_at'] ?? '');

$iocs = Unit42Feed::iocs($articleId);
$iocCounts = Unit42Feed::iocCounts($articleId);
$sections = is_array($article['sections'] ?? null) ? $article['sections'] : [];

/** Escapa y convierte URLs en enlaces (el contenido original no se modifica). */
$renderText = static function (string $text): string {
    $escaped = e($text);
    return preg_replace(
        '~https?://[^\s<>"]+~i',
        '<a href="$0" target="_blank" rel="noopener noreferrer" class="text-brand-600 hover:underline break-all">$0</a>',
        $escaped
    ) ?? $escaped;
};

$rawUrl = 'https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/'
    . rawurlencode((string)($article['path'] ?? ''));
$fullUrl = base_url('modules/threat_intelligence/unit42/' . $articleId) . '?tenant=' . $tenantId;
$rawId = 'u42-raw-' . $articleId;
$reportId = 'u42-report-' . $articleId;
?>
<div class="space-y-3">
    <?php if ($panelMode): ?>
        <div class="flex items-center gap-2 flex-wrap">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft">
                Informe Unit 42
                <?= (string)($article['published_at'] ?? '') !== '' ? '· ' . e(format_date((string)$article['published_at'])) : '' ?>
                <?php if ($fresh['updated']): ?>
                    · <span title="El fichero se modificó en el repositorio">actualizado <?= e(format_date($updatedAt)) ?></span>
                <?php endif; ?>
            </p>
            <?php if ($fresh['new24']): ?>
                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-warning-bg text-warning"
                      title="Descargado en las últimas 24 h">24 h</span>
            <?php endif; ?>
            <?php if ($fresh['updated24']): ?>
                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300"
                      title="Fichero modificado en GitHub y vuelto a descargar">Actualizado</span>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    <p class="text-[11px] text-ink-muted truncate">
        Fichero: <a href="<?= e($rawUrl) ?>" target="_blank" rel="noopener"
                    class="text-brand-600 hover:underline"><?= e((string)($article['path'] ?? '')) ?></a>
    </p>

    <?php if ($iocCounts !== []): ?>
        <div class="card p-4">
            <h4 class="text-sm font-semibold m-0">IOCs detectados</h4>
            <p class="text-[11px] text-ink-muted mt-1">
                Extraídos de la sección INDICATORS. El fichero original permanece intacto.
            </p>
            <div class="flex flex-wrap gap-1.5 mt-3">
                <?php foreach ($iocCounts as $count): ?>
                    <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-muted text-[10px] text-ink-muted">
                        <strong><?= e((string)$count['ioc_type']) ?></strong> <?= (int)$count['c'] ?>
                    </span>
                <?php endforeach; ?>
            </div>
            <div class="flex flex-wrap gap-2 mt-3">
                <button type="button"
                        onclick="IOCExtractor.open({source:'u42', articleIds:[<?= $articleId ?>], format:'stix'})"
                        class="px-2.5 py-1 bg-brand-500 hover:bg-brand-600 text-white text-[11px] font-medium rounded-lg">
                    Extraer IOCs
                </button>
                <span class="text-[10px] text-ink-soft self-center">Revisa y configura el formato antes de exportar.</span>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($reports !== []): ?>
        <?php
        $reportKinds = Unit42Feed::reportKinds();
        $statusMap = [
            'done'     => ['Listo', 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'],
            'running'  => ['Generando', 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'],
            'pending'  => ['En cola', 'bg-gray-100 text-gray-600'],
            'error'    => ['Error', 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'],
            'canceled' => ['Cancelado', 'bg-amber-100 text-amber-700'],
        ];
        ?>
        <div class="card p-4">
            <h4 class="text-sm font-semibold m-0">Informes con IA de esta publicación</h4>
            <div class="mt-2 divide-y divide-line-subtle">
                <?php foreach ($reports as $report): ?>
                    <?php
                    $status = (string)($report['status'] ?? 'pending');
                    $statusLabel = $statusMap[$status] ?? [$status, 'bg-gray-100 text-gray-600'];
                    $kindLabel = $reportKinds[(string)($report['kind'] ?? '')]['label'] ?? (string)($report['kind'] ?? '');
                    ?>
                    <a href="<?= e(base_url('modules/threat_intelligence/unit42/report/' . (int)$report['id'])) ?>?tenant=<?= $tenantId ?>"
                       class="flex items-start justify-between gap-3 py-2 hover:bg-muted/50">
                        <span class="min-w-0">
                            <span class="block text-xs font-medium break-words"><?= e((string)($report['title'] ?? 'Informe')) ?></span>
                            <span class="block text-[10px] text-ink-muted mt-0.5">
                                <?= e($kindLabel) ?> · <?= e((string)($report['created_at'] ?? '')) ?>
                                <?php if (!empty($report['model'])): ?> · <?= e((string)$report['model']) ?><?php endif; ?>
                            </span>
                        </span>
                        <span class="shrink-0 px-2 py-0.5 rounded-full text-[10px] font-medium <?= $statusLabel[1] ?>"><?= e($statusLabel[0]) ?></span>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endif; ?>

    <div class="card p-4">
        <div class="flex items-center justify-between gap-3 flex-wrap mb-3">
            <h4 class="text-sm font-semibold m-0">Análisis</h4>
            <button type="button" class="u42-raw-toggle px-2.5 py-1 border border-line-strong text-[11px] rounded-lg hover:bg-muted"
                    data-raw="<?= e($rawId) ?>" data-report="<?= e($reportId) ?>">
                Ver texto original
            </button>
        </div>

        <div id="<?= e($reportId) ?>" class="u42-report space-y-3">
            <?php if ($sections === []): ?>
                <pre class="whitespace-pre-wrap text-xs text-ink-muted"><?= e((string)($article['content'] ?? '')) ?></pre>
            <?php else: ?>
                <?php foreach ($sections as $section): ?>
                    <section class="border border-line rounded-lg p-3">
                        <h5 class="text-xs font-semibold uppercase tracking-wide text-brand-600 mb-2">
                            <?= e((string)($section['title'] ?? '')) ?>
                        </h5>
                        <ul class="space-y-1.5">
                            <?php foreach (($section['items'] ?? []) as $item): ?>
                                <?php $depth = max(0, min(4, (int)($item['depth'] ?? 0))); ?>
                                <li class="text-xs leading-relaxed <?= $depth > 0 ? 'text-ink-muted' : 'text-ink' ?>"
                                    style="padding-left: <?= $depth * 18 ?>px;">
                                    <?php if (!empty($item['label'])): ?>
                                        <strong class="text-ink"><?= $renderText((string)$item['text']) ?></strong>
                                    <?php else: ?>
                                        <span class="text-brand-500 mr-1"><?= str_repeat('–', max(1, $depth)) ?></span>
                                        <?= $renderText((string)$item['text']) ?>
                                    <?php endif; ?>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </section>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <pre id="<?= e($rawId) ?>" hidden class="hidden whitespace-pre-wrap break-words text-xs text-ink-muted bg-muted/40 rounded-lg p-3 mt-2"><?= e((string)($article['content'] ?? '')) ?></pre>
    </div>

    <div class="flex items-center gap-2 flex-wrap no-print">
        <button type="button"
                class="u42-read-toggle w-7 h-7 inline-flex items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 <?= $isRead ? 'text-green-500' : 'text-gray-400' ?>"
                data-id="<?= $articleId ?>" data-read="<?= $isRead ? '1' : '0' ?>"
                title="<?= $isRead ? 'Dejar sin leer' : 'Marcar como leído' ?>">
            <i class="material-icons icon-16" aria-hidden="true">check</i>
        </button>
        <button type="button"
                class="u42-fav-toggle w-7 h-7 inline-flex items-center justify-center rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 text-base leading-none <?= $isFavorite ? 'text-amber-400' : 'text-gray-300 dark:text-gray-600' ?>"
                data-id="<?= $articleId ?>" data-fav="<?= $isFavorite ? '1' : '0' ?>"
                title="<?= $isFavorite ? 'Quitar de favoritos' : 'Añadir a favoritos' ?>">
            <?= $isFavorite ? '★' : '☆' ?>
        </button>
        <?php if ($panelMode): ?>
            <a href="<?= e($fullUrl) ?>" class="px-2.5 py-1 text-xs text-brand-600 hover:underline">Abrir ficha completa ↗</a>
        <?php else: ?>
            <a href="<?= e($rawUrl) ?>" target="_blank" rel="noopener" class="px-2.5 py-1 text-xs text-brand-600 hover:underline">Ver en GitHub ↗</a>
        <?php endif; ?>
    </div>
</div>
