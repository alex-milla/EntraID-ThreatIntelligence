<?php
/**
 * Vista: un fichero de Unit 42 mostrado como informe, sin tocar el original.
 */
$tiActiveTab = 'unit42';
require VIEWS_PATH . '/partials/ti_header.php';

$article = is_array($article ?? null) ? $article : [];
$iocs = is_array($iocs ?? null) ? $iocs : [];
$iocCounts = is_array($iocCounts ?? null) ? $iocCounts : [];
$sections = is_array($article['sections'] ?? null) ? $article['sections'] : [];

/** Escapa y convierte URLs en enlaces (el contenido original no se modifica). */
$renderText = static function (string $text): string {
    $escaped = e($text);
    return preg_replace(
        '~https?://[^\s<>"\']+~i',
        '<a href="$0" target="_blank" rel="noopener noreferrer" class="text-brand-600 hover:underline break-all">$0</a>',
        $escaped
    ) ?? $escaped;
};

$rawUrl = 'https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/'
    . rawurlencode((string)($article['path'] ?? ''));
$articleId = (int)($article['id'] ?? 0);
$tenantId = (int)($selectedTenant ?? 0);
$exportBase = base_url('modules/export/download') . '?source=u42&article_id=' . $articleId . '&tenant=' . $tenantId;
?>
<div class="space-y-4">
    <div class="card p-5">
        <div class="flex items-start justify-between gap-4 flex-wrap">
            <div class="min-w-0">
                <a href="<?= e(base_url('modules/threat_intelligence/unit42')) ?>?tenant=<?= $tenantId ?>"
                   class="text-xs text-brand-600 hover:underline">← Unit42</a>
                <p class="text-[10px] font-semibold uppercase tracking-wide text-ink-soft mt-3">
                    Informe Unit 42 <?= (string)($article['published_at'] ?? '') !== '' ? '· ' . e((string)$article['published_at']) : '' ?>
                </p>
                <h2 class="text-lg font-bold mt-1 break-words"><?= e((string)($article['title'] ?? '')) ?></h2>
                <p class="text-[11px] text-ink-muted mt-2 truncate">
                    Fichero: <a href="<?= e($rawUrl) ?>" target="_blank" rel="noopener" class="text-brand-600 hover:underline"><?= e((string)($article['path'] ?? '')) ?></a>
                </p>
            </div>
            <a href="<?= e($rawUrl) ?>" target="_blank" rel="noopener"
               class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">Ver en GitHub ↗</a>
        </div>
    </div>

    <?php if ($iocCounts !== []): ?>
        <div class="card p-4">
            <div class="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h3 class="text-sm font-semibold m-0">IOCs detectados</h3>
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
                </div>
                <div class="flex flex-wrap gap-2">
                    <a href="<?= e($exportBase . '&format=stix') ?>" class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">STIX 2.1</a>
                    <a href="<?= e($exportBase . '&format=misp') ?>" class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">MISP</a>
                    <a href="<?= e($exportBase . '&format=txt') ?>" class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">TXT</a>
                    <a href="<?= e($exportBase . '&format=csv') ?>" class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">CSV</a>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <div class="card p-5">
        <div class="flex items-center justify-between gap-3 flex-wrap mb-4">
            <h3 class="text-sm font-semibold m-0">Análisis</h3>
            <button type="button" onclick="u42ToggleRaw()"
                    class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">
                Ver texto original
            </button>
        </div>

        <div id="u42-report" class="space-y-5">
            <?php if ($sections === []): ?>
                <pre class="whitespace-pre-wrap text-xs text-ink-muted"><?= e((string)($article['content'] ?? '')) ?></pre>
            <?php else: ?>
                <?php foreach ($sections as $section): ?>
                    <section class="border border-line rounded-lg p-4">
                        <h4 class="text-xs font-semibold uppercase tracking-wide text-brand-600 mb-2">
                            <?= e((string)($section['title'] ?? '')) ?>
                        </h4>
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

        <pre id="u42-raw" hidden class="hidden whitespace-pre-wrap break-words text-xs text-ink-muted bg-muted/40 rounded-lg p-4 mt-2"><?= e((string)($article['content'] ?? '')) ?></pre>
    </div>
</div>

<script>
(function () {
    'use strict';
    var showing = false;
    window.u42ToggleRaw = function () {
        var raw = document.getElementById('u42-raw');
        var report = document.getElementById('u42-report');
        if (!raw || !report) { return; }
        showing = !showing;
        raw.hidden = !showing;
        raw.classList.toggle('hidden', !showing);
        report.classList.toggle('hidden', showing);
    };
})();
</script>
