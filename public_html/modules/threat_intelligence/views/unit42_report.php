<?php
/**
 * Vista: informe con IA sobre publicaciones de Unit 42.
 */
$tiActiveTab = 'unit42';
require VIEWS_PATH . '/partials/ti_header.php';

$report = is_array($report ?? null) ? $report : [];
$tenantId = (int)($selectedTenant ?? 0);
$status = (string)($report['status'] ?? 'pending');
$wordHtml = Unit42Feed::reportWordHtml($report);
?>
<div class="space-y-4">
    <div class="card p-4">
        <div class="flex items-start justify-between gap-4 flex-wrap">
            <div class="min-w-0">
                <a href="<?= e(base_url('modules/threat_intelligence/unit42/reports')) ?>?tenant=<?= $tenantId ?>"
                   class="text-xs text-brand-600 hover:underline">← Informes con IA</a>
                <h2 class="text-sm font-semibold mt-3 break-words"><?= e((string)($report['title'] ?? 'Informe')) ?></h2>
                <p class="text-[11px] text-ink-muted mt-1">
                    Estado: <strong><?= e($status) ?></strong>
                    <?php if (!empty($report['model'])): ?> · modelo <?= e((string)$report['model']) ?><?php endif; ?>
                    <?php if (!empty($report['finished_at'])): ?> · terminado <?= e((string)$report['finished_at']) ?><?php endif; ?>
                </p>
                <?php if (!empty($report['error'])): ?>
                    <p class="text-xs text-danger mt-2 break-words"><?= e((string)$report['error']) ?></p>
                <?php endif; ?>
            </div>
            <?php if ($status === 'done'): ?>
                <div class="flex items-center gap-2 flex-wrap">
                    <button type="button" data-rd-action="copy-rich" data-rd-target="u42-report-sheet"
                            data-rd-html="u42-report-word"
                            class="px-3 py-1.5 bg-brand-500 hover:bg-brand-600 text-white text-xs font-medium rounded-lg">
                        Copiar informe
                    </button>
                    <button type="button" data-rd-action="download-html" data-rd-target="u42-report-sheet"
                            data-rd-html="u42-report-word" data-rd-filename="informe-unit42.html"
                            data-rd-title="Informe Unit 42"
                            class="px-3 py-1.5 border border-line-strong text-xs rounded-lg hover:bg-muted">
                        .html (Word)
                    </button>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <?php if ($status === 'done'): ?>
        <div class="card p-6">
            <div id="u42-report-sheet" class="md-body ai-report-body">
                <?= function_exists('render_ai_markdown') ? render_ai_markdown((string)($report['content_md'] ?? '')) : nl2br(e((string)($report['content_md'] ?? ''))) ?>
            </div>
        </div>
        <template id="u42-report-word"><?= $wordHtml ?></template>
    <?php elseif ($status === 'pending' || $status === 'running'): ?>
        <div class="card p-10 text-center">
            <p class="text-sm font-semibold">El informe se está generando…</p>
            <p class="text-xs text-ink-muted mt-2">Esta página se actualizará sola cuando termine.</p>
        </div>
    <?php endif; ?>
</div>

<?php if ($status === 'pending' || $status === 'running'): ?>
<script>
(function () {
    'use strict';
    var timer = setInterval(function () {
        fetch('<?= e(base_url('modules/threat_intelligence/unit42/report/' . (int)($report['id'] ?? 0) . '/data')) ?>', {
            headers: {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'},
            credentials: 'same-origin'
        }).then(function (r) { return r.json(); }).then(function (st) {
            if (st && (st.status === 'done' || st.status === 'error' || st.status === 'canceled')) {
                clearInterval(timer);
                window.location.reload();
            }
        }).catch(function () { /* reintenta */ });
    }, 3000);
})();
</script>
<?php endif; ?>
