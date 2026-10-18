<?php
/**
 * Vista: informe de CVE generado con IA (formato SploitScan).
 * Variables: $report, $profiles.
 */

$report = is_array($report ?? null) ? $report : null;
$profiles = is_array($profiles ?? null) ? $profiles : [];

$status = (string)($report['status'] ?? 'pending');
$content = trim((string)($report['content_text'] ?? ''));
$aiError = trim((string)($report['ai_error'] ?? ''));
$cveIds = safe_json_decode((string)($report['cve_ids'] ?? ''), []);
if (!is_array($cveIds)) {
    $cveIds = [];
}
$isProcessing = in_array($status, ['pending', 'running'], true);
$hasContent = $content !== '';

$statusLabels = [
    'pending' => 'En cola',
    'running' => 'Generando con IA',
    'done'    => 'Listo',
    'error'   => 'Error de IA',
];
$statusClasses = [
    'pending' => 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300',
    'running' => 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    'done'    => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    'error'   => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
];
?>

<?php if ($report === null): ?>
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-red-200 dark:border-red-800 p-6">
        <h1 class="text-lg font-semibold text-red-600 dark:text-red-400">Informe no encontrado</h1>
        <p class="text-sm text-gray-500 mt-2">El informe solicitado no existe o ha sido eliminado.</p>
        <a href="<?= base_url('modules/cve?tab=reports') ?>" class="inline-block mt-4 text-sm text-brand-600 dark:text-brand-400 hover:underline">Volver a informes</a>
    </div>
<?php else: ?>

    <div class="mb-5 flex items-start justify-between gap-4 flex-wrap no-print">
        <a href="<?= base_url('modules/cve?tab=reports') ?>" class="inline-flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19l-7-7 7-7"/></svg>
            Informes CVE
        </a>
        <div class="flex items-center gap-2 flex-wrap">
            <?php if ($hasContent): ?>
                <button type="button" onclick="copyCveAiReport(this)"
                        class="px-3 py-2 border border-gray-200 dark:border-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                    Copiar
                </button>
                <a href="<?= base_url('modules/cve/report-ai/' . (int)$report['id'] . '/txt') ?>"
                   class="px-3 py-2 border border-gray-200 dark:border-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                    Descargar .txt
                </a>
                <button type="button" onclick="window.print()"
                        class="px-3 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">
                    Imprimir / PDF
                </button>
            <?php endif; ?>
            <button type="button" disabled title="Pendiente de configurar: el envío por email llegará en una próxima versión."
                    class="px-3 py-2 border border-gray-200 dark:border-gray-700 text-sm font-medium rounded-lg opacity-50 cursor-not-allowed">
                Enviar por email
            </button>
        </div>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-5">
        <div class="flex items-start justify-between gap-4 flex-wrap">
            <div class="min-w-0">
                <p class="text-xs font-semibold uppercase tracking-wide text-brand-600 dark:text-brand-400">Informe de CVE con IA</p>
                <h1 class="text-xl font-bold mt-1 break-words"><?= e((string)($report['title'] ?? 'Informe CVE')) ?></h1>
                <div class="flex items-center gap-1.5 flex-wrap mt-3">
                    <?php foreach ($cveIds as $cveId): ?>
                        <a href="https://nvd.nist.gov/vuln/detail/<?= e(rawurlencode((string)$cveId)) ?>"
                           target="_blank" rel="noopener"
                           class="px-2 py-0.5 rounded-full bg-gray-100 dark:bg-gray-800 text-[11px] font-mono text-gray-600 dark:text-gray-300 hover:text-brand-600 dark:hover:text-brand-400">
                            <?= e((string)$cveId) ?>
                        </a>
                    <?php endforeach; ?>
                </div>
                <p class="text-xs text-gray-500 mt-3">
                    <span class="inline-flex px-2 py-0.5 text-[10px] rounded-full <?= $statusClasses[$status] ?? $statusClasses['pending'] ?>">
                        <?= e($statusLabels[$status] ?? $status) ?>
                    </span>
                    <?php if (!empty($report['ai_model'])): ?>
                        · Modelo: <?= e((string)$report['ai_model']) ?>
                    <?php endif; ?>
                    <?php if (!empty($report['ai_duration_ms'])): ?>
                        · <?= e(number_format((int)$report['ai_duration_ms'] / 1000, 1, ',', '.')) ?> s
                    <?php endif; ?>
                    · Generado <?= e(format_db_date((string)($report['created_at'] ?? ''), 'd/m/Y H:i')) ?>
                </p>
            </div>
            <div class="text-right text-xs text-gray-400">
                <p class="font-semibold text-gray-600 dark:text-gray-300">EntraID Threat Intelligence</p>
                <p>Fuentes: NVD · CISA KEV · EPSS</p>
            </div>
        </div>
    </div>

    <?php if ($isProcessing): ?>
        <div class="mb-5 px-4 py-3 rounded-lg text-sm bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300 flex items-start justify-between gap-3 flex-wrap" id="ai-processing-banner">
            <div class="flex items-center gap-3 min-w-0">
                <svg class="w-4 h-4 animate-spin shrink-0" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"/></svg>
                <span id="ai-processing-text">La IA está redactando la evaluación de riesgo. Esta página se actualizará sola cuando termine.</span>
            </div>
            <button type="button" onclick="runCveAiReport()"
                    class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium rounded-lg transition-colors shrink-0">
                Ejecutar ahora
            </button>
        </div>
    <?php endif; ?>

    <?php if ($status === 'error' && $aiError !== ''): ?>
        <div class="mb-5 px-4 py-3 rounded-lg text-sm bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300 flex items-start justify-between gap-3 flex-wrap">
            <div class="min-w-0">
                <p class="font-semibold">La evaluación con IA no se pudo completar</p>
                <p class="text-xs mt-1 break-words"><?= e($aiError) ?></p>
            </div>
            <button type="button" onclick="retryCveAiReport(this)"
                    class="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs font-medium rounded-lg transition-colors shrink-0">
                Reintentar
            </button>
        </div>
    <?php endif; ?>

    <?php if ($hasContent): ?>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
            <pre id="ai-report-content" class="ai-report-pre p-5 overflow-x-auto whitespace-pre text-[12px] leading-relaxed text-gray-800 dark:text-gray-200 font-mono"><?= e($content) ?></pre>
        </div>
        <p class="text-[11px] text-gray-400 mt-3 leading-relaxed">
            El informe combina datos del catálogo local (NVD, CISA KEV y EPSS) con una evaluación generada por IA.
            La prioridad de parcheo se calcula con la fórmula de SploitScan (KEV, CVSS, EPSS y exploits públicos).
            Verifica siempre la información antes de tomar decisiones.
        </p>
    <?php elseif (!$isProcessing): ?>
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center">
            <h2 class="text-sm font-semibold">Sin contenido</h2>
            <p class="text-sm text-gray-500 mt-2">El informe no tiene contenido. Vuelve a generarlo desde la pestaña Informes.</p>
        </div>
    <?php endif; ?>

    <style>
        @media print {
            .ai-report-pre {
                font-size: 9pt;
                line-height: 1.25;
                white-space: pre-wrap;
                word-break: break-word;
                color: #000 !important;
                background: #fff !important;
                padding: 0 !important;
            }
            .ai-report-pre + p { display: none; }
        }
    </style>

    <script>
    (function () {
        'use strict';

        var STATUS_URL = <?= json_encode(base_url('modules/cve/reports/ai-status/' . (int)$report['id'])) ?>;
        var RETRY_URL  = <?= json_encode(base_url('modules/cve/reports/ai-retry/' . (int)$report['id'])) ?>;
        var RUN_URL    = <?= json_encode(base_url('modules/cve/reports/ai-run/' . (int)$report['id'])) ?>;
        var CONTENT    = <?= json_encode($content, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        var STATUS     = <?= json_encode($status) ?>;

        var pollTimer = null;
        var running = false;

        function csrfToken() {
            var el = document.querySelector('input[name="csrf_token"]');
            return el ? el.value : '';
        }

        function parseResponse(res) {
            return res.text().then(function (text) {
                var payload;
                try {
                    payload = text ? JSON.parse(text) : {};
                } catch (e) {
                    var snippet = (text || '').replace(/\s+/g, ' ').trim().slice(0, 160);
                    var err = new Error('HTTP ' + res.status + (snippet ? ' · ' + snippet : ''));
                    err.httpStatus = res.status;
                    throw err;
                }
                if (res.status === 401) {
                    window.location.href = (window.APP_URL || '') + '/admin/login';
                }
                return payload;
            });
        }

        function postJson(url, data) {
            return fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': csrfToken()
                },
                credentials: 'same-origin',
                body: JSON.stringify(data || {})
            }).then(parseResponse);
        }

        function getJson(url) {
            return fetch(url, {
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'same-origin'
            }).then(parseResponse);
        }

        function errorText(err) {
            return (err && err.message) ? err.message : 'error de red';
        }

        function setBanner(text) {
            var el = document.getElementById('ai-processing-text');
            if (el) {
                el.textContent = text;
            }
        }

        function startPolling() {
            if (pollTimer) {
                return;
            }
            var tries = 0;
            pollTimer = setInterval(function () {
                tries++;
                if (tries > 300) {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    return;
                }
                getJson(STATUS_URL).then(function (res) {
                    if (res.success && (res.status === 'done' || res.status === 'error')) {
                        clearInterval(pollTimer);
                        pollTimer = null;
                        window.location.reload();
                    }
                }).catch(function () { /* se reintenta */ });
            }, 3000);
        }

        function runNow() {
            if (running) {
                return;
            }
            running = true;
            startPolling();
            setBanner('Ejecutando el informe… si la conexión se corta, seguiremos consultando el estado.');

            postJson(RUN_URL, {}).then(function (res) {
                if (res && res.url) {
                    window.location.href = res.url;
                    return;
                }
                if (res && res.error) {
                    setBanner(res.error);
                }
            }).catch(function (err) {
                setBanner('No se pudo ejecutar: ' + errorText(err) + '. Seguimos comprobando el estado…');
                startPolling();
            }).then(function () {
                running = false;
            });
        }

        function retry() {
            postJson(RETRY_URL, {}).then(function (res) {
                if (!res.success) {
                    alert(res.error || 'No se pudo reintentar el informe.');
                    return;
                }
                window.location.reload();
            }).catch(function (err) {
                alert('No se pudo reintentar: ' + errorText(err));
            });
        }

        function fallbackCopy(text, done) {
            var area = document.createElement('textarea');
            area.value = text;
            area.style.position = 'fixed';
            area.style.opacity = '0';
            document.body.appendChild(area);
            area.select();
            try { document.execCommand('copy'); if (done) done(); } catch (e) {}
            document.body.removeChild(area);
        }

        function copyReport(button) {
            var text = CONTENT || '';
            if (!text) {
                return;
            }
            var done = function () {
                var original = button.textContent;
                button.textContent = 'Copiado';
                setTimeout(function () { button.textContent = original; }, 1500);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done).catch(function () {
                    fallbackCopy(text, done);
                });
            } else {
                fallbackCopy(text, done);
            }
        }

        // Los onclick del HTML deben encontrar las funciones.
        window.runCveAiReport = runNow;
        window.retryCveAiReport = retry;
        window.copyCveAiReport = copyReport;

        function ready(fn) {
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', fn);
            } else {
                fn();
            }
        }

        ready(function () {
            if (STATUS === 'pending') {
                runNow();
            } else if (STATUS === 'running') {
                startPolling();
            }

            if (STATUS === 'pending' || STATUS === 'running') {
                setTimeout(function () {
                    if (document.getElementById('ai-processing-banner')) {
                        setBanner('Está tardando más de lo normal. Pulsa «Ejecutar ahora» o revisa Admin → Logs (canal cve_ai).');
                    }
                }, 45000);
            }
        });
    })();
    </script>
<?php endif; ?>
