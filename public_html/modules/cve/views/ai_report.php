<?php
/**
 * Vista: página completa del informe de CVE con IA.
 * Variables: $report, $items, $aiText, $sections.
 *
 * El documento vive en _ai_report_body.php y se reutiliza en el workspace.
 */

$report = is_array($report ?? null) ? $report : null;
$items = is_array($items ?? null) ? $items : [];
$aiText = (string)($aiText ?? '');
$sections = is_array($sections ?? null) ? $sections : [];
$defender = is_array($defender ?? null) ? $defender : null;
$isAdmin = $isAdmin ?? Auth::isAdmin();

$status = (string)($report['status'] ?? 'pending');
$isProcessing = in_array($status, ['pending', 'running'], true);

$tab = 'reports';
require __DIR__ . '/_tabs.php';
?>
<?php if ($report === null): ?>
    <div class="bg-white rounded-xl border border-red-200 p-6">
        <h1 class="text-lg font-semibold text-red-600">Informe no encontrado</h1>
        <p class="text-sm text-gray-500 mt-2">El informe solicitado no existe o ha sido eliminado.</p>
        <a href="<?= base_url('modules/cve?tab=reports') ?>" class="inline-block mt-4 text-sm text-brand-600 hover:underline">Volver a informes</a>
    </div>
<?php else: ?>

    <div class="mb-5 flex items-start justify-between gap-4 flex-wrap no-print">
        <a href="<?= base_url('modules/cve?tab=reports') ?>" class="inline-flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19l-7-7 7-7"/></svg>
            Informes CVE
        </a>
        <div class="flex items-center gap-2 flex-wrap">
            <a href="<?= base_url('modules/cve?tab=reports&report=' . (int)$report['id']) ?>"
               class="px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-muted-dark transition-colors">
                Abrir en el workspace
            </a>
            <?php if (!$isProcessing): ?>
                <button type="button" onclick="window.print()"
                        class="px-3 py-2 bg-gray-900 hover:bg-black text-white text-sm font-medium rounded-lg transition-colors">
                    Imprimir / PDF
                </button>
            <?php endif; ?>
            <button type="button" disabled title="Pendiente de configurar: el envío por email llegará en una próxima versión."
                    class="px-3 py-2 border border-gray-300 text-sm font-medium rounded-lg opacity-50 cursor-not-allowed">
                Enviar por email
            </button>
        </div>
    </div>

    <?php require __DIR__ . '/_ai_report_body.php'; ?>

    <?php if ($isProcessing || $status === 'error' || $status === 'canceled'): ?>
    <script>
    (function () {
        'use strict';

        var STATUS_URL = <?= json_encode(base_url('modules/cve/reports/ai-status/' . (int)$report['id'])) ?>;
        var RETRY_URL  = <?= json_encode(base_url('modules/cve/reports/ai-retry/' . (int)$report['id'])) ?>;
        var RUN_URL    = <?= json_encode(base_url('modules/cve/reports/ai-run/' . (int)$report['id'])) ?>;
        var CANCEL_URL = <?= json_encode(base_url('modules/cve/reports/ai-cancel/' . (int)$report['id'])) ?>;
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
                    if (res.success && (res.status === 'done' || res.status === 'error' || res.status === 'canceled')) {
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
                    appAlert(res.error || 'No se pudo reintentar el informe.', { title: 'No se pudo reintentar' });
                    return;
                }
                window.location.reload();
            }).catch(function (err) {
                appAlert('No se pudo reintentar: ' + errorText(err), { title: 'No se pudo reintentar' });
            });
        }

        function cancel() {
            appConfirm('¿Cancelar la generación de este informe?', {
                title: 'Cancelar informe',
                danger: true,
                confirmText: 'Cancelar informe'
            }).then(function (ok) {
                if (!ok) {
                    return;
                }
                postJson(CANCEL_URL, {}).then(function (res) {
                    if (!res.success) {
                        appAlert(res.error || 'No se pudo cancelar el informe.', { title: 'No se pudo cancelar' });
                        return;
                    }
                    window.location.reload();
                }).catch(function (err) {
                    appAlert('No se pudo cancelar: ' + errorText(err), { title: 'No se pudo cancelar' });
                });
            });
        }

        window.runCveAiReport = runNow;
        window.retryCveAiReport = retry;
        window.cancelCveAiReport = cancel;

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
<?php endif; ?>
