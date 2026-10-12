<?php
/**
 * Vista: detalle de incidente (datos, alertas, MITRE, evidencia) + análisis IA manual.
 */
$sev = strtolower((string)($incident['severity'] ?? ''));
$sevClass = in_array($sev, ['high', 'critical'], true) ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
    : ($sev === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
    : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300');

$mitreOf = function ($raw): array {
    $d = safe_json_decode((string)$raw, []);
    return is_array($d) ? array_values(array_filter(array_map('strval', $d))) : [];
};
$evLabel = function (array $e): string {
    if (!empty($e['ipAddress'])) { return (string)$e['ipAddress']; }
    if (!empty($e['url'])) { return (string)$e['url']; }
    if (!empty($e['userAccount']['accountName'])) { return (string)$e['userAccount']['accountName']; }
    if (!empty($e['deviceDnsName'])) { return (string)$e['deviceDnsName']; }
    if (!empty($e['fileDetails']['fileName'])) { return (string)$e['fileDetails']['fileName']; }
    if (!empty($e['process']['filePath'])) { return (string)$e['process']['filePath']; }
    if (!empty($e['processCommandLine'])) { return truncate((string)$e['processCommandLine'], 160); }
    return '';
};

$tags = safe_json_decode((string)($incident['custom_tags'] ?? ''), []);
$raItems = null;
if (!empty($incident['recommended_actions'])) {
    $d = json_decode((string)$incident['recommended_actions'], true);
    if (is_array($d)) { $raItems = $d; }
}
?>
<div class="mb-6">
    <a href="<?= base_url('modules/incidents?tenant=' . (int)$incident['tenant_id']) ?>" class="text-xs text-brand-500 hover:underline">← Volver a incidentes</a>
    <div class="flex items-start justify-between gap-3 mt-3 flex-wrap">
        <div class="min-w-0">
            <h2 class="text-xl font-bold"><?= e($incident['display_name']) ?></h2>
            <p class="text-xs text-gray-400 mt-1">
                <?= e($tenant['name'] ?? '') ?> · Creado: <?= e($incident['created_date'] ?? '—') ?>
                <?php if (!empty($incident['last_update_date'])): ?> · Actualizado: <?= e($incident['last_update_date']) ?><?php endif; ?>
            </p>
        </div>
        <span class="inline-flex px-3 py-1 text-xs rounded-full shrink-0 <?= $sevClass ?>"><?= e($incident['severity'] ?: '—') ?></span>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Columna izquierda: datos -->
    <div class="lg:col-span-2 space-y-6">
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
            <h3 class="text-sm font-semibold mb-4">Detalles</h3>
            <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
                <div><dt class="text-xs text-gray-500">Estado</dt><dd class="mt-0.5"><?= e($incident['status'] ?: '—') ?></dd></div>
                <div><dt class="text-xs text-gray-500">Clasificación</dt><dd class="mt-0.5"><?= e($incident['classification'] ?: '—') ?></dd></div>
                <div><dt class="text-xs text-gray-500">Determinación</dt><dd class="mt-0.5"><?= e($incident['determination'] ?: '—') ?></dd></div>
                <div><dt class="text-xs text-gray-500">Asignado a</dt><dd class="mt-0.5"><?= e($incident['assigned_to'] ?: '—') ?></dd></div>
            </dl>
            <?php if (!empty($tags) && is_array($tags)): ?>
                <div class="mt-4 flex flex-wrap gap-1.5">
                    <?php foreach ($tags as $t): ?><span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300"><?= e(is_array($t) ? json_encode($t) : (string)$t) ?></span><?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
            <h3 class="text-sm font-semibold mb-4">Alertas (<?= count($alerts) ?>)</h3>
            <?php if (empty($alerts)): ?>
                <p class="text-sm text-gray-500">Sin alertas asociadas.</p>
            <?php else: ?>
                <div class="space-y-4">
                    <?php foreach ($alerts as $al): ?>
                        <?php $mitre = $mitreOf($al['mitre_techniques']); $raw = safe_json_decode((string)$al['raw_data'], []); $ev = is_array($raw) ? ($raw['evidence'] ?? []) : []; ?>
                        <div class="border border-gray-100 dark:border-gray-700 rounded-lg p-3">
                            <div class="flex items-start justify-between gap-3">
                                <p class="text-sm font-medium"><?= e($al['title']) ?></p>
                                <span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 <?= strtolower((string)$al['severity']) === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300' ?>"><?= e($al['severity'] ?: '—') ?></span>
                            </div>
                            <p class="text-xs text-gray-400 mt-1">
                                <?php if (!empty($al['threat_display_name'])): ?>Amenaza: <span class="text-gray-600 dark:text-gray-300"><?= e($al['threat_display_name']) ?></span><?php endif; ?>
                                <?php if (!empty($al['category'])): ?> · Cat: <?= e($al['category']) ?><?php endif; ?>
                                <?php if (!empty($al['service_source'])): ?> · Servicio: <?= e($al['service_source']) ?><?php endif; ?>
                                <?php if (!empty($al['detection_source'])): ?> · Detección: <?= e($al['detection_source']) ?><?php endif; ?>
                            </p>
                            <p class="text-xs text-gray-400 mt-0.5">
                                <?php if (!empty($al['first_activity'])): ?>Primera: <?= e($al['first_activity']) ?> ·<?php endif; ?>
                                <?php if (!empty($al['last_activity'])): ?> Última: <?= e($al['last_activity']) ?><?php endif; ?>
                            </p>
                            <?php if (!empty($mitre)): ?>
                                <div class="mt-2 flex flex-wrap gap-1.5">
                                    <?php foreach ($mitre as $m): ?><span class="inline-flex px-1.5 py-0.5 text-[10px] font-mono rounded bg-brand-50 dark:bg-brand-950 text-brand-600 dark:text-brand-300"><?= e($m) ?></span><?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                            <?php if (!empty($ev) && is_array($ev)): ?>
                                <details class="mt-2">
                                    <summary class="text-xs text-gray-500 cursor-pointer select-none">Evidencia (<?= count($ev) ?>)</summary>
                                    <ul class="mt-1 text-xs text-gray-500 space-y-0.5">
                                        <?php foreach ($ev as $e): ?>
                                            <?php $lab = is_array($e) ? $evLabel($e) : ''; ?>
                                            <li>· <?= e($lab !== '' ? $lab : (is_array($e) ? json_encode($e) : (string)$e)) ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </details>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <?php if (!empty($raItems) || !empty($incident['recommended_actions'])): ?>
            <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
                <h3 class="text-sm font-semibold mb-3">Acciones recomendadas</h3>
                <?php if (is_array($raItems)): ?>
                    <ul class="list-disc list-inside text-sm space-y-1">
                        <?php foreach ($raItems as $ra): ?><li><?= e(is_array($ra) ? json_encode($ra) : (string)$ra) ?></li><?php endforeach; ?>
                    </ul>
                <?php else: ?>
                    <p class="text-sm whitespace-pre-wrap"><?= e((string)$incident['recommended_actions']) ?></p>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <!-- Columna derecha: análisis IA (manual) -->
    <div class="lg:col-span-1">
        <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
            <h3 class="text-sm font-semibold mb-3">Análisis con IA</h3>
            <?php if (empty($profiles)): ?>
                <p class="text-xs text-gray-400">No hay perfiles de IA configurados. Añádelos en <a href="<?= base_url('admin/apis') ?>" class="text-brand-500 hover:underline">Admin → APIs</a>.</p>
            <?php else: ?>
                <label class="block text-xs text-gray-500 mb-1">IA</label>
                <select id="ia-profile" class="w-full px-2 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    <?php foreach ($profiles as $p): ?>
                        <option value="<?= (int)$p['id'] ?>" <?= (int)($defaultProfileId ?? 0) === (int)$p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?><?= !empty($p['model']) ? ' · ' . e($p['model']) : '' ?></option>
                    <?php endforeach; ?>
                </select>
                <button type="button" onclick="analyzeIncidentAI()" id="btn-analyze-inc" class="w-full mt-3 px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Analizar con IA</button>
                <p class="text-xs text-gray-400 mt-2">Manual: el análisis se genera solo al pulsar el botón. Los datos del incidente se envían al proveedor de IA.</p>
                <div id="inc-ai-result" class="hidden md-body mt-4 border-t border-gray-100 dark:border-gray-700 pt-4"></div>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
function getIncAiProfile() { var s = document.getElementById('ia-profile'); return s ? parseInt(s.value, 10) : 0; }

function analyzeIncidentAI() {
    var btn = document.getElementById('btn-analyze-inc');
    var box = document.getElementById('inc-ai-result');
    if (!box) return;
    btn.disabled = true;
    var prev = btn.innerHTML;
    btn.innerHTML = 'Analizando…';
    box.classList.remove('hidden');
    box.innerHTML = '<div class="spinner mx-auto"></div>';

    api('POST', '<?= base_url('modules/llm/analyze-incident') ?>/<?= (int)$incident['id'] ?>', { profile_id: getIncAiProfile() })
        .then(function (res) {
            if (res.success) {
                box.innerHTML = res.content_html || (res.content ? '<pre class="whitespace-pre-wrap text-sm">' + esc(res.content) + '</pre>' : '');
            } else {
                box.innerHTML = '<p class="text-sm text-red-500">' + esc(res.error || 'Error') + '</p>';
                toast('Error: ' + (res.error || ''), 'error');
            }
        })
        .catch(function () { box.innerHTML = '<p class="text-sm text-red-500">Error de conexión</p>'; })
        .finally(function () { btn.disabled = false; btn.innerHTML = prev; });
}

function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }
</script>
