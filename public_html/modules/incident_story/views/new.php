<?php
/**
 * Vista de ingesta — Incidentes Story.
 *
 * @var Module_IncidentStory $module
 * @var array $formats
 * @var array|null $notice
 * @var string $oldText
 * @var string $oldClientDomains
 */

$base = base_url('modules/incident_story');
$inputClass = 'w-full px-3 py-2 rounded-lg border border-line-strong bg-input text-ink text-sm focus:ring-2 focus:ring-brand-500 outline-none';
?>

<?php if (!empty($notice) && is_array($notice)): ?>
    <div class="alert alert-<?= e((string)($notice['type'] ?? 'info')) ?>" role="status">
        <?= e((string)($notice['text'] ?? '')) ?>
    </div>
<?php endif; ?>

<div class="page-header">
    <h1>Nuevo caso · Incidentes Story</h1>
    <p class="subtitle">
        Dos formas de ingesta: pega la historia copiada del portal o sube el JSON del story
        (portal, export de Graph o Advanced Hunting). Ambas convergen en el mismo modelo y se
        pseudonimizan antes del triaje.
    </p>
    <span class="spacer"></span>
    <a class="btn btn-outline" href="<?= e($base) ?>">← Volver</a>
</div>

<div class="alert alert-info" role="status">
    <strong>Privacidad:</strong> usuarios, equipos, dominios internos e IPs privadas se sustituyen
    por pseudónimos correlacionados antes de enviar nada a la IA. Los hashes de fichero y las IPs
    públicas se conservan porque son necesarios para el análisis y la reputación.
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
    <!-- Texto pegado -->
    <form method="POST" action="<?= e($base . '/ingest') ?>" class="card p-5 space-y-4">
        <?= Csrf::field() ?>
        <input type="hidden" name="mode" value="text">
        <div>
            <h2 class="text-base font-semibold">Pegar la historia</h2>
            <p class="text-xs text-ink-muted mt-1">
                En Defender XDR, abre la incidencia → historia/timeline → «Copiar historia».
                Pega aquí el texto completo, con sus bloques de fecha y hora.
            </p>
        </div>
        <div>
            <label for="story-text" class="block text-xs font-medium text-ink-muted mb-1">
                Story de Defender
            </label>
            <textarea id="story-text" name="story_text" rows="16" class="<?= e($inputClass) ?> font-mono text-xs"
                      placeholder="10/30/2026 8:10:38 AM&#10; [41544] powershell.exe -NoProfile ...&#10;Command line ..."
                      spellcheck="false"><?= e($oldText) ?></textarea>
        </div>
        <div>
            <label for="client-domains-text" class="block text-xs font-medium text-ink-muted mb-1">
                Dominios internos del cliente (opcional)
            </label>
            <input id="client-domains-text" type="text" name="client_domains"
                   value="<?= e($oldClientDomains) ?>" class="<?= e($inputClass) ?>"
                   placeholder="diba.es, corporativo.local">
            <p class="mt-1 text-[11px] text-ink-soft">
                Separados por comas. Refuerzan la pseudonimización de dominios internos detectados
                de forma heurística.
            </p>
        </div>
        <button type="submit" class="btn">
            <?= icon('travel_explore', 18) ?> Analizar texto
        </button>
    </form>

    <!-- Fichero JSON -->
    <form method="POST" action="<?= e($base . '/ingest') ?>" enctype="multipart/form-data" class="card p-5 space-y-4">
        <?= Csrf::field() ?>
        <input type="hidden" name="mode" value="file">
        <div>
            <h2 class="text-base font-semibold">Subir JSON</h2>
            <p class="text-xs text-ink-muted mt-1">
                Se detecta automáticamente el sabor del JSON. Máximo 5 MB. También se admite un
                <code>.txt</code> con la historia copiada.
            </p>
        </div>
        <div>
            <label for="story-file" class="block text-xs font-medium text-ink-muted mb-1">
                Fichero de evidencia
            </label>
            <input id="story-file" type="file" name="story_file" accept=".json,.jsonc,.txt,.log,application/json,text/plain" required
                   class="block w-full text-sm text-ink file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-brand-500 file:text-white file:text-xs file:font-semibold hover:file:bg-brand-600 border border-line-strong rounded-lg bg-input">
        </div>
        <div>
            <label for="client-domains-file" class="block text-xs font-medium text-ink-muted mb-1">
                Dominios internos del cliente (opcional)
            </label>
            <input id="client-domains-file" type="text" name="client_domains"
                   value="<?= e($oldClientDomains) ?>" class="<?= e($inputClass) ?>"
                   placeholder="diba.es, corporativo.local">
        </div>
        <button type="submit" class="btn">
            <?= icon('cloud_upload', 18) ?> Analizar fichero
        </button>
    </form>
</div>

<div class="card mt-6 p-5">
    <h2 class="text-base font-semibold mb-3">Formatos admitidos</h2>
    <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
        <?php foreach ($formats as $key => $label): ?>
            <div>
                <dt class="font-medium"><?= e($label) ?></dt>
                <dd class="text-xs text-ink-muted mt-0.5">
                    <?php if ($key === 'texto_pegado'): ?>
                        Story copiado del portal: bloques de fecha, procesos, command lines, usuarios y scripts.
                    <?php elseif ($key === 'story_json_portal'): ?>
                        JSON interno <code>story/timeline</code> capturado en la pestaña Network del navegador.
                    <?php elseif ($key === 'graph_export'): ?>
                        Incidencia de Microsoft Graph con <code>alerts</code> y sus <code>evidence</code>.
                    <?php else: ?>
                        Resultado de KQL sobre <code>DeviceProcessEvents</code> (columnas de proceso y padre).
                    <?php endif; ?>
                </dd>
            </div>
        <?php endforeach; ?>
    </dl>
    <p class="mt-4 text-[11px] text-ink-soft">
        El endpoint <code>story</code> del portal no está documentado por Microsoft y puede cambiar
        sin aviso. El parser es defensivo: conserva los bloques no reconocidos y el triaje sigue
        funcionando con el texto pegado o el export oficial de Graph.
    </p>
</div>
