<?php
/**
 * Panel de exportación (STIX 2.1 y MISP) de IOCs ThreatFox.
 *
 * Replica el paso 4 del extractor de referencia: labels encima del control
 * (.input-field + .helper-text, §6.7), leyenda TLP con los tokens semánticos,
 * acciones primaria/secundaria y vuelta a la consulta.
 *
 * @var Module_Threatfox $module
 * @var array $filters
 * @var array $config
 * @var int|null $selection
 * @var array $types
 * @var array $tlpLevels
 */

$base = base_url('modules/threatfox');

$backQuery = [
    'source'      => $filters['source'],
    'mode'        => $filters['mode'],
    'search_term' => $filters['term'],
    'days'        => $filters['days'],
    'exact'       => $filters['exact'] ? 1 : 0,
    'limit'       => $filters['limit'],
    'f_malware'   => $filters['malware'],
    'f_ioc_type'  => $filters['ioc_type'],
    'f_threat'    => $filters['threat_type'],
    'f_tag'       => $filters['tag'],
    'f_conf'      => $filters['conf'],
    'f_ref'       => $filters['ref_only'] ? 1 : 0,
];
foreach ($backQuery as $key => $value) {
    if ($value === '' || $value === null || $value === 0) {
        unset($backQuery[$key]);
    }
}
$backUrl = $base . ($backQuery ? '?' . http_build_query($backQuery) : '');
$fmt = static fn(int|float $n): string => number_format((float)$n, 0, ',', '.');
?>

<div class="page-header">
    <h1>Exportar IOCs</h1>
    <p class="subtitle">
        Se exporta el conjunto que cumple los filtros de la consulta.
        <?php if ($selection !== null): ?>
            <strong><?= $fmt($selection) ?></strong> IOCs seleccionados.
        <?php else: ?>
            El conjunto se resolverá contra la API en vivo al generar el fichero.
        <?php endif; ?>
    </p>
    <span class="spacer"></span>
    <a class="btn-flat btn" href="<?= e($backUrl) ?>">
        <?= icon('arrow_back', 18) ?> Volver a la consulta
    </a>
</div>

<form id="tf-export-form" class="card" data-export-url="<?= e($base . '/export') ?>">
    <div class="card-head">
        <h2>Exportación a STIX 2.1</h2>
        <?php if ($selection !== null): ?>
            <span class="count-chip"><?= $fmt($selection) ?> IOCs</span>
        <?php endif; ?>
    </div>
    <p class="card-sub mb-4">Configura los metadatos para la exportación STIX 2.1.</p>

    <!-- Filtros activos: viajan ocultos para reejecutar la misma selección -->
    <input type="hidden" name="source" value="<?= e($filters['source']) ?>">
    <input type="hidden" name="mode" value="<?= e($filters['mode']) ?>">
    <input type="hidden" name="search_term" value="<?= e($filters['term']) ?>">
    <input type="hidden" name="days" value="<?= (int)$filters['days'] ?>">
    <input type="hidden" name="exact" value="<?= $filters['exact'] ? 1 : 0 ?>">
    <input type="hidden" name="limit" value="<?= (int)$filters['limit'] ?>">
    <input type="hidden" name="f_malware" value="<?= e($filters['malware']) ?>">
    <input type="hidden" name="f_ioc_type" value="<?= e($filters['ioc_type']) ?>">
    <input type="hidden" name="f_threat" value="<?= e($filters['threat_type']) ?>">
    <input type="hidden" name="f_tag" value="<?= e($filters['tag']) ?>">
    <input type="hidden" name="f_conf" value="<?= (int)$filters['conf'] ?>">
    <input type="hidden" name="f_ref" value="<?= $filters['ref_only'] ? 1 : 0 ?>">

    <div class="input-field">
        <label for="tf-output-format">Formato de Salida</label>
        <select id="tf-output-format" name="split">
            <option value="1" selected>Separado por tipo (recomendado)</option>
            <option value="0">Archivo único combinado</option>
        </select>
        <span class="helper-text">Separado por tipo crea un archivo JSON por cada categoría de IOC.</span>
    </div>

    <div class="input-field">
        <label for="tf-source-name">Nombre de la Fuente</label>
        <input type="text" id="tf-source-name" name="source_name" maxlength="80"
               value="<?= e((string)$config['sourceName']) ?>" placeholder="abuse.ch ThreatFox">
        <span class="helper-text">Ej: abuse.ch ThreatFox, Cobalt Strike. Se recuerda la última fuente usada.</span>
    </div>

    <div class="input-field">
        <label for="tf-threat-actor">Actor de Amenaza (opcional)</label>
        <input type="text" id="tf-threat-actor" name="threat_actor" maxlength="120"
               value="<?= e((string)$config['threatActor']) ?>" placeholder="Ej: APT28, Lazarus Group">
        <span class="helper-text">
            Se añade como <code>threat_actor_names</code>; la familia de cada IOC no se modifica.
        </span>
    </div>

    <div class="input-field">
        <label for="tf-tags">Etiquetas (opcional)</label>
        <input type="text" id="tf-tags" name="tags" maxlength="200"
               value="<?= e((string)$config['tags']) ?>" placeholder="ransomware, c2, banking">
        <span class="helper-text">Separadas por coma. Se suman a los tags propios de cada IOC.</span>
    </div>

    <div class="input-field">
        <label for="tf-indicator-type">Tipo de Indicador</label>
        <select id="tf-indicator-type" name="indicator_type">
            <?php foreach ($types as $value => $label): ?>
                <option value="<?= e($value) ?>" <?= $config['indicatorType'] === $value ? 'selected' : '' ?>>
                    <?= e($label) ?>
                </option>
            <?php endforeach; ?>
        </select>
        <span class="helper-text">Vocabulario estándar de STIX 2.1 (<code>indicator_types</code>).</span>
    </div>

    <div class="input-field">
        <label for="tf-confidence">Confianza (1-100)</label>
        <input type="number" id="tf-confidence" name="confidence" min="0" max="100" step="1"
               value="<?= (int)$config['confidence'] ?>">
        <label class="check-inline mt-2" for="tf-use-ioc-confidence">
            <input type="checkbox" id="tf-use-ioc-confidence" name="use_ioc_confidence" value="1" checked>
            <span class="text-sm">Usar la confianza de cada IOC (ThreatFox la publica siempre)</span>
        </label>
        <span class="helper-text">
            Si marcas la casilla se respeta <code>confidence_level</code>; si no, se aplica este valor.
        </span>
    </div>

    <div class="input-field">
        <label for="tf-tlp">Nivel TLP</label>
        <select id="tf-tlp" name="tlp">
            <?php foreach ($tlpLevels as $level => $meta): ?>
                <option value="<?= e($level) ?>" <?= $config['tlp'] === $level ? 'selected' : '' ?>>
                    <?= e($meta['label']) ?>
                </option>
            <?php endforeach; ?>
        </select>
        <span class="helper-text">
            TLP (Traffic Light Protocol): indica el grado de difusión permitido de la información.
        </span>
        <ul class="list-none m-0 mt-1 p-0 space-y-1">
            <?php foreach ($tlpLevels as $level => $meta): ?>
                <li class="flex items-center gap-2 text-sm text-ink-muted">
                    <span class="inline-block w-2.5 h-2.5 rounded-full <?= e($meta['dot']) ?>"></span>
                    <span><strong class="text-ink"><?= e($meta['label']) ?></strong> — <?= e($meta['help']) ?></span>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>

    <div class="input-field">
        <label for="tf-valid-days">Validez (días)</label>
        <input type="number" id="tf-valid-days" name="valid_days" min="1" max="3650" step="1"
               value="<?= (int)$config['valid_days'] ?>">
        <span class="helper-text">Se usa para calcular <code>valid_until</code> a partir de la fecha del IOC.</span>
    </div>

    <div class="input-field">
        <label for="tf-ip-direction">Dirección de IP (MISP)</label>
        <select id="tf-ip-direction" name="ip_direction">
            <option value="ip-dst" <?= $config['ip_direction'] === 'ip-dst' ? 'selected' : '' ?>>Destino (ip-dst)</option>
            <option value="ip-src" <?= $config['ip_direction'] === 'ip-src' ? 'selected' : '' ?>>Origen (ip-src)</option>
            <option value="both" <?= $config['ip_direction'] === 'both' ? 'selected' : '' ?>>Ambas</option>
        </select>
        <span class="helper-text">Atributo MISP que se usa para las direcciones IP (no afecta a STIX).</span>
    </div>

    <div class="flex flex-wrap items-center gap-3 mt-2">
        <button type="button" class="btn" data-tf-export="stix">
            <?= icon('inventory_2', 18) ?> Generar STIX 2.1
        </button>
        <button type="button" class="btn-outline btn" data-tf-export="misp">
            <?= icon('terminal', 18) ?> Exportar MISP
        </button>
        <a class="btn-outline btn" href="<?= e($backUrl) ?>">
            <?= icon('arrow_back', 18) ?> Volver
        </a>
    </div>

    <div class="hint-bar mt-4">
        <span class="hint"><?= icon('description', 16) ?> Otros formatos:</span>
        <button type="button" class="btn-tiny btn-outline btn" data-tf-export="csv">CSV</button>
        <button type="button" class="btn-tiny btn-outline btn" data-tf-export="json">JSON</button>
        <button type="button" class="btn-tiny btn-outline btn" data-tf-export="txt">TXT</button>
    </div>
</form>

<script>
(function () {
    'use strict';

    var form = document.getElementById('tf-export-form');
    if (!form) { return; }

    var exportUrl = form.getAttribute('data-export-url');
    var confidenceInput = document.getElementById('tf-confidence');
    var useIocConfidence = document.getElementById('tf-use-ioc-confidence');

    function syncConfidence() {
        if (!confidenceInput || !useIocConfidence) { return; }
        confidenceInput.disabled = useIocConfidence.checked;
    }
    if (useIocConfidence) {
        useIocConfidence.addEventListener('change', syncConfidence);
        syncConfidence();
    }

    form.addEventListener('click', function (event) {
        var button = event.target.closest('[data-tf-export]');
        if (!button) { return; }

        var format = button.getAttribute('data-tf-export');
        var payload = {};
        new FormData(form).forEach(function (value, key) {
            payload[key] = value;
        });
        payload.format = format;
        payload.split = payload.split === '1';
        payload.use_ioc_confidence = !!useIocConfidence && useIocConfidence.checked;

        button.disabled = true;
        toast('Generando exportación ' + format.toUpperCase() + '…', 'info');

        api('POST', exportUrl, payload)
            .then(function (res) {
                if (!res.success) {
                    toast('Error: ' + (res.error || 'no se pudo generar la exportación'), 'error');
                    return;
                }
                (res.files || []).forEach(function (file) {
                    downloadFile(file.content, file.filename, file.mime);
                });
                var extra = res.skipped > 0 ? ' (' + res.skipped + ' sin mapear)' : '';
                toast('Descargados ' + (res.count || 0) + ' IOCs' + extra, 'success');
            })
            .catch(function (err) {
                toast('Error al exportar: ' + (err && err.message ? err.message : 'conexión'), 'error');
            })
            .then(function () {
                button.disabled = false;
            });
    });
})();
</script>
