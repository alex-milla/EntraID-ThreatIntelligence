<?php
/**
 * Vista de alta/edición — Seguimiento TI TF.
 *
 * @var Module_TiTracker $module
 * @var array $search
 * @var array $filters
 * @var array $catalogs
 * @var array $formats
 * @var array $tlpLevels
 * @var array|null $notice
 */

$base = base_url('modules/ti_tracker');
$isEdit = (int)($search['id'] ?? 0) > 0;
$formatsSaved = (array)($search['formats'] ?? []);
?>

<?php if (!empty($notice) && is_array($notice)): ?>
    <div class="alert alert-<?= e((string)($notice['type'] ?? 'info')) ?>" role="status">
        <?= e((string)($notice['text'] ?? '')) ?>
    </div>
<?php endif; ?>

<div class="page-header">
    <h1><?= $isEdit ? 'Editar búsqueda' : 'Nueva búsqueda' ?></h1>
    <p class="subtitle">
        Define los filtros de IOCs y los formatos de exportación. La ejecución
        corre contra la base local de ThreatFox, que se refresca a diario.
    </p>
    <span class="spacer"></span>
    <a class="btn-flat btn" href="<?= e($base) ?>">
        <?= icon('arrow_back', 18) ?> Volver
    </a>
</div>

<form method="POST" action="<?= e($base . '/save') ?>" class="card">
    <?= Csrf::field() ?>
    <input type="hidden" name="id" value="<?= (int)($search['id'] ?? 0) ?>">

    <div class="grid grid-cols-1 md:grid-cols-2 gap-x-4">
        <div class="input-field md:col-span-2">
            <label for="tt-name">Nombre de la búsqueda</label>
            <input type="text" id="tt-name" name="name" maxlength="120" required
                   value="<?= e((string)($search['name'] ?? '')) ?>"
                   placeholder="Ej: Cobalt Strike en dominios, últimas 2 semanas">
        </div>

        <div class="input-field md:col-span-2">
            <label for="tt-notes">Notas (opcional)</label>
            <input type="text" id="tt-notes" name="notes" maxlength="500"
                   value="<?= e((string)($search['notes'] ?? '')) ?>"
                   placeholder="Para qué sirve, quién la revisa, qué hacer con las novedades…">
        </div>
    </div>

    <h2 class="text-base font-semibold mt-2 mb-1">Filtros de IOCs</h2>

    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-x-4">
        <div class="input-field">
            <label for="tt-source">Fuente</label>
            <select id="tt-source" name="source">
                <option value="db" <?= $filters['source'] === 'db' ? 'selected' : '' ?>>Base local</option>
                <option value="api" <?= $filters['source'] === 'api' ? 'selected' : '' ?>>API en vivo</option>
            </select>
            <span class="helper-text">La base local se refresca con el cron diario de ThreatFox.</span>
        </div>

        <div class="input-field">
            <label for="tt-mode">Modo de búsqueda</label>
            <select id="tt-mode" name="mode">
                <?php foreach (ThreatfoxQuery::MODES as $modeKey => $modeLabel): ?>
                    <option value="<?= e($modeKey) ?>" <?= $filters['mode'] === $modeKey ? 'selected' : '' ?>>
                        <?= e($modeLabel) ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <span class="helper-text">Automático detecta el tipo del indicador por su forma.</span>
        </div>

        <div class="input-field xl:col-span-2">
            <label for="tt-term">Término de búsqueda</label>
            <input type="search" id="tt-term" name="search_term" maxlength="300"
                   value="<?= e((string)$filters['term']) ?>"
                   placeholder="dominio, url, ip:puerto, hash, familia o tag">
            <span class="helper-text">Varios términos separados por comas se combinan con AND.</span>
        </div>

        <div class="input-field">
            <label for="tt-days">Ventana de días</label>
            <input type="number" id="tt-days" name="days" min="0" max="<?= (int)TI_TRACKER_DAYS_DB_MAX ?>" step="1"
                   value="<?= (int)$filters['days'] ?>">
            <span class="helper-text">
                0 = sin ventana (solo modo Recientes la aplica). Base local hasta
                <?= (int)TI_TRACKER_DAYS_DB_MAX ?> días; API máximo <?= (int)THREATFOX_DAYS_MAX ?>.
            </span>
        </div>

        <div class="input-field">
            <label for="tt-limit">Límite en la API</label>
            <input type="number" id="tt-limit" name="limit" min="1" max="1000" step="1"
                   value="<?= (int)$filters['limit'] ?>">
            <span class="helper-text">Solo se usa con la fuente API en vivo.</span>
        </div>

        <div class="input-field">
            <label for="tt-malware">Familia de malware</label>
            <input type="text" id="tt-malware" name="f_malware" maxlength="120"
                   value="<?= e((string)$filters['malware']) ?>" placeholder="ej. win.cobalt_strike">
        </div>

        <div class="input-field">
            <label for="tt-ioc-type">Tipo de IOC</label>
            <select id="tt-ioc-type" name="f_ioc_type">
                <option value="">Todos</option>
                <?php foreach ($catalogs['ioc_type'] as $type): ?>
                    <option value="<?= e((string)$type) ?>" <?= $filters['ioc_type'] === (string)$type ? 'selected' : '' ?>>
                        <?= e((string)$type) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="input-field">
            <label for="tt-threat">Tipo de amenaza</label>
            <select id="tt-threat" name="f_threat">
                <option value="">Todos</option>
                <?php foreach ($catalogs['threat_type'] as $type): ?>
                    <option value="<?= e((string)$type) ?>" <?= $filters['threat_type'] === (string)$type ? 'selected' : '' ?>>
                        <?= e((string)$type) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="input-field">
            <label for="tt-tag">Tag</label>
            <input type="text" id="tt-tag" name="f_tag" maxlength="80"
                   value="<?= e((string)$filters['tag']) ?>" placeholder="ej. Magecart">
        </div>

        <div class="input-field">
            <label for="tt-conf">Confianza mínima</label>
            <input type="number" id="tt-conf" name="f_conf" min="0" max="100" step="1"
                   value="<?= (int)$filters['conf'] ?>">
        </div>

        <div class="input-field">
            <label>Opciones</label>
            <label class="check-inline" for="tt-exact">
                <input type="checkbox" id="tt-exact" name="exact" value="1" <?= !empty($filters['exact']) ? 'checked' : '' ?>>
                <span class="text-sm">Coincidencia exacta (solo API)</span>
            </label>
            <label class="check-inline mt-2" for="tt-ref">
                <input type="checkbox" id="tt-ref" name="f_ref" value="1" <?= !empty($filters['ref_only']) ? 'checked' : '' ?>>
                <span class="text-sm">Solo IOCs con referencia</span>
            </label>
        </div>
    </div>

    <h2 class="text-base font-semibold mt-4 mb-1">Exportación</h2>

    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-x-4">
        <div class="input-field xl:col-span-2">
            <label>Formatos disponibles</label>
            <div class="flex flex-wrap items-center gap-4 pt-2">
                <?php foreach ($formats as $formatKey => $formatLabel): ?>
                    <label class="check-inline" for="tt-format-<?= e($formatKey) ?>">
                        <input type="checkbox" id="tt-format-<?= e($formatKey) ?>"
                               name="formats[]" value="<?= e($formatKey) ?>"
                               <?= in_array($formatKey, $formatsSaved, true) ? 'checked' : '' ?>>
                        <span class="text-sm"><?= e($formatLabel) ?></span>
                    </label>
                <?php endforeach; ?>
            </div>
            <span class="helper-text">Cada formato genera un botón de descarga en el panel.</span>
        </div>

        <div class="input-field">
            <label for="tt-tlp">Nivel TLP</label>
            <select id="tt-tlp" name="tlp">
                <?php foreach ($tlpLevels as $level => $meta): ?>
                    <option value="<?= e($level) ?>" <?= ((string)$search['tlp'] === $level) ? 'selected' : '' ?>>
                        <?= e((string)$meta['label']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <span class="helper-text">Se aplica al bundle STIX y al evento MISP.</span>
        </div>

        <div class="input-field">
            <label for="tt-valid-days">Validez (días)</label>
            <input type="number" id="tt-valid-days" name="valid_days" min="1" max="3650" step="1"
                   value="<?= (int)($search['valid_days'] ?? 365) ?>">
            <span class="helper-text">Calcula <code>valid_until</code> en STIX.</span>
        </div>

        <div class="input-field">
            <label for="tt-source-name">Nombre de la fuente</label>
            <input type="text" id="tt-source-name" name="source_name" maxlength="80"
                   value="<?= e((string)($search['source_name'] ?? 'abuse.ch ThreatFox')) ?>">
        </div>

        <div class="input-field">
            <label for="tt-threat-actor">Actor de amenaza (opcional)</label>
            <input type="text" id="tt-threat-actor" name="threat_actor" maxlength="120"
                   value="<?= e((string)($search['threat_actor'] ?? '')) ?>" placeholder="Ej: APT28">
        </div>

        <div class="input-field xl:col-span-2">
            <label for="tt-extra-tags">Etiquetas extra (opcional)</label>
            <input type="text" id="tt-extra-tags" name="extra_tags" maxlength="200"
                   value="<?= e((string)($search['extra_tags'] ?? '')) ?>" placeholder="ransomware, c2">
            <span class="helper-text">Separadas por coma; se suman a los tags propios de cada IOC.</span>
        </div>
    </div>

    <div class="flex flex-wrap items-center gap-3 mt-2">
        <button type="submit" class="btn">
            <?= icon('save', 18) ?> Guardar búsqueda
        </button>
        <a class="btn-outline btn" href="<?= e($base) ?>">Cancelar</a>
    </div>
</form>
