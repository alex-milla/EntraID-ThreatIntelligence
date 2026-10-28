<?php
/**
 * Ajustes del módulo IOCs ThreatFox (solo administradores).
 *
 * @var Module_Threatfox $module
 * @var bool $hasKey
 * @var bool $keyEnv
 * @var string $keyMasked
 * @var string $dbPath
 * @var bool $dbExists
 * @var array|null $notice
 * @var string $cronCmd
 */

$base = base_url('modules/threatfox');
?>

<?php if (!empty($notice) && is_array($notice)): ?>
    <div class="alert alert-<?= e((string)($notice['type'] ?? 'info')) ?>" role="status">
        <?= e((string)($notice['text'] ?? '')) ?>
    </div>
<?php endif; ?>

<div class="page-header">
    <h1>Ajustes · IOCs ThreatFox</h1>
    <p class="subtitle">Auth-Key de abuse.ch, base local y automatización de la ingesta.</p>
    <span class="spacer"></span>
    <a class="btn-outline btn" href="<?= e($base) ?>">
        <?= icon('arrow_back', 18) ?> Volver
    </a>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Auth-Key -->
    <div class="card">
        <div class="card-head">
            <h2>Auth-Key de abuse.ch</h2>
        </div>

        <?php if ($keyEnv): ?>
            <div class="alert alert-info">
                La clave está definida en la variable de entorno <code>THREATFOX_AUTH_KEY</code> (.env),
                que tiene prioridad sobre este formulario.
            </div>
            <div class="input-field">
                <label>Clave en uso</label>
                <input type="text" value="<?= e($keyMasked) ?>" readonly>
                <span class="helper-text">Para cambiarla, edita el .env del servidor.</span>
            </div>
        <?php else: ?>
            <p class="text-sm text-ink-muted mt-0 mb-3">
                Se guarda cifrada (AES-256) en la tabla de ajustes y solo se usa en las llamadas
                salientes: nunca se envía al navegador.
            </p>

            <?php if ($hasKey): ?>
                <div class="alert alert-success">
                    Hay una Auth-Key configurada: <code><?= e($keyMasked) ?></code>
                </div>
            <?php else: ?>
                <div class="alert alert-warning">
                    Sin Auth-Key solo funciona la consulta a la base local.
                    Consigue una gratuita en
                    <a href="https://auth.abuse.ch/" target="_blank" rel="noopener noreferrer">auth.abuse.ch</a>.
                </div>
            <?php endif; ?>

            <form method="POST" action="<?= e($base) ?>/settings">
                <?= Csrf::field() ?>
                <div class="input-field">
                    <label for="tf-auth-key">Auth-Key</label>
                    <input type="password" id="tf-auth-key" name="auth_key" autocomplete="new-password"
                           placeholder="Pega aquí la Auth-Key de abuse.ch">
                    <span class="helper-text">Se muestra enmascarada una vez guardada.</span>
                </div>
                <button type="submit" class="btn"><?= icon('save', 18) ?> Guardar clave</button>
            </form>

            <?php if ($hasKey): ?>
                <form method="POST" action="<?= e($base) ?>/settings" class="mt-3"
                      data-confirm="Se eliminará la Auth-Key guardada. ¿Continuar?"
                      data-confirm-danger>
                    <?= Csrf::field() ?>
                    <input type="hidden" name="clear_key" value="1">
                    <button type="submit" class="btn-tiny btn-outline btn text-danger">
                        <?= icon('delete', 16) ?> Eliminar clave guardada
                    </button>
                </form>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Base de datos -->
    <div class="card">
        <div class="card-head">
            <h2>Base de datos local</h2>
        </div>
        <div class="input-field">
            <label>Fichero SQLite</label>
            <input type="text" value="<?= e($dbPath) ?>" readonly>
            <span class="helper-text">
                <?= $dbExists
                    ? 'La base existe y está fuera del alcance web (storage/ está denegado).'
                    : 'Todavía no existe: se creará con la primera ingesta.' ?>
            </span>
        </div>
        <p class="text-sm text-ink-muted mt-0">
            La base es independiente de la principal de la aplicación, así que ingerir
            IOCs no afecta al resto de módulos.
        </p>
    </div>
</div>

<!-- Automatización -->
<div class="card mt-6">
    <div class="card-head">
        <h2>Automatización de la ingesta</h2>
    </div>
    <p class="text-sm text-ink-muted mt-0 mb-3">
        La ingesta diaria es idempotente y apta para cron. Solo hace una llamada a la API
        por ejecución.
    </p>

    <div class="input-field">
        <label>Por CLI (recomendado)</label>
        <input type="text" value="<?= e($cronCmd) ?>" readonly class="font-mono">
        <span class="helper-text">Ejemplo de cron: <code>0 6 * * * <?= e($cronCmd) ?></code></span>
    </div>

    <div class="input-field">
        <label>Por URL (token de CRON_TOKEN)</label>
        <input type="text" value="<?= e(rtrim(APP_URL, '/') . '/cron/threatfox-ingest.php?token=TU_CRON_TOKEN') ?>" readonly>
        <span class="helper-text">Sustituye TU_CRON_TOKEN por el valor de CRON_TOKEN de tu .env.</span>
    </div>

    <p class="text-sm text-ink-muted m-0">
        El histórico completo (~6 meses) no se descarga por cron: se lanza desde la vista
        principal con «Descargar histórico completo».
    </p>
</div>
