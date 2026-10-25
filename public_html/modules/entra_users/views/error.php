<?php
/**
 * Vista: error genérica del módulo Usuarios Entra ID.
 */
?>
<div class="bg-danger-bg border border-danger-border rounded-xl p-6 text-center">
    <p class="text-sm text-danger"><?= e($message ?? 'Ha ocurrido un error') ?></p>
    <a href="<?= base_url('modules/entra_users') ?>" class="inline-block mt-3 text-sm text-brand-500 hover:underline">Volver</a>
</div>
