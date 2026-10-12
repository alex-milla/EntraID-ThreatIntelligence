<?php
/**
 * Vista: Error genérica de módulo.
 */
?>
<div class="bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 rounded-xl p-6 text-center">
    <p class="text-sm text-red-600 dark:text-red-300"><?= e($message ?? 'Ha ocurrido un error') ?></p>
    <a href="<?= base_url('modules/reports') ?>" class="inline-block mt-3 text-sm text-brand-500 hover:underline">Volver a reportes</a>
</div>
