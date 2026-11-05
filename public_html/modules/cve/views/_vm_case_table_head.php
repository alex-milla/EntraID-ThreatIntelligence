<?php
/**
 * Parcial: cabecera de la cola de seguimiento (v0.3.23).
 * Variable: $isAdmin (checkbox de selección múltiple).
 */
$isAdmin = !empty($isAdmin);
?>
<thead class="bg-muted text-ink-muted">
    <tr>
        <th class="px-3 py-2 text-left w-8">
            <?php if ($isAdmin): ?>
                <input type="checkbox" data-vm-bulk-all title="Seleccionar todos"
                       class="accent-brand-500" aria-label="Seleccionar todos los casos">
            <?php endif; ?>
        </th>
        <th class="px-3 py-2 text-left">CVE</th>
        <th class="px-3 py-2 text-left">Producto</th>
        <th class="px-3 py-2 text-left">Empresa</th>
        <th class="px-3 py-2 text-left">Prioridad</th>
        <th class="px-3 py-2 text-left">Estado</th>
        <th class="px-3 py-2 text-left">Vencimiento</th>
        <th class="px-3 py-2 text-left">Responsable</th>
        <th class="px-3 py-2 text-left">Última obs.</th>
        <th class="px-3 py-2"></th>
    </tr>
</thead>
