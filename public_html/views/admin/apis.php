<?php
/**
 * Vista: Panel de APIs / perfiles de IA.
 * Variables: $profiles, $editProfile, $tasks, $taskProfiles, $success, $error
 */
$pageTitle = 'APIs';
$providers = [
    ''          => '— Selecciona proveedor —',
    'openai'    => 'OpenAI',
    'anthropic' => 'Anthropic',
    'azure'     => 'Azure OpenAI',
    'ollama'    => 'Ollama (local)',
    'ollama_cloud' => 'Ollama Cloud (API)',
    'gemini'    => 'Google Gemini',
    'mistral'   => 'Mistral',
    'custom'    => 'Personalizado (compatible OpenAI)',
];
$editId = (int)($editProfile['id'] ?? 0);
?>
<?php
$flashData = flash();
foreach ($flashData as $type => $msg):
    $colors = match($type) {
        'success' => 'text-green-600 bg-green-50 dark:bg-green-900/20',
        'error'   => 'text-red-600 bg-red-50 dark:bg-red-900/20',
        default   => 'text-blue-600 bg-blue-50 dark:bg-blue-900/20',
    };
?>
    <div class="mb-4 px-4 py-3 rounded-lg text-sm <?= $colors ?>"><?= e($msg) ?></div>
<?php endforeach; ?>

<div class="mb-6">
    <h1 class="text-xl font-semibold">Configuración de APIs</h1>
    <p class="text-sm text-gray-500 mt-1">Guarda varios proveedores de IA a la vez. Marca uno como <strong>predeterminado</strong> y, si quieres, asigna un modelo distinto a cada tarea.</p>
</div>

<!-- Perfiles -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden mb-6">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-sm font-semibold">Perfiles de IA (<?= count($profiles) ?>)</h2>
    </div>
    <?php if (empty($profiles)): ?>
        <p class="px-5 py-6 text-sm text-gray-500">No hay perfiles todavía. Crea el primero abajo.</p>
    <?php else: ?>
        <table class="w-full text-sm">
            <thead>
                <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                    <th class="text-left px-4 py-2">Nombre</th>
                    <th class="text-left px-4 py-2">Proveedor</th>
                    <th class="text-left px-4 py-2">Modelo</th>
                    <th class="text-left px-4 py-2">Estado</th>
                    <th class="text-right px-4 py-2">Acciones</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700/50">
                <?php foreach ($profiles as $p): ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                        <td class="px-4 py-2 font-medium"><?= e($p['name']) ?></td>
                        <td class="px-4 py-2 text-xs text-gray-500"><?= e($p['provider'] ?: '—') ?></td>
                        <td class="px-4 py-2 text-xs font-mono text-gray-500"><?= e($p['model'] ?: '—') ?></td>
                        <td class="px-4 py-2">
                            <?php if (!empty($p['is_default'])): ?>
                                <span class="inline-flex px-2 py-0.5 text-xs rounded-full bg-brand-100 dark:bg-brand-900 text-brand-700 dark:text-brand-300">Predeterminado</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-4 py-2 text-right whitespace-nowrap">
                            <button type="button" onclick="testProfile(<?= (int)$p['id'] ?>)" class="text-xs text-gray-400 hover:text-brand-500 mr-2">Probar</button>
                            <a href="<?= base_url('admin/apis?edit=' . (int)$p['id']) ?>" class="text-xs text-gray-400 hover:text-brand-500 mr-2">Editar</a>
                            <?php if (empty($p['is_default'])): ?>
                                <form method="POST" action="<?= base_url('admin/apis/default') ?>" class="inline">
                                    <?= Csrf::field() ?>
                                    <input type="hidden" name="id" value="<?= (int)$p['id'] ?>">
                                    <button type="submit" class="text-xs text-gray-400 hover:text-brand-500 mr-2">Usar por defecto</button>
                                </form>
                            <?php endif; ?>
                            <form method="POST" action="<?= base_url('admin/apis/delete') ?>" class="inline" data-confirm="¿Eliminar el perfil «<?= e($p['name']) ?>»?" data-confirm-danger>
                                <?= Csrf::field() ?>
                                <input type="hidden" name="id" value="<?= (int)$p['id'] ?>">
                                <button type="submit" class="text-xs text-gray-400 hover:text-red-500">Eliminar</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<!-- Formulario perfil -->
<form method="POST" action="<?= base_url('admin/apis/save') ?>" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 space-y-4 mb-6">
    <?= Csrf::field() ?>
    <input type="hidden" name="id" value="<?= $editId ?>">
    <h2 class="text-lg font-semibold"><?= $editId ? 'Editar perfil' : 'Nuevo perfil' ?></h2>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Nombre</label>
            <input type="text" name="name" value="<?= e($editProfile['name'] ?? '') ?>" placeholder="Mistral prod / OpenAI…"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Proveedor</label>
            <select name="provider" id="provider"
                    class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <?php foreach ($providers as $val => $label): ?>
                    <option value="<?= e($val) ?>" <?= ($editProfile['provider'] ?? '') === $val ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
    </div>

    <div>
        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Base URL <span class="text-gray-400 font-normal">(opcional)</span></label>
        <input type="text" name="api_url" value="<?= e($editProfile['api_url'] ?? '') ?>" placeholder="Vacío = endpoint por defecto del proveedor"
               class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Modelo</label>
            <input type="text" name="model" id="model-input" value="<?= e($editProfile['model'] ?? '') ?>" placeholder="mistral-large-latest / gpt-4o-mini" list="model-suggestions" autocomplete="off"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <datalist id="model-suggestions"></datalist>
            <p class="text-xs text-gray-400 mt-1">El modelo debe ser válido para el proveedor elegido (se sugieren los típicos de cada uno).</p>
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Max tokens</label>
            <input type="number" name="max_tokens" value="<?= (int)($editProfile['max_tokens'] ?? 2048) ?>" min="1" max="128000"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
    </div>

    <div>
        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">API Key</label>
        <input type="password" name="api_key" autocomplete="new-password"
               placeholder="<?= !empty($editProfile['api_key']) ? '•••••••• (ya configurada — deja vacío para mantenerla)' : 'Pega aquí tu API key (no necesaria para Ollama local)' ?>"
               class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
    </div>

    <label class="inline-flex items-center gap-2 text-sm">
        <input type="checkbox" name="is_default" value="1" <?= !empty($editProfile['is_default']) || $editId === 0 ? 'checked' : '' ?> class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
        Usar como perfil predeterminado
    </label>

    <div class="flex items-center gap-3 pt-2 border-t border-gray-100 dark:border-gray-700">
        <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Guardar perfil</button>
        <button type="button" onclick="testForm()" class="px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">Probar conexión</button>
        <button type="button" onclick="verifyForm()" class="px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">Verificar clave (Ollama)</button>
        <?php if ($editId): ?>
            <a href="<?= base_url('admin/apis') ?>" class="text-sm text-gray-500 hover:underline">Cancelar edición</a>
        <?php endif; ?>
    </div>
</form>

<!-- Modelo por tarea -->
<form method="POST" action="<?= base_url('admin/apis/tasks') ?>" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-6">
    <?= Csrf::field() ?>
    <h2 class="text-lg font-semibold mb-1">Modelo por tarea</h2>
    <p class="text-xs text-gray-500 mb-4">Elige qué perfil usar en cada tarea (o deja «Predeterminado»).</p>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <?php foreach ($tasks as $key => $label): ?>
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"><?= e($label) ?></label>
                <select name="tasks[<?= e($key) ?>]" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                    <option value="0" <?= empty($taskProfiles[$key]) ? 'selected' : '' ?>>Predeterminado</option>
                    <?php foreach ($profiles as $p): ?>
                        <option value="<?= (int)$p['id'] ?>" <?= (int)($taskProfiles[$key] ?? 0) === (int)$p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
        <?php endforeach; ?>
    </div>
    <div class="pt-4">
        <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Guardar tareas</button>
    </div>
</form>

<?php
$cve = is_array($cve ?? null) ? $cve : [];
$cveCounts = is_array($cveCounts ?? null) ? $cveCounts : [];
$cveState = is_array($cveState ?? null) ? $cveState : [];
$cveError = $cveError ?? null;
$cveLog = is_array($cveLog ?? null) ? $cveLog : [];
$cvePage = is_array($cvePage ?? null) ? $cvePage : [];
$cveScope = (string)($cve['scope'] ?? 'full');
?>
<!-- Fuentes públicas de CVEs -->
<form method="POST" action="<?= base_url('admin/apis/cve-save') ?>" class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-6 mb-6 space-y-4">
    <?= Csrf::field() ?>
    <div class="flex items-start justify-between gap-4 flex-wrap">
        <div>
            <h2 class="text-lg font-semibold">Fuentes públicas de CVEs</h2>
            <p class="text-xs text-gray-500 mt-1">
                Catálogo NVD + CISA KEV + EPSS. Son fuentes gratuitas; solo NVD usa API key (opcional pero muy recomendable).
            </p>
        </div>
        <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener noreferrer"
           class="text-xs text-brand-600 dark:text-brand-400 hover:underline">Solicitar API key de NVD ↗</a>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">NVD API Key</label>
            <input type="password" name="nvd_api_key" autocomplete="new-password"
                   placeholder="<?= !empty($cve['nvd_key_set']) ? '•••••••• (ya configurada — deja vacío para mantenerla)' : 'Pega aquí tu API key de NVD' ?>"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <label class="inline-flex items-center gap-2 text-xs text-gray-500 mt-2">
                <input type="checkbox" name="clear_nvd_key" value="1" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                Borrar la API key guardada
            </label>
            <p class="text-xs text-gray-400 mt-1">Sin key: 5 peticiones/30 s (≈6 s entre páginas). Con key: 50/30 s (≈0,6 s).</p>
            <p class="text-xs text-gray-400 mt-1">La primera carga completa baja de ~20 min a ~3-4 min con API key y página de 2.000.</p>
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Alcance de la primera carga</label>
            <select name="scope" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <option value="full" <?= $cveScope === 'full' ? 'selected' : '' ?>>Completo — todos los CVEs de NVD</option>
                <option value="recent" <?= $cveScope === 'recent' ? 'selected' : '' ?>>Reciente — últimos años</option>
                <option value="kev" <?= $cveScope === 'kev' ? 'selected' : '' ?>>Solo KEV + EPSS (sin NVD)</option>
            </select>
            <p class="text-xs text-gray-400 mt-1">Se usa cuando aún no hay catálogo. Después, «Actualizar catálogo» usa el incremental.</p>
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">URL de NVD</label>
            <input type="text" name="nvd_url" value="<?= e((string)($cve['nvd_url'] ?? CVE_NVD_URL)) ?>"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Tamaño de página</label>
            <select name="nvd_page_size" class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
                <?php foreach ([500, 1000, 2000] as $size): ?>
                    <option value="<?= $size ?>" <?= (int)($cve['nvd_page_size'] ?? 2000) === $size ? 'selected' : '' ?>><?= number_format($size) ?> CVEs/petición<?= $size === 2000 ? ' — recomendado' : '' ?></option>
                <?php endforeach; ?>
            </select>
            <?php
            $cvePageEffective = (int)($cvePage['effective'] ?? 0);
            $cvePageMemory = (int)($cvePage['memory'] ?? 0);
            $cveRate = (int)($cvePage['rate_max'] ?? 5) . '/' . (int)($cvePage['rate_window'] ?? 30) . ' s';
            ?>
            <p class="text-xs text-gray-400 mt-1">
                En uso: <?= number_format($cvePageEffective) ?> CVEs/petición · rate limit <?= e($cveRate) ?>
                <?php if (!empty($cvePage['degraded'])): ?>
                    <span class="text-amber-600 dark:text-amber-400">(reducido a 1.000 por memory_limit de <?= number_format(max(1, (int)round($cvePageMemory / 1048576))) ?> MB)</span>
                <?php endif; ?>
            </p>
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Años recientes</label>
            <input type="number" name="recent_years" min="1" max="10" value="<?= (int)($cve['recent_years'] ?? 3) ?>"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <p class="text-xs text-gray-400 mt-1">Solo se usa con alcance “Reciente”.</p>
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">CVSS mínimo</label>
            <input type="number" name="min_cvss" min="0" max="10" step="0.1" value="<?= e((string)($cve['min_cvss'] ?? 0)) ?>"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <p class="text-xs text-gray-400 mt-1">0 = guardar todos. Un valor alto reduce el tamaño.</p>
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">URL de CISA KEV</label>
            <input type="text" name="kev_url" value="<?= e((string)($cve['kev_url'] ?? CVE_KEV_URL)) ?>"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">URL de respaldo KEV (GitHub)</label>
            <input type="text" name="kev_fallback_url" value="<?= e((string)($cve['kev_fallback_url'] ?? CVE_KEV_FALLBACK_URL)) ?>"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
            <p class="text-xs text-gray-400 mt-1">Se usa si CISA bloquea la IP del hosting (403). Mirror oficial de CISA.</p>
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">URL del CSV de EPSS</label>
            <input type="text" name="epss_url" value="<?= e((string)($cve['epss_url'] ?? CVE_EPSS_CSV_URL)) ?>"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Sincronización automática</label>
            <label class="inline-flex items-center gap-2 text-sm mt-2">
                <input type="checkbox" name="auto_sync" value="1" <?= !empty($cve['auto_sync']) ? 'checked' : '' ?> class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                Activar sincronización automática (requiere cron)
            </label>
        </div>
        <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Intervalo (horas)</label>
            <input type="number" name="interval_hours" min="1" max="168" value="<?= (int)($cve['interval_hours'] ?? 24) ?>"
                   class="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-brand-500 outline-none">
        </div>
    </div>

    <div class="flex items-center gap-3 pt-2 border-t border-gray-100 dark:border-gray-700 flex-wrap">
        <button type="submit" class="px-4 py-2 bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium rounded-lg transition-colors">Guardar fuentes</button>
        <button type="button" onclick="testCveSources()" class="px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">Probar fuentes</button>
        <button type="button" onclick="startCveSyncFromAdmin('auto')" title="Incremental si ya hay catálogo; primera carga completa si está vacío."
                class="px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors">Actualizar catálogo</button>
        <button type="button" onclick="startCveSyncFromAdmin('full')" title="Reconstruye el catálogo completo desde cero."
                class="px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-500 dark:text-gray-400 text-sm font-medium rounded-lg transition-colors">Reconstruir</button>
        <button type="button" onclick="startCveSyncFromAdmin('kev')" title="Actualiza solo CISA KEV y EPSS, sin descargar NVD."
                class="px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-500 dark:text-gray-400 text-sm font-medium rounded-lg transition-colors">KEV / EPSS</button>
    </div>

    <div id="cve-test-result" class="text-xs text-gray-500 space-y-1"></div>
    <p class="text-xs text-gray-400">
        El progreso de la descarga se muestra en <strong>Seguridad → CVE → Catálogo</strong>.
    </p>

    <?php if (!empty($cveError)): ?>
        <div class="px-4 py-3 rounded-lg text-sm text-red-600 bg-red-50 dark:bg-red-900/20">
            No se pudo abrir la base de datos de CVEs: <?= e($cveError) ?>
        </div>
    <?php else: ?>
        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-3 border-t border-gray-100 dark:border-gray-700">
            <div><p class="text-xs text-gray-400">Catálogo</p><p class="text-sm font-semibold"><?= number_format((int)($cveCounts['catalog'] ?? 0)) ?></p></div>
            <div><p class="text-xs text-gray-400">KEV</p><p class="text-sm font-semibold"><?= number_format((int)($cveCounts['kev'] ?? 0)) ?></p></div>
            <div><p class="text-xs text-gray-400">EPSS</p><p class="text-sm font-semibold"><?= number_format((int)($cveCounts['epss'] ?? 0)) ?></p></div>
            <div><p class="text-xs text-gray-400">Grupos</p><p class="text-sm font-semibold"><?= number_format((int)($cveCounts['groups'] ?? 0)) ?></p></div>
            <div><p class="text-xs text-gray-400">Software</p><p class="text-sm font-semibold"><?= number_format((int)($cveCounts['software'] ?? 0)) ?></p></div>
            <div><p class="text-xs text-gray-400">Matches</p><p class="text-sm font-semibold"><?= number_format((int)($cveCounts['matches'] ?? 0)) ?></p></div>
        </div>
        <p class="text-xs text-gray-400">
            Estado: <strong><?= e((string)($cveState['status'] ?? 'idle')) ?></strong>
            <?php if (!empty($cveState['last_success_at'])): ?> · última sync: <?= e((string)$cveState['last_success_at']) ?><?php endif; ?>
        </p>
    <?php endif; ?>
    <p class="text-xs text-gray-400">
        La API key de NVD se guarda cifrada (AES-256-GCM) y nunca se muestra ni se envía al navegador.
    </p>
</form>

<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 mb-6 overflow-hidden">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-sm font-semibold">Log de sincronización CVE</h2>
        <p class="text-xs text-gray-500 mt-1">
            Últimos 15 eventos (cierres y errores). El número de error (#ID) es el que se muestra al detener una descarga.
        </p>
    </div>
    <?php if (empty($cveLog)): ?>
        <p class="px-5 py-6 text-xs text-gray-400">Todavía no hay eventos registrados.</p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="w-full text-xs">
                <thead>
                    <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-gray-500 uppercase">
                        <th class="text-left px-4 py-2">#</th>
                        <th class="text-left px-4 py-2">Fecha</th>
                        <th class="text-left px-4 py-2">Fuente</th>
                        <th class="text-left px-4 py-2">Modo</th>
                        <th class="text-left px-4 py-2">Estado</th>
                        <th class="text-right px-4 py-2">Registros</th>
                        <th class="text-left px-4 py-2">Detalle</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($cveLog as $entry): ?>
                        <?php
                        $entryStatus = (string)($entry['status'] ?? '');
                        $statusClass = $entryStatus === 'error'
                            ? 'text-red-600 dark:text-red-400'
                            : ($entryStatus === 'warning' ? 'text-amber-600 dark:text-amber-400' : 'text-green-600 dark:text-green-400');
                        ?>
                        <tr class="border-b border-gray-100 dark:border-gray-800 align-top">
                            <td class="px-4 py-2 text-gray-400">#<?= (int)($entry['id'] ?? 0) ?></td>
                            <td class="px-4 py-2 whitespace-nowrap text-gray-500"><?= e((string)($entry['finished_at'] ?? $entry['started_at'] ?? '')) ?></td>
                            <td class="px-4 py-2 uppercase text-gray-500"><?= e((string)($entry['source'] ?? '')) ?></td>
                            <td class="px-4 py-2 text-gray-500"><?= e((string)($entry['mode'] ?? '—')) ?></td>
                            <td class="px-4 py-2 font-medium <?= $statusClass ?>"><?= e($entryStatus) ?></td>
                            <td class="px-4 py-2 text-right text-gray-500"><?= number_format((int)($entry['records'] ?? 0)) ?></td>
                            <td class="px-4 py-2 text-gray-500 break-all max-w-[520px]"><?= e((string)($entry['error'] ?? '')) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<div class="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-xl p-4">
    <p class="text-xs text-amber-700 dark:text-amber-300">
        <strong>Sobre los perfiles de IA:</strong> la API key se guarda <strong>cifrada (AES-256-GCM)</strong> y nunca se muestra ni se envía al navegador.
        Consejo: el <strong>nombre del modelo debe ser válido para el proveedor</strong> elegido; si no, la prueba de conexión indicará «Invalid model».
        Mistral no entrena con tus prompts (zero-retention).
    </p>
</div>

<script>
// Sugerencias de modelos por proveedor (se vuelcan en el <datalist>).
var MODEL_SUGGESTIONS = {
    openai:    ['gpt-4o-mini', 'gpt-4o', 'gpt-4.1-mini', 'gpt-4.1'],
    mistral:   ['mistral-large-latest', 'mistral-small-latest', 'open-mistral-nemo', 'codestral-latest'],
    anthropic: ['claude-3-5-sonnet-20241022', 'claude-3-5-haiku-20241022', 'claude-3-opus-20240229'],
    gemini:    ['gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-2.0-flash'],
    azure:     ['gpt-4o-mini', 'gpt-4o'],
    ollama:    ['llama3.1', 'qwen2.5', 'mistral', 'phi3'],
    ollama_cloud: ['gpt-oss:120b', 'gpt-oss:20b', 'gemma4:31b'],
    custom:    []
};
function updateModelSuggestions() {
    var list = document.getElementById('model-suggestions');
    var prov = document.getElementById('provider');
    if (!list || !prov) return;
    list.innerHTML = '';
    (MODEL_SUGGESTIONS[prov.value] || []).forEach(function(m) {
        var o = document.createElement('option');
        o.value = m;
        list.appendChild(o);
    });
}
function startCveSyncFromAdmin(mode) {
    mode = mode || 'auto';
    var msg = mode === 'full'
        ? 'Se reconstruirá el catálogo completo desde cero. Puede tardar bastante. ¿Continuar?'
        : (mode === 'kev'
            ? 'Se actualizarán solo CISA KEV y EPSS. ¿Continuar?'
            : 'Se actualizará el catálogo NVD en segundo plano. ¿Continuar?');
    if (!window.confirm(msg)) return;
    api('POST', '<?= base_url('modules/cve/sync') ?>', { mode: mode })
        .then(function(res) {
            if (!res || !res.success) {
                toast((res && res.error) ? res.error : 'No se pudo iniciar la sincronización', 'error');
                return;
            }
            toast(res.message || 'Sincronización iniciada', res.worker_started ? 'success' : 'info');
        })
        .catch(function() { toast('Error de conexión', 'error'); });
}
function testCveSources() {
    var box = document.getElementById('cve-test-result');
    if (box) { box.textContent = 'Probando fuentes…'; }
    api('POST', '<?= base_url('admin/apis/cve-test') ?>', {})
        .then(function(res) {
            if (!res || !res.sources) {
                if (box) { box.textContent = (res && res.error) ? res.error : 'Error al probar las fuentes.'; }
                toast((res && res.error) ? res.error : 'Error al probar las fuentes', 'error');
                return;
            }
            var labels = {nvd: 'NVD', kev: 'CISA KEV', epss: 'EPSS'};
            var html = '';
            var hasProblem = false;
            ['nvd', 'kev', 'epss'].forEach(function(k) {
                var s = res.sources[k] || {};
                var status = s.status || (s.ok ? 'ok' : 'error');
                if (status !== 'ok') { hasProblem = true; }
                var color = status === 'ok'
                    ? 'text-green-600 dark:text-green-400'
                    : (status === 'warning' ? 'text-amber-600 dark:text-amber-400' : 'text-red-600 dark:text-red-400');
                var label = labels[k];
                if (k === 'kev' && s.source === 'github') { label = 'CISA KEV (mirror GitHub)'; }
                html += '<div><span class="font-medium ' + color + '">' + label + ':</span> ' + escHtml(s.message || '') + '</div>';
            });
            if (box) { box.innerHTML = html; }
            if (!res.success) {
                toast('Hay fuentes con error', 'error');
            } else if (hasProblem) {
                toast('Fuentes comprobadas con avisos', 'warning');
            } else {
                toast('Fuentes comprobadas correctamente', 'success');
            }
        })
        .catch(function() {
            if (box) { box.textContent = 'Error de conexión.'; }
            toast('Error de conexión', 'error');
        });
}
function escHtml(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
}
function testProfile(id) {
    api('POST', '<?= base_url('admin/apis/test') ?>', { profile_id: id })
        .then(function(res) { toast(res.success ? (res.message || 'OK') : ('Error: ' + (res.error || 'desconocido')), res.success ? 'success' : 'error'); })
        .catch(function() { toast('Error de conexión', 'error'); });
}
function formPayload() {
    var idInput = document.querySelector('input[name="id"]');
    return {
        id: idInput ? idInput.value : '0',
        provider: document.getElementById('provider').value,
        api_url: document.querySelector('input[name="api_url"]').value,
        model: document.querySelector('input[name="model"]').value,
        api_key: document.querySelector('input[name="api_key"]').value
    };
}
function testForm() {
    api('POST', '<?= base_url('admin/apis/test') ?>', formPayload())
        .then(function(res) { toast(res.success ? (res.message || 'OK') : ('Error: ' + (res.error || 'desconocido')), res.success ? 'success' : 'error'); })
        .catch(function() { toast('Error de conexión', 'error'); });
}
function verifyForm() {
    api('POST', '<?= base_url('admin/apis/verify') ?>', formPayload())
        .then(function(res) { toast(res.success ? (res.message || 'OK') : ('Error: ' + (res.error || 'desconocido')), res.success ? 'success' : 'error'); })
        .catch(function() { toast('Error de conexión', 'error'); });
}

(function() {
    var prov = document.getElementById('provider');
    if (prov) { prov.addEventListener('change', updateModelSuggestions); }
    updateModelSuggestions();
})();
</script>
