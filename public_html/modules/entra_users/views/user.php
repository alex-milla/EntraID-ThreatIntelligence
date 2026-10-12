<?php
/**
 * Vista: ficha de un usuario de Entra ID.
 * Variables: $tenant, $user, $profileError, $methods, $methodsError, $mfa, $mfaError,
 *            $signIns, $signInsError, $risk, $riskError, $usualCountry, $countryCounts
 */
$methodsMap = [
    'passwordAuthenticationMethod'               => 'Contraseña',
    'microsoftAuthenticatorAuthenticationMethod' => 'Microsoft Authenticator',
    'phoneAuthenticationMethod'                  => 'Teléfono',
    'emailAuthenticationMethod'                  => 'Email',
    'fido2AuthenticationMethod'                  => 'Clave FIDO2',
    'windowsHelloForBusinessAuthenticationMethod'=> 'Windows Hello',
    'softwareOathAuthenticationMethod'           => 'App OATH',
    'temporaryAccessPassAuthenticationMethod'    => 'Acceso temporal (TAP)',
    'passwordlessMicrosoftAuthenticatorAuthenticationMethod' => 'Authenticator sin contraseña',
    'platformCredentialAuthenticationMethod'     => 'Credencial de plataforma',
];
?>
<div class="mb-6 flex items-start justify-between gap-4">
    <div class="min-w-0">
        <a href="<?= base_url('modules/entra_users?tenant=' . (int)$tenant['id']) ?>" class="text-xs text-brand-500 hover:underline">← Volver</a>
        <h1 class="text-xl font-semibold mt-2"><?= e($user['displayName'] ?? 'Usuario') ?></h1>
        <p class="text-xs text-gray-400 font-mono mt-1"><?= e($user['userPrincipalName'] ?? '') ?> · <?= e($tenant['name'] ?? '') ?></p>
    </div>
    <?php if (!empty($user['accountEnabled']) || (isset($user['accountEnabled']) && $user['accountEnabled'] === false)): ?>
        <span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 <?= !empty($user['accountEnabled']) ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' ?>">
            <?= !empty($user['accountEnabled']) ? 'Cuenta activa' : 'Deshabilitada' ?>
        </span>
    <?php endif; ?>
</div>

<?php if (!empty($profileError)): ?>
    <div class="mb-4 px-4 py-3 rounded-lg text-sm text-red-600 bg-red-50 dark:bg-red-900/20">No se pudo leer el perfil: <?= e($profileError) ?></div>
<?php endif; ?>

<!-- Tarjetas -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h2 class="text-xs font-semibold text-gray-500 uppercase mb-3">Perfil</h2>
        <dl class="space-y-2 text-sm">
            <div><dt class="text-gray-400 text-xs">Departamento</dt><dd class="font-medium"><?= e($user['department'] ?? '—') ?></dd></div>
            <div><dt class="text-gray-400 text-xs">Empresa</dt><dd class="font-medium"><?= e($user['companyName'] ?? '—') ?></dd></div>
            <div><dt class="text-gray-400 text-xs">Cargo</dt><dd class="font-medium"><?= e($user['jobTitle'] ?? '—') ?></dd></div>
            <div><dt class="text-gray-400 text-xs">País / ciudad</dt><dd class="font-medium"><?= e(trim(($user['country'] ?? '') . ' ' . ($user['city'] ?? '')) ?: '—') ?></dd></div>
        </dl>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h2 class="text-xs font-semibold text-gray-500 uppercase mb-3">Contraseña</h2>
        <p class="text-sm font-medium"><?= !empty($user['lastPasswordChangeDateTime']) ? format_date($user['lastPasswordChangeDateTime']) : '—' ?></p>
        <p class="text-xs text-gray-400 mt-1">Último cambio de contraseña</p>
        <p class="text-xs text-gray-400 mt-3">Alta: <?= !empty($user['createdDateTime']) ? format_date($user['createdDateTime']) : '—' ?></p>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h2 class="text-xs font-semibold text-gray-500 uppercase mb-3">MFA</h2>
        <?php if (!empty($mfaError) && empty($methods)): ?>
            <p class="text-xs text-red-500"><?= e($mfaError) ?></p>
        <?php else: ?>
            <div class="flex items-center gap-2 mb-2">
                <?php $mfaOk = !empty($mfa['isMfaRegistered']); ?>
                <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $mfaOk ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' ?>">
                    <?= $mfaOk ? 'MFA registrado' : 'MFA no registrado' ?>
                </span>
                <?php if (isset($mfa['isMfaCapable'])): ?>
                    <span class="text-xs text-gray-400"><?= !empty($mfa['isMfaCapable']) ? 'capaz' : 'no capaz' ?></span>
                <?php endif; ?>
            </div>
            <?php if (!empty($methods)): ?>
                <ul class="text-xs text-gray-600 dark:text-gray-300 space-y-1">
                    <?php foreach ($methods as $m): ?>
                        <?php
                        $t = (string)($m['@odata.type'] ?? '');
                        $t = preg_replace('/^#microsoft\.graph\./', '', $t);
                        $label = $methodsMap[$t] ?? $t;
                        $extra = '';
                        if ($t === 'phoneAuthenticationMethod' && !empty($m['phoneNumber'])) $extra = ' (' . $m['phoneNumber'] . ')';
                        ?>
                        <li>· <?= e($label . $extra) ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php elseif (empty($mfaError)): ?>
                <p class="text-xs text-gray-500">Sin métodos detectados.</p>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 p-5">
        <h2 class="text-xs font-semibold text-gray-500 uppercase mb-3">Riesgo</h2>
        <?php if (!empty($riskError)): ?>
            <p class="text-xs text-gray-500"><?= e($riskError) ?></p>
        <?php elseif (!empty($risk)): ?>
            <?php
            $rl = strtolower((string)($risk['riskLevel'] ?? ''));
            $rlClass = $rl === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                : ($rl === 'medium' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'
                : ($rl === 'low' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'));
            ?>
            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $rlClass ?>"><?= e($risk['riskLevel'] ?? '—') ?></span>
            <p class="text-sm mt-2"><span class="text-gray-400 text-xs">Estado:</span> <?= e($risk['riskState'] ?? '—') ?></p>
            <p class="text-sm"><span class="text-gray-400 text-xs">Detalle:</span> <?= e($risk['riskDetail'] ?? '—') ?></p>
            <p class="text-xs text-gray-400 mt-2">Actualizado: <?= !empty($risk['riskLastUpdatedDateTime']) ? format_date($risk['riskLastUpdatedDateTime']) : '—' ?></p>
        <?php else: ?>
            <p class="text-sm text-gray-500">Sin riesgo registrado.</p>
            <p class="text-xs text-gray-400 mt-1">(Requiere Entra ID P2)</p>
        <?php endif; ?>
    </div>
</div>

<!-- Sign-ins -->
<div class="bg-white dark:bg-surface-dark rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between gap-3 flex-wrap">
        <h2 class="text-sm font-semibold">Inicios de sesión (<?= count($signIns) ?>)</h2>
        <div class="flex items-center gap-4 text-xs">
            <span class="text-gray-400">País habitual: <strong class="text-gray-600 dark:text-gray-300"><?= e($usualCountry ?? '—') ?></strong></span>
            <label class="inline-flex items-center gap-2 cursor-pointer">
                <input type="checkbox" id="only-outside" onchange="filterSignins()" class="rounded border-gray-300 text-brand-500 focus:ring-brand-500">
                Solo fuera del país habitual
            </label>
        </div>
    </div>

    <?php if (!empty($signInsError)): ?>
        <p class="px-5 py-6 text-sm text-red-500">No se pudieron leer los sign-ins: <?= e($signInsError) ?></p>
    <?php elseif (empty($signIns)): ?>
        <p class="px-5 py-6 text-sm text-gray-500">Sin inicios de sesión registrados.</p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="w-full text-sm">
                <thead>
                    <tr class="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-xs text-gray-500 uppercase">
                        <th class="text-left px-4 py-2">Fecha</th>
                        <th class="text-left px-4 py-2">IP</th>
                        <th class="text-left px-4 py-2">País / ciudad</th>
                        <th class="text-left px-4 py-2">App</th>
                        <th class="text-left px-4 py-2">Resultado</th>
                    </tr>
                </thead>
                <tbody id="signin-body" class="divide-y divide-gray-100 dark:divide-gray-700/50">
                    <?php foreach ($signIns as $s): ?>
                        <?php
                        $country = $s['location']['countryOrRegion'] ?? '';
                        $city = $s['location']['city'] ?? '';
                        $outside = ($usualCountry !== null && $country !== '' && $country !== $usualCountry);
                        $ok = ((int)($s['status']['errorCode'] ?? 0) === 0);
                        ?>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50 <?= $outside ? 'bg-red-50/60 dark:bg-red-950/20' : '' ?>" data-outside="<?= $outside ? '1' : '0' ?>">
                            <td class="px-4 py-2 text-xs whitespace-nowrap"><?= format_date($s['createdDateTime'] ?? null) ?></td>
                            <td class="px-4 py-2 text-xs font-mono"><?= e($s['ipAddress'] ?? '—') ?></td>
                            <td class="px-4 py-2 text-xs">
                                <?= e($country ?: '—') ?><?= $city ? ' · ' . e($city) : '' ?>
                                <?php if ($outside): ?><span class="ml-1 inline-flex px-1.5 py-0.5 text-[10px] rounded bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">fuera</span><?php endif; ?>
                            </td>
                            <td class="px-4 py-2 text-xs text-gray-500"><?= e($s['clientAppUsed'] ?? '—') ?></td>
                            <td class="px-4 py-2 text-xs">
                                <span class="<?= $ok ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400' ?>"><?= $ok ? 'Correcto' : ('Fallido (' . (int)($s['status']['errorCode'] ?? 0) . ')') ?></span>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<script>
function filterSignins() {
    var only = document.getElementById('only-outside').checked;
    document.querySelectorAll('#signin-body tr').forEach(function (tr) {
        tr.style.display = (only && tr.getAttribute('data-outside') !== '1') ? 'none' : '';
    });
}
</script>
