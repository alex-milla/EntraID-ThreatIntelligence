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
        <p class="text-xs text-ink-soft font-mono mt-1"><?= e($user['userPrincipalName'] ?? '') ?> · <?= e($tenant['name'] ?? '') ?></p>
    </div>
    <?php if (!empty($user['accountEnabled']) || (isset($user['accountEnabled']) && $user['accountEnabled'] === false)): ?>
        <span class="inline-flex px-2 py-0.5 text-xs rounded-full shrink-0 <?= !empty($user['accountEnabled']) ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' ?>">
            <?= !empty($user['accountEnabled']) ? 'Cuenta activa' : 'Deshabilitada' ?>
        </span>
    <?php endif; ?>
</div>

<?php if (!empty($profileError)): ?>
    <div class="alert alert-error">No se pudo leer el perfil: <?= e($profileError) ?></div>
<?php endif; ?>

<!-- Tarjetas -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <div class="card p-5">
        <h2 class="text-xs font-semibold text-ink-muted uppercase mb-3">Perfil</h2>
        <dl class="space-y-2 text-sm">
            <div><dt class="text-ink-soft text-xs">Departamento</dt><dd class="font-medium"><?= e($user['department'] ?? '—') ?></dd></div>
            <div><dt class="text-ink-soft text-xs">Empresa</dt><dd class="font-medium"><?= e($user['companyName'] ?? '—') ?></dd></div>
            <div><dt class="text-ink-soft text-xs">Cargo</dt><dd class="font-medium"><?= e($user['jobTitle'] ?? '—') ?></dd></div>
            <div><dt class="text-ink-soft text-xs">País / ciudad</dt><dd class="font-medium"><?= e(trim(($user['country'] ?? '') . ' ' . ($user['city'] ?? '')) ?: '—') ?></dd></div>
        </dl>
    </div>

    <div class="card p-5">
        <h2 class="text-xs font-semibold text-ink-muted uppercase mb-3">Contraseña</h2>
        <p class="text-sm font-medium"><?= !empty($user['lastPasswordChangeDateTime']) ? format_date($user['lastPasswordChangeDateTime']) : '—' ?></p>
        <p class="text-xs text-ink-soft mt-1">Último cambio de contraseña</p>
        <p class="text-xs text-ink-soft mt-3">Alta: <?= !empty($user['createdDateTime']) ? format_date($user['createdDateTime']) : '—' ?></p>
    </div>

    <div class="card p-5">
        <h2 class="text-xs font-semibold text-ink-muted uppercase mb-3">MFA</h2>
        <?php if (!empty($mfaError) && empty($methods)): ?>
            <p class="text-xs text-red-500"><?= e($mfaError) ?></p>
        <?php else: ?>
            <div class="flex items-center gap-2 mb-2">
                <?php $mfaOk = !empty($mfa['isMfaRegistered']); ?>
                <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $mfaOk ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' ?>">
                    <?= $mfaOk ? 'MFA registrado' : 'MFA no registrado' ?>
                </span>
                <?php if (isset($mfa['isMfaCapable'])): ?>
                    <span class="text-xs text-ink-soft"><?= !empty($mfa['isMfaCapable']) ? 'capaz' : 'no capaz' ?></span>
                <?php endif; ?>
            </div>
            <?php if (!empty($methods)): ?>
                <ul class="text-xs text-ink-muted space-y-1">
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
                <p class="text-xs text-ink-muted">Sin métodos detectados.</p>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <div class="card p-5">
        <h2 class="text-xs font-semibold text-ink-muted uppercase mb-3">Riesgo</h2>
        <?php if (!empty($riskError)): ?>
            <p class="text-xs text-ink-muted"><?= e($riskError) ?></p>
        <?php elseif (!empty($risk)): ?>
            <?php
            $rl = strtolower((string)($risk['riskLevel'] ?? ''));
            $rlClass = $rl === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                : ($rl === 'medium' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300'
                : ($rl === 'low' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'));
            ?>
            <span class="inline-flex px-2 py-0.5 text-xs rounded-full <?= $rlClass ?>"><?= e($risk['riskLevel'] ?? '—') ?></span>
            <p class="text-sm mt-2"><span class="text-ink-soft text-xs">Estado:</span> <?= e($risk['riskState'] ?? '—') ?></p>
            <p class="text-sm"><span class="text-ink-soft text-xs">Detalle:</span> <?= e($risk['riskDetail'] ?? '—') ?></p>
            <p class="text-xs text-ink-soft mt-2">Actualizado: <?= !empty($risk['riskLastUpdatedDateTime']) ? format_date($risk['riskLastUpdatedDateTime']) : '—' ?></p>
        <?php else: ?>
            <p class="text-sm text-ink-muted">Sin riesgo registrado.</p>
            <p class="text-xs text-ink-soft mt-1">(Requiere Entra ID P2)</p>
        <?php endif; ?>
    </div>
</div>

<!-- Sign-ins -->
<?php $mfaCodes = [50074, 50076, 500121, 50158]; ?>
<div class="card overflow-hidden">
    <div class="px-5 py-4 border-b border-line flex items-center justify-between gap-3 flex-wrap">
        <div class="flex items-center gap-3 flex-wrap">
            <h2 class="text-sm font-semibold">Inicios de sesión (<?= count($signIns) ?>)</h2>
            <div class="flex items-center gap-2 text-xs">
                <span class="text-ink-soft">Periodo:</span>
                <?php foreach ([1 => '24 h', 7 => '7 días', 14 => '14 días', 30 => '30 días', 0 => 'Sin filtro'] as $d => $lbl): ?>
                    <a href="?tenant=<?= (int)$tenant['id'] ?>&days=<?= $d ?>" class="<?= (int)($days ?? 7) === $d ? 'font-semibold text-brand-500' : 'text-gray-500 hover:underline' ?>"><?= $lbl ?></a>
                <?php endforeach; ?>
            </div>
        </div>
        <div class="flex items-center gap-3 flex-wrap text-xs">
            <select id="filter-state" onchange="applyFilters()" class="px-2 py-1 rounded-lg border border-line-strong bg-input text-xs">
                <option value="">Todos los resultados</option>
                <option value="ok">Correcto</option>
                <option value="mfa">MFA no completado</option>
                <option value="fail">Fallido</option>
            </select>
            <label class="inline-flex items-center gap-2 cursor-pointer">
                <input type="checkbox" id="only-outside" onchange="applyFilters()" class="rounded border-line-strong text-brand-500 focus:ring-brand-500">
                Solo fuera del país habitual
            </label>
        </div>
    </div>

    <?php if (!empty($signInsFallback)): ?>
        <div class="px-5 py-2 text-xs text-warning bg-warning-bg/30 border-b border-warning-border">
            El filtro de fecha no devolvió resultados; mostrando los inicios de sesión más recientes.
        </div>
    <?php endif; ?>

    <?php if (!empty($signInsError)): ?>
        <div class="px-5 py-6 text-sm text-red-500">
            No se pudieron leer los sign-ins: <?= e($signInsError) ?>
            <p class="text-xs text-ink-soft mt-1">Requiere el permiso <code>AuditLog.Read.All</code>.</p>
        </div>
    <?php elseif (empty($signIns)): ?>
        <p class="px-5 py-6 text-sm text-ink-muted">Sin inicios de sesión en el periodo seleccionado. <span class="text-ink-soft">(El histórico es de 7 días; con Entra ID P1/P2, hasta 30).</span></p>
    <?php else: ?>
        <div class="px-5 py-3 border-b border-line flex items-center gap-4 text-xs flex-wrap">
            <span class="text-ink-soft">Mostrando <strong id="cnt-shown"><?= count($signIns) ?></strong>:</span>
            <span class="text-success">● Correctos: <strong id="cnt-ok">0</strong></span>
            <span class="text-orange-500 dark:text-orange-400">● MFA no completado: <strong id="cnt-mfa">0</strong></span>
            <span class="text-danger">● Fallidos: <strong id="cnt-fail">0</strong></span>
            <span class="text-ink-soft">· País habitual: <strong class="text-ink-muted"><?= e($usualCountry ?? '—') ?></strong></span>
        </div>
        <div class="overflow-x-auto">
            <table class="data-table w-full text-sm">
                <thead>
                    <tr class="border-b border-line bg-muted text-xs text-ink-muted uppercase">
                        <th class="text-left px-4 py-2">Fecha</th>
                        <th class="text-left px-4 py-2">IP</th>
                        <th class="text-left px-4 py-2">País / ciudad</th>
                        <th class="text-left px-4 py-2">App</th>
                        <th class="text-left px-4 py-2">Resultado</th>
                    </tr>
                </thead>
                <tbody id="signin-body" class="divide-y divide-line-subtle">
                    <?php foreach ($signIns as $s): ?>
                        <?php
                        $country = $s['location']['countryOrRegion'] ?? '';
                        $city = $s['location']['city'] ?? '';
                        $outside = ($usualCountry !== null && $country !== '' && $country !== $usualCountry);
                        $ec = (int)($s['status']['errorCode'] ?? 0);
                        $fr = (string)($s['status']['failureReason'] ?? '');
                        if ($ec === 0) {
                            $state = 'ok';
                        } elseif (in_array($ec, $mfaCodes, true) || stripos($fr, 'strong authentication') !== false || stripos($fr, 'multi-factor') !== false) {
                            $state = 'mfa';
                        } else {
                            $state = 'fail';
                        }
                        $badge = match($state) {
                            'ok'    => 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
                            'mfa'   => 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
                            default => 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
                        };
                        $label = match($state) { 'ok' => 'Correcto', 'mfa' => 'MFA no completado', default => 'Fallido' };
                        ?>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50 <?= $outside ? 'bg-red-50/60 dark:bg-red-950/20' : '' ?>" data-state="<?= $state ?>" data-outside="<?= $outside ? '1' : '0' ?>">
                            <td class="px-4 py-2 text-xs whitespace-nowrap"><?= format_date($s['createdDateTime'] ?? null) ?></td>
                            <td class="px-4 py-2 text-xs font-mono"><?= e($s['ipAddress'] ?? '—') ?></td>
                            <td class="px-4 py-2 text-xs">
                                <?= e($country ?: '—') ?><?= $city ? ' · ' . e($city) : '' ?>
                                <?php if ($outside): ?><span class="ml-1 inline-flex px-1.5 py-0.5 text-[10px] rounded bg-danger-bg text-danger">fuera</span><?php endif; ?>
                            </td>
                            <td class="px-4 py-2 text-xs text-ink-muted"><?= e($s['clientAppUsed'] ?? '—') ?></td>
                            <td class="px-4 py-2 text-xs">
                                <span class="inline-flex px-2 py-0.5 rounded text-[11px] <?= $badge ?>"><?= e($label) ?></span>
                                <?php if ($ec !== 0): ?><span class="ml-1 text-[10px] text-ink-soft font-mono"><?= $ec ?></span><?php endif; ?>
                                <?php if ($fr !== ''): ?><div class="text-[10px] text-ink-soft mt-0.5"><?= e(truncate($fr, 90)) ?></div><?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<script>
function applyFilters() {
    var state = document.getElementById('filter-state') ? document.getElementById('filter-state').value : '';
    var only = document.getElementById('only-outside') ? document.getElementById('only-outside').checked : false;
    var c = { ok: 0, mfa: 0, fail: 0 }, shown = 0;

    document.querySelectorAll('#signin-body tr').forEach(function (tr) {
        var st = tr.getAttribute('data-state');
        var outside = tr.getAttribute('data-outside') === '1';
        var vis = (state === '' || state === st) && (!only || outside);
        tr.style.display = vis ? '' : 'none';
        if (vis) { shown++; if (c[st] !== undefined) c[st]++; }
    });

    var set = function (id, v) { var el = document.getElementById(id); if (el) el.textContent = v; };
    set('cnt-ok', c.ok); set('cnt-mfa', c.mfa); set('cnt-fail', c.fail); set('cnt-shown', shown);
}
document.addEventListener('DOMContentLoaded', applyFilters);
</script>
