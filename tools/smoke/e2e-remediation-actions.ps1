# ============================================================
#  E2E de acciones del ticket (CVE Desk, F2)
#
#  Recorre la máquina de estados desde la ficha:
#    planificar → iniciar → retraso → bloqueo → reactivar →
#    verificación → fallo → cierre con evidencia → reabrir → riesgo.
#
#  Restaura database.sqlite en `finally`; no usa red externa.
#
#  Uso:
#    pwsh tools/smoke/e2e-remediation-actions.ps1
# ============================================================
param(
    [int]$Port = 8889,
    [string]$User = 'admin',
    [string]$Pass = 'admin'
)

$ErrorActionPreference = 'Stop'
$root    = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$docroot = Join-Path $root 'public_html'
$storage = Join-Path $docroot 'storage'
$probe   = Join-Path $PSScriptRoot 'remediation-probe.php'
$base    = "http://127.0.0.1:$Port"

$fail = 0
$total = 0
function Check {
    param([string]$label, [bool]$ok, [string]$detail = '')
    $script:total++
    if ($ok) {
        Write-Host "OK   $label" -ForegroundColor Green
        return
    }
    $script:fail++
    Write-Host "FALLO $label" -NoNewline -ForegroundColor Red
    if ($detail -ne '') { Write-Host " - $detail" } else { Write-Host '' }
}

function Probe {
    param([string[]]$cmdArgs)
    $raw = & php -f $probe @cmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Probe falló: $($cmdArgs -join ' ')"
    }
    return ($raw | ConvertFrom-Json)
}

$names = @('database.sqlite', 'database.sqlite-wal', 'database.sqlite-shm')
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('rem-act-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
foreach ($name in $names) {
    $src = Join-Path $storage $name
    if (Test-Path $src) { Copy-Item $src (Join-Path $tmp $name) -Force }
}

$server = $null
$orgId = 0
try {
    $server = Start-Process -FilePath 'php' `
        -ArgumentList @('-d', 'post_max_size=64M', '-d', 'upload_max_filesize=64M',
                        '-S', "127.0.0.1:$Port", '-t', $docroot, (Join-Path $PSScriptRoot 'router.php')) `
        -WorkingDirectory $docroot -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2

    $login = Invoke-WebRequest -Uri "$base/admin/login" -SessionVariable ws -UseBasicParsing -TimeoutSec 30
    $token = [regex]::Match($login.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    $post = Invoke-WebRequest -Uri "$base/admin/login" -Method POST -WebSession $ws `
        -Body @{ username=$User; password=$Pass; csrf_token=$token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    if ($post.Content -match 'name="password"') { throw 'login fallido' }

    $seed = Probe @('seed-workflow')
    $orgId = [int]$seed.org_id
    $taskId = [int]$seed.task_id
    $taskUrl = "$base/index.php/modules/remediation?tab=tasks&org=$orgId&task=$taskId"
    $actionUrl = "$base/index.php/modules/remediation/tasks/action"

    $page = Invoke-WebRequest -Uri $taskUrl -WebSession $ws -UseBasicParsing -TimeoutSec 60
    $csrf = [regex]::Match($page.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    $baseBody = @{ csrf_token = $csrf; org_id = "$orgId"; task_id = "$taskId" }

    # --- estado inicial ---
    Check 'ficha: stepper' ($page.Content -match 'w-6 h-6 rounded-full' -and $page.Content -match 'Cierre')
    Check 'ficha: primaria Planificar' ($page.Content -match 'Planificar')
    Check 'ficha: incidencia visible' ($page.Content -match 'Registrar incidencia')
    Check 'ficha: aceptar riesgo' ($page.Content -match 'Aceptar riesgo')
    Check 'ficha: datos de gestión' ($page.Content -match 'Datos de gestión')

    # --- planificar ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'planificar'; ventana_parcheo = 'dom 22:00' }) `
        -UseBasicParsing -TimeoutSec 60
    Check 'planificar: aviso' ($r.Content -match 'Ticket planificado')
    Check 'planificar: estado' ($r.Content -match 'Planificado')
    Check 'planificar: primaria Iniciar' ($r.Content -match 'Iniciar parcheo')
    Check 'planificar: ventana visible' ($r.Content -match 'dom 22:00')

    # Guardar campos sin enviar `status` no debe reabrir ni cambiar el ciclo.
    $saveUrl = "$base/index.php/modules/remediation/tasks/save"
    $r = Invoke-WebRequest -Uri $saveUrl -Method POST -WebSession $ws `
        -Body @{
            csrf_token = $csrf; org_id = "$orgId"; id = "$taskId";
            owner = 'Equipo de sistemas'; due_at = [string]$seed.due_at;
            patch_kb = ''; fixed_version = ''; evidence = ''; notes = 'Solo campos'; exception_until = ''
        } `
        -UseBasicParsing -TimeoutSec 60
    $state = Probe @('workflow', "$taskId")
    Check 'guardar campos: conserva el estado' ([string]$state.estado -eq 'planificado') ([string]$state.estado)
    Check 'guardar campos: aviso' ($r.Content -match 'Tarea actualizada')

    # --- iniciar ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'iniciar' }) -UseBasicParsing -TimeoutSec 60
    Check 'iniciar: estado' ($r.Content -match 'En curso')
    Check 'iniciar: primaria verificación' ($r.Content -match 'Pasar a verificación')

    # --- retraso ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'incidencia'; tipo = 'retraso'; texto = 'Ventana denegada por FW'; impacto_dias = '2' }) `
        -UseBasicParsing -TimeoutSec 60
    Check 'retraso: aviso' ($r.Content -match 'Entrada añadida')
    Check 'retraso: acumulado' ($r.Content -match '\+2 d · 1 entrada')

    # --- bloqueo ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'incidencia'; tipo = 'bloqueo'; texto = 'Vendor sin parche'; impacto_dias = '3' }) `
        -UseBasicParsing -TimeoutSec 60
    Check 'bloqueo: estado' ($r.Content -match 'Bloqueado')
    Check 'bloqueo: primaria Reactivar' ($r.Content -match 'Reactivar')
    Check 'bloqueo: ETA desplazada' ($r.Content -match '\+5 d · 2 entrada')
    $state = Probe @('workflow', "$taskId")
    Check 'bloqueo: estado en BD' ([string]$state.estado -eq 'bloqueado') ([string]$state.estado)

    # --- reactivar ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'reactivar' }) -UseBasicParsing -TimeoutSec 60
    Check 'reactivar: vuelve a en curso' ($r.Content -match 'En curso')

    # --- verificación y fallo ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'pasar_verificacion' }) -UseBasicParsing -TimeoutSec 60
    Check 'verificación: estado' ($r.Content -match 'En verificación')
    Check 'verificación: Cerrar CVE' ($r.Content -match 'Cerrar CVE')
    Check 'verificación: fallo visible' ($r.Content -match 'Verificación fallida')

    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'verificacion_fallida'; motivo = 'Sigue vulnerable'; impacto_dias = '1' }) `
        -UseBasicParsing -TimeoutSec 60
    Check 'fallo: vuelve a en curso' ($r.Content -match 'En curso')
    Check 'fallo: motivo en el registro' ($r.Content -match 'Sigue vulnerable')

    # --- cerrar sin evidencia (debe fallar) ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'cerrar' }) -UseBasicParsing -TimeoutSec 60
    Check 'cierre sin evidencia: error' ($r.Content -match 'Falta el campo obligatorio: evidencia')
    $state = Probe @('workflow', "$taskId")
    Check 'cierre sin evidencia: no cierra' ([string]$state.estado -ne 'cerrado') ([string]$state.estado)

    # --- cerrar con evidencia ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'cerrar'; evidencia = 'CHG-2026-0123 · KB5040442'; resolucion = 'patched' }) `
        -UseBasicParsing -TimeoutSec 60
    Check 'cierre: estado cerrado' ($r.Content -match 'Cerrado')
    Check 'cierre: evidencia visible' ($r.Content -match 'CHG-2026-0123')
    Check 'cierre: primaria Reabrir' ($r.Content -match 'Reabrir')
    $state = Probe @('workflow', "$taskId")
    Check 'cierre: estado en BD' ([string]$state.estado -eq 'cerrado') ([string]$state.estado)
    Check 'cierre: status patched' ([string]$state.status -eq 'patched') ([string]$state.status)

    # --- reabrir ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'reabrir' }) -UseBasicParsing -TimeoutSec 60
    Check 'reabrir: ticket creado' ($r.Content -match 'Ticket creado')

    # --- riesgo: caducidad fuera de plazo ---
    $tooLong = (Get-Date).AddDays(120).ToString('yyyy-MM-dd')
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'aceptar_riesgo'; justificacion = 'Compensado con WAF'; caducidad = $tooLong }) `
        -UseBasicParsing -TimeoutSec 60
    Check 'riesgo: caducidad > 90 rechazada' ($r.Content -match 'no puede superar 90')

    # --- riesgo válido ---
    $valid = (Get-Date).AddDays(30).ToString('yyyy-MM-dd')
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'aceptar_riesgo'; justificacion = 'Compensado con WAF'; caducidad = $valid }) `
        -UseBasicParsing -TimeoutSec 60
    Check 'riesgo: aceptado' ($r.Content -match 'Riesgo aceptado y registrado')
    Check 'riesgo: chip' ($r.Content -match 'Riesgo aceptado')
    $state = Probe @('workflow', "$taskId")
    Check 'riesgo: estado en BD' ([string]$state.estado -eq 'riesgo_aceptado') ([string]$state.estado)
    Check 'riesgo: última entrada' ([string]$state.last_type -eq 'riesgo') ([string]$state.last_type)

    # --- cancelar aceptación ---
    $r = Invoke-WebRequest -Uri $actionUrl -Method POST -WebSession $ws `
        -Body ($baseBody + @{ action = 'cancelar_riesgo' }) -UseBasicParsing -TimeoutSec 60
    Check 'cancelar riesgo: vuelve a la cola' ($r.Content -match 'Ticket creado')
} finally {
    if ($orgId -gt 0) {
        try { Probe @('cleanup', "$orgId") | Out-Null } catch {}
    }
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        Start-Sleep -Milliseconds 500
    }
    foreach ($name in $names) {
        $dst = Join-Path $storage $name
        if (Test-Path $dst) { Remove-Item $dst -Force -ErrorAction SilentlyContinue }
        $src = Join-Path $tmp $name
        if (Test-Path $src) { Copy-Item $src $dst -Force }
    }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($fail -eq 0) { Write-Host "RESULTADO: OK ($total comprobaciones)" -ForegroundColor Green }
else { Write-Host "RESULTADO: $fail fallo(s) de $total" -ForegroundColor Red; exit 1 }
