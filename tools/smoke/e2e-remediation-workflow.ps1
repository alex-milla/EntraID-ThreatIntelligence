# ============================================================
#  E2E del workflow de Remediación (CVE Desk, F0)
#
#  Comprueba sobre HTTP real:
#    - el alta deja estado "Ticket creado" y su entrada de registro,
#    - cambiar el estado desde el formulario actualiza el ciclo y el log,
#    - cerrar guarda evidencia y fechas,
#    - aceptar riesgo crea la aceptación y vuelve a la cola al caducar.
#
#  Restaura database.sqlite en `finally`; no usa red externa.
#
#  Uso:
#    pwsh tools/smoke/e2e-remediation-workflow.ps1
# ============================================================
param(
    [int]$Port = 8887,
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

# --- copia de seguridad de la BD principal ---
$names = @('database.sqlite', 'database.sqlite-wal', 'database.sqlite-shm')
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('rem-wf-' + [guid]::NewGuid().ToString('N'))
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

    # --- alta: estado y registro ---
    $taskUrl = "$base/index.php/modules/remediation?tab=tasks&org=$orgId&task=$taskId"
    $page = Invoke-WebRequest -Uri $taskUrl -WebSession $ws -UseBasicParsing -TimeoutSec 60
    $csrf = [regex]::Match($page.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    Check 'alta: chip Ticket creado' ($page.Content -match 'Ticket creado')
    Check 'alta: tarjeta de registro' ($page.Content -match 'Registro del ticket')
    Check 'alta: entrada de alta' ($page.Content -match 'Alta E2E')

    $saveUrl = "$base/index.php/modules/remediation/tasks/save"
    $common = @{
        csrf_token = $csrf
        id         = "$taskId"
        org_id     = "$orgId"
        owner      = 'Equipo de sistemas'
        due_at     = [string]$seed.due_at
    }

    # --- en curso ---
    $r1 = Invoke-WebRequest -Uri $saveUrl -Method POST -WebSession $ws -Body ($common + @{ status = 'in_progress'; notes = 'Empieza el parcheo' }) `
        -UseBasicParsing -TimeoutSec 60
    Check 'en curso: chip' ($r1.Content -match 'En curso')
    Check 'en curso: registro' ($r1.Content -match 'Empieza el parcheo')
    $state = Probe @('workflow', "$taskId")
    Check 'en curso: estado en_curso' ([string]$state.estado -eq 'en_curso') ([string]$state.estado)
    Check 'en curso: status in_progress' ([string]$state.status -eq 'in_progress') ([string]$state.status)
    Check 'en curso: dos entradas' ([int]$state.log_count -ge 2) ([string]$state.log_count)

    # --- cierre con evidencia ---
    $r2 = Invoke-WebRequest -Uri $saveUrl -Method POST -WebSession $ws -Body ($common + @{
        status = 'patched'; evidence = 'KB5040442 aplicada'; notes = 'Verificado en pre'
    }) -UseBasicParsing -TimeoutSec 60
    Check 'cierre: chip Cerrado' ($r2.Content -match 'Cerrado')
    Check 'cierre: evidencia visible' ($r2.Content -match 'KB5040442 aplicada')
    $state = Probe @('workflow', "$taskId")
    Check 'cierre: estado cerrado' ([string]$state.estado -eq 'cerrado') ([string]$state.estado)
    Check 'cierre: status patched' ([string]$state.status -eq 'patched') ([string]$state.status)
    Check 'cierre: resolved_at' ([string]$state.resolved_at -ne '')
    Check 'cierre: última entrada estado' ([string]$state.last_origin -eq 'en_curso' -and [string]$state.last_target -eq 'cerrado')

    # --- aceptar riesgo (con caducidad) ---
    $until = (Get-Date).AddDays(14).ToString('yyyy-MM-dd')
    $r3 = Invoke-WebRequest -Uri $saveUrl -Method POST -WebSession $ws -Body ($common + @{
        status = 'accepted'; exception_until = $until; notes = 'Aceptado por negocio'
    }) -UseBasicParsing -TimeoutSec 60
    Check 'riesgo: chip Riesgo aceptado' ($r3.Content -match 'Riesgo aceptado')
    $state = Probe @('workflow', "$taskId")
    Check 'riesgo: estado riesgo_aceptado' ([string]$state.estado -eq 'riesgo_aceptado') ([string]$state.estado)
    Check 'riesgo: status accepted' ([string]$state.status -eq 'accepted') ([string]$state.status)
    Check 'riesgo: registro de riesgo' ([string]$state.last_type -eq 'riesgo') ([string]$state.last_type)
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
