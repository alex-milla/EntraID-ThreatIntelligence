# ============================================================
#  E2E de informes, métricas y roles (CVE Desk, F3)
#
#  Comprueba sobre HTTP real:
#    - crear un borrador con las marcas "En informe",
#    - publicar y congelar la foto,
#    - que un publicado es inmutable,
#    - la pestaña de métricas de servicio,
#    - el aviso de riesgo próximo a caducar,
#    - la tarjeta de roles en Ajustes.
#
#  Crea un tenant sintético y restaura database.sqlite en `finally`.
#
#  Uso:
#    pwsh tools/smoke/e2e-remediation-reports.ps1
# ============================================================
param(
    [int]$Port = 8890,
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
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('rem-rep-' + [guid]::NewGuid().ToString('N'))
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

    $seed = Probe @('seed-queue')
    $orgId = [int]$seed.org_id
    $taskId = [int]$seed.task_id

    # --- marcar el CVE de la cola para el informe ---
    $queueUrl = "$base/index.php/modules/remediation?tab=queue&org=$orgId"
    $queue = Invoke-WebRequest -Uri $queueUrl -WebSession $ws -UseBasicParsing -TimeoutSec 60
    $csrf = [regex]::Match($queue.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    Invoke-WebRequest -Uri "$base/index.php/modules/remediation/queue/mark" -Method POST -WebSession $ws -Body @{
        csrf_token = $csrf; org_id = "$orgId"; cve_id = 'CVE-2026-98202'; mark = '1'; return_state = ''
    } -UseBasicParsing -TimeoutSec 60 | Out-Null

    # --- informes: borrador ---
    $reportsUrl = "$base/index.php/modules/remediation?tab=reports&org=$orgId"
    $reportsPage = Invoke-WebRequest -Uri $reportsUrl -WebSession $ws -UseBasicParsing -TimeoutSec 60
    Check 'informes: pestaña' ($reportsPage.Content -match 'Nuevo informe' -and $reportsPage.Content -match 'Informes')
    $reportsCsrf = [regex]::Match($reportsPage.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    $period = (Get-Date).ToString('yyyy-MM')
    $created = Invoke-WebRequest -Uri "$base/index.php/modules/remediation/reports/create" -Method POST -WebSession $ws `
        -Body @{ csrf_token = $reportsCsrf; org_id = "$orgId"; periodo = $period } `
        -UseBasicParsing -TimeoutSec 60
    Check 'informes: borrador creado' ($created.Content -match 'borrador creado' -or $created.Content -match 'Informe .* creado')
    Check 'informes: CVE marcado copiado' ($created.Content -match 'CVE-2026-98202')
    Check 'informes: acción publicar' ($created.Content -match 'Publicar informe')
    Check 'informes: estado borrador' ($created.Content -match 'Borrador')

    # --- publicar ---
    $reportId = [int]([regex]::Match($created.BaseResponse.RequestMessage.RequestUri.ToString(), 'report=(\d+)').Groups[1].Value)
    Check 'informes: id de informe' ($reportId -gt 0) "id=$reportId"
    $publishCsrf = [regex]::Match($created.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    $published = Invoke-WebRequest -Uri "$base/index.php/modules/remediation/reports/publish" -Method POST -WebSession $ws `
        -Body @{ csrf_token = $publishCsrf; org_id = "$orgId"; report_id = "$reportId" } `
        -UseBasicParsing -TimeoutSec 60
    Check 'publicar: aviso' ($published.Content -match 'Informe publicado')
    Check 'publicar: estado' ($published.Content -match 'Publicado')
    Check 'publicar: hoja con CVE' ($published.Content -match 'rem-report-sheet' -and $published.Content -match 'CVE-2026-98202')
    Check 'publicar: métricas en la foto' ($published.Content -match 'Servicio del periodo')
    Check 'publicar: sin acciones de borrador' (-not ($published.Content -match 'Publicar informe'))

    # --- inmutable ---
    $addCsrf = [regex]::Match($published.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    $immutable = Invoke-WebRequest -Uri "$base/index.php/modules/remediation/reports/items" -Method POST -WebSession $ws `
        -Body @{ csrf_token = $addCsrf; org_id = "$orgId"; report_id = "$reportId"; item_action = 'add'; cve_id = 'CVE-2026-98201' } `
        -UseBasicParsing -TimeoutSec 60
    Check 'publicado: inmutable' ($immutable.Content -match 'inmutable')

    # --- métricas de servicio ---
    $metricsUrl = "$base/index.php/modules/remediation?tab=metrics&org=$orgId&period=$period"
    $metrics = Invoke-WebRequest -Uri $metricsUrl -WebSession $ws -UseBasicParsing -TimeoutSec 60
    Check 'métricas: informe de servicio' ($metrics.Content -match 'Informe de servicio')
    Check 'métricas: cumplimiento SLA' ($metrics.Content -match 'Cumplimiento SLA')
    Check 'métricas: MTTR por severidad' ($metrics.Content -match 'MTTR por severidad')
    Check 'métricas: riesgos vigentes' ($metrics.Content -match 'Riesgos aceptados vigentes')

    # --- riesgo próximo a caducar ---
    $risk = Probe @('risk', "$taskId")
    Check 'riesgo: aceptado por probe' ($risk.ok -eq $true) ([string]$risk.error)
    $taskPage = Invoke-WebRequest -Uri "$base/index.php/modules/remediation?tab=tasks&org=$orgId&task=$taskId" -WebSession $ws -UseBasicParsing -TimeoutSec 60
    Check 'riesgo: aviso 7 días en la ficha' ($taskPage.Content -match 'Caduca en \d+ día')
    $dash = Invoke-WebRequest -Uri "$base/index.php/modules/remediation?tab=tasks&org=$orgId" -WebSession $ws -UseBasicParsing -TimeoutSec 60
    Check 'riesgo: contador por caducar' ($dash.Content -match 'Riesgos por caducar\s*<span[^>]*>1</span>')

    # --- roles en ajustes ---
    $settings = Invoke-WebRequest -Uri "$base/index.php/modules/remediation?tab=settings&org=$orgId" -WebSession $ws -UseBasicParsing -TimeoutSec 60
    Check 'roles: tarjeta' ($settings.Content -match 'Roles de remediación')
    Check 'roles: admin conserva permisos' ($settings.Content -match 'Administrador \(todos\)')
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
