# ============================================================
#  E2E de la cola y el SLA de Remediación (CVE Desk, F1)
#
#  Comprueba sobre HTTP real:
#    - la cola del tenant lista los CVE sin ticket y su SLA,
#    - "En informe" marca/desmarca y actualiza contadores,
#    - la bandeja muestra el SLA de la tarea,
#    - el editor de activos marca prod+crítico y refuerza el SLA.
#
#  Crea un tenant sintético y restaura database.sqlite en `finally`.
#
#  Uso:
#    pwsh tools/smoke/e2e-remediation-queue.ps1
# ============================================================
param(
    [int]$Port = 8888,
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
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('rem-q-' + [guid]::NewGuid().ToString('N'))
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
    $assetId = [int]$seed.asset_id

    # --- cola ---
    $queueUrl = "$base/index.php/modules/remediation?tab=queue&org=$orgId"
    $queue = Invoke-WebRequest -Uri $queueUrl -WebSession $ws -UseBasicParsing -TimeoutSec 60
    Check 'cola: CVE sin ticket' ($queue.Content -match 'CVE-2026-98202')
    Check 'cola: no lista el CVE con ticket' (-not ($queue.Content -match 'CVE-2026-98201'))
    Check 'cola: botón crear ticket' ($queue.Content -match 'Crear ticket')
    Check 'cola: SLA de 15 días' ($queue.Content -match 'día 1 de 15')
    Check 'contadores: nuevos' ($queue.Content -match 'Nuevos\s*<span[^>]*>1</span>')
    $csrf = [regex]::Match($queue.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value

    # --- marcar en informe ---
    $markUrl = "$base/index.php/modules/remediation/queue/mark"
    $marked = Invoke-WebRequest -Uri $markUrl -Method POST -WebSession $ws -Body @{
        csrf_token = $csrf; org_id = "$orgId"; cve_id = 'CVE-2026-98202'; mark = '1'; return_state = ''
    } -UseBasicParsing -TimeoutSec 60
    Check 'marcar: aviso' ($marked.Content -match 'añadido al informe')
    Check 'marcar: contador en informe' ($marked.Content -match 'En informe\s*<span[^>]*>1</span>')
    $queueMarked = Invoke-WebRequest -Uri "$queueUrl&queue=en_informe" -WebSession $ws -UseBasicParsing -TimeoutSec 60
    Check 'marcar: filtro en informe' ($queueMarked.Content -match 'CVE-2026-98202')

    $unmarked = Invoke-WebRequest -Uri $markUrl -Method POST -WebSession $ws -Body @{
        csrf_token = $csrf; org_id = "$orgId"; cve_id = 'CVE-2026-98202'; mark = '0'; return_state = ''
    } -UseBasicParsing -TimeoutSec 60
    Check 'desmarcar: aviso' ($unmarked.Content -match 'devuelto a la cola')

    # --- bandeja: SLA de la tarea ---
    $taskUrl = "$base/index.php/modules/remediation?tab=tasks&org=$orgId&task=$taskId"
    $taskPage = Invoke-WebRequest -Uri $taskUrl -WebSession $ws -UseBasicParsing -TimeoutSec 60
    Check 'tarea: tarjeta SLA' ($taskPage.Content -match 'SLA ·')
    Check 'tarea: en riesgo por 6/7' ($taskPage.Content -match 'En riesgo' -and $taskPage.Content -match 'día 7 de 7')
    Check 'activos: editor visible' ($taskPage.Content -match 'Guardar activos' -and $taskPage.Content -match 'WEB-01')

    # --- activo prod crítico → SLA reforzado ---
    $taskCsrf = [regex]::Match($taskPage.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    $assetsUrl = "$base/index.php/modules/remediation/tasks/assets"
    $body = @{
        csrf_token = $taskCsrf
        org_id     = "$orgId"
        task_id    = "$taskId"
    }
    $body["assets[$assetId][environment]"] = 'prod'
    $body["assets[$assetId][criticality]"] = 'alta'
    $body["assets[$assetId][owner]"] = 'Equipo de sistemas'
    $saved = Invoke-WebRequest -Uri $assetsUrl -Method POST -WebSession $ws -Body $body -UseBasicParsing -TimeoutSec 60
    Check 'activos: guardado' ($saved.Content -match 'Activos actualizados')
    Check 'SLA: activo prod crítico' ($saved.Content -match 'activo en producción crítico')
    Check 'SLA: vencido con plazo reforzado' ($saved.Content -match 'SLA vencido' -and $saved.Content -match '3 días de plazo \(reforzado\)')

    $dashboard = Invoke-WebRequest -Uri "$base/index.php/modules/remediation?tab=tasks&org=$orgId" -WebSession $ws -UseBasicParsing -TimeoutSec 60
    Check 'contadores: SLA vencido' ($dashboard.Content -match 'SLA vencido\s*<span[^>]*>1</span>')
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
