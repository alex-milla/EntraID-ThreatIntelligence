# ============================================================
#  E2E del asistente de remediación
#
#  Levanta la app y el llama-server falso y comprueba:
#    - "Proponer datos" devuelve KB/versión/verificación/rollback en JSON,
#    - "Guardar en la tarea" escribe solo lo confirmado,
#    - el contexto avisa de los datos que no constan,
#    - un 502 con página HTML del proxy se traduce (no se muestra el HTML).
#
#  Restaura la BD en `finally`; no usa red externa.
#
#  Uso:
#    pwsh tools/smoke/e2e-remediation-assistant.ps1
# ============================================================
param(
    [int]$Port = 8886,
    [string]$User = 'admin',
    [string]$Pass = 'admin'
)

$ErrorActionPreference = 'Stop'
$root    = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$docroot = Join-Path $root 'public_html'
$storage = Join-Path $docroot 'storage'
$llmProbe = Join-Path $PSScriptRoot 'llm-probe.php'
$remProbe = Join-Path $PSScriptRoot 'remediation-probe.php'
$fake     = Join-Path $PSScriptRoot 'fake-llm-openai.php'
$base     = "http://127.0.0.1:$Port"
$fakePort = $Port + 1
$fakeBase = "http://127.0.0.1:$fakePort"
$fakeKey  = 'e2e-orin-key'
$fakeModel = 'e2e-orin-model.gguf'

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
    param([string]$script, [string[]]$cmdArgs)
    $raw = & php -f $script @cmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Probe falló: $script $($cmdArgs -join ' ')"
    }
    return ($raw | ConvertFrom-Json)
}

# --- copia de seguridad de la BD principal ---
$names = @('database.sqlite', 'database.sqlite-wal', 'database.sqlite-shm')
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('rem-e2e-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
foreach ($name in $names) {
    $src = Join-Path $storage $name
    if (Test-Path $src) { Copy-Item $src (Join-Path $tmp $name) -Force }
}

# --- .env temporal: la clave del perfil se cifra ---
$envPath    = Join-Path $docroot '.env'
$envExisted = Test-Path $envPath
$envBackup  = if ($envExisted) { Get-Content $envPath -Raw } else { $null }
$envKeyAdded = $false
if (-not $envExisted) {
    $enc = (& php -r 'echo base64_encode(random_bytes(32));').Trim()
    Set-Content -Path $envPath -Value ("ENCRYPTION_KEY=" + $enc) -Encoding ascii -NoNewline
    $envKeyAdded = $true
} elseif ($envBackup -notmatch '(?m)^\s*ENCRYPTION_KEY\s*=') {
    $enc = (& php -r 'echo base64_encode(random_bytes(32));').Trim()
    Add-Content -Path $envPath -Value ("ENCRYPTION_KEY=" + $enc) -Encoding ascii
    $envKeyAdded = $true
}

$server = $null
$llmServer = $null
$profileId = 0
$orgId = 0
$taskId = 0

try {
    $llmServer = Start-Process -FilePath 'php' `
        -ArgumentList @('-S', "127.0.0.1:$fakePort", $fake) `
        -WorkingDirectory $PSScriptRoot -PassThru -WindowStyle Hidden
    $server = Start-Process -FilePath 'php' `
        -ArgumentList @('-S', "127.0.0.1:$Port", '-t', $docroot, (Join-Path $PSScriptRoot 'router.php')) `
        -WorkingDirectory $docroot -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2

    # --- login ---
    $login = Invoke-WebRequest -Uri "$base/admin/login" -SessionVariable ws -UseBasicParsing -TimeoutSec 30
    $token = [regex]::Match($login.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    if (-not $token) { throw 'No se pudo extraer el token CSRF del login' }
    $post = Invoke-WebRequest -Uri "$base/admin/login" -Method POST -WebSession $ws `
        -Body @{ username = $User; password = $Pass; csrf_token = $token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    if ($post.Content -match 'name="password"') { throw 'Login fallido' }

    $apis = Invoke-WebRequest -Uri "$base/admin/apis" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    $csrf = [regex]::Match($apis.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    if (-not $csrf) { throw 'No se pudo extraer el CSRF del panel de APIs' }
    $headers = @{ 'X-CSRF-Token' = $csrf }

    # --- perfil + organización/tarea temporales ---
    $profile = Probe $llmProbe @('profile-create', 'custom', "$fakeBase/v1", $fakeModel, $fakeKey, '4096', '8192', '60')
    $profileId = [int]$profile.id
    $seed = Probe $remProbe @('seed')
    $orgId = [int]$seed.org_id
    $taskId = [int]$seed.task_id
    Check 'E2E: organización y tarea creadas' ($orgId -gt 0 -and $taskId -gt 0) "org=$orgId task=$taskId"

    $suggestUrl = "$base/index.php/modules/remediation/tasks/suggest"
    $applyUrl   = "$base/index.php/modules/remediation/tasks/apply"
    $askUrl     = "$base/index.php/modules/remediation/ask"

    # --- proponer datos ---
    $payload = @{ org_id = $orgId; task_id = $taskId; profile_id = $profileId } | ConvertTo-Json -Compress
    $r = Invoke-WebRequest -Uri $suggestUrl -Method POST -WebSession $ws -Headers $headers `
        -ContentType 'application/json' -Body $payload -UseBasicParsing -TimeoutSec 90
    $sug = $r.Content | ConvertFrom-Json
    Check 'E2E suggest: success' ($sug.success -eq $true) ($sug.error)
    Check 'E2E suggest: KB propuesta' ([string]$sug.fields.patch_kb -eq 'KB5040442') ([string]$sug.fields.patch_kb)
    Check 'E2E suggest: versión propuesta' ([string]$sug.fields.fixed_version -eq '11.0.1') ([string]$sug.fields.fixed_version)
    Check 'E2E suggest: verificación y rollback' (([string]$sug.fields.verification) -ne '' -and ([string]$sug.fields.rollback) -ne '')
    Check 'E2E suggest: dice lo que no consta' (@($sug.fields.missing) -contains 'productos afectados') (@($sug.fields.missing) -join ',')

    # --- guardar en la tarea (lo confirmado) ---
    $applyPayload = @{
        org_id = $orgId; task_id = $taskId;
        patch_kb = 'KB5040442'; fixed_version = '11.0.1';
        notes = "Verificación: build 11.0.1`nRollback: desinstalar KB5040442"
    } | ConvertTo-Json -Compress
    $ra = Invoke-WebRequest -Uri $applyUrl -Method POST -WebSession $ws -Headers $headers `
        -ContentType 'application/json' -Body $applyPayload -UseBasicParsing -TimeoutSec 60
    $applied = $ra.Content | ConvertFrom-Json
    Check 'E2E apply: success' ($applied.success -eq $true) ($applied.error)

    $state = Probe $remProbe @('task', "$taskId")
    Check 'E2E apply: KB guardada' ([string]$state.patch_kb -eq 'KB5040442') ([string]$state.patch_kb)
    Check 'E2E apply: versión guardada' ([string]$state.fixed_version -eq '11.0.1') ([string]$state.fixed_version)
    Check 'E2E apply: notas guardadas' (([string]$state.notes) -match 'Rollback')

    # --- 502 del proxy: mensaje legible, sin HTML ---
    $askPayload = @{ org_id = $orgId; task_id = $taskId; question = 'TRIGGER-502'; profile_id = $profileId } | ConvertTo-Json -Compress
    try {
        $null = Invoke-WebRequest -Uri $askUrl -Method POST -WebSession $ws -Headers $headers `
            -ContentType 'application/json' -Body $askPayload -UseBasicParsing -TimeoutSec 90
        Check 'E2E 502: responde con error' $false 'devolvió 200'
    } catch {
        $body = ''
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $body = [string]$_.ErrorDetails.Message
        } elseif ($_.Exception.Response) {
            try { $body = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult() } catch { }
        }
        if ($body -eq '') { throw }
        $ask = $body | ConvertFrom-Json
        Check 'E2E 502: mensaje traducido' ([string]$ask.error -match '502 Bad Gateway') ([string]$ask.error)
        Check 'E2E 502: no se muestra HTML' (-not ([string]$ask.error -match '<html')) ([string]$ask.error)
    }
}
finally {
    if ($orgId -gt 0) { try { Probe $remProbe @('cleanup', "$orgId") | Out-Null } catch { } }
    if ($profileId -gt 0) { try { Probe $llmProbe @('profile-delete', "$profileId") | Out-Null } catch { } }
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    if ($llmServer -and -not $llmServer.HasExited) { Stop-Process -Id $llmServer.Id -Force }
    Start-Sleep -Milliseconds 500
    foreach ($name in $names) {
        $dst = Join-Path $storage $name
        $backup = Join-Path $tmp $name
        if (-not (Test-Path $backup)) { continue }
        for ($i = 0; $i -lt 12; $i++) {
            try {
                if (Test-Path $dst) { Remove-Item $dst -Force -ErrorAction Stop }
                Copy-Item $backup $dst -Force -ErrorAction Stop
                break
            } catch {
                Start-Sleep -Milliseconds 500
            }
        }
    }
    if ($envKeyAdded) {
        if ($envExisted) { [System.IO.File]::WriteAllText($envPath, [string]$envBackup) }
        elseif (Test-Path $envPath) { Remove-Item $envPath -Force }
    }
    if (Test-Path $tmp) {
        for ($i = 0; $i -lt 10 -and (Test-Path $tmp); $i++) {
            Start-Sleep -Milliseconds 300
            try { Remove-Item $tmp -Recurse -Force -ErrorAction Stop } catch { }
        }
    }
}

Write-Host ''
if ($fail -gt 0) {
    Write-Host "RESULTADO: $fail comprobación(es) fallidas de $total" -ForegroundColor Red
    exit 1
}
Write-Host "RESULTADO: OK ($total comprobaciones)" -ForegroundColor Green
