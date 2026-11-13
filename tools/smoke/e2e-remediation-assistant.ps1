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

    # --- consulta en segundo plano: encolar y resolver con el worker ---
    function WaitChatStatus {
        param([int]$ChatId, [string]$Want, [int]$Seconds = 25)
        $deadline = (Get-Date).AddSeconds($Seconds)
        $last = $null
        while ((Get-Date) -lt $deadline) {
            $st = Probe $remProbe @('chat-token', "$ChatId")
            $last = $st
            if ([string]$st.status -eq $Want) { return $st }
            Start-Sleep -Milliseconds 700
        }
        return $last
    }

    $askPayload = @{ org_id = $orgId; task_id = $taskId; question = 'Plan de implementación paso a paso'; profile_id = $profileId } | ConvertTo-Json -Compress
    $askRes = Invoke-WebRequest -Uri $askUrl -Method POST -WebSession $ws -Headers $headers `
        -ContentType 'application/json' -Body $askPayload -UseBasicParsing -TimeoutSec 60
    $ask = $askRes.Content | ConvertFrom-Json
    Check 'E2E ask: responde encolado' ($ask.success -eq $true -and $ask.pending -eq $true) ($ask.error)
    $chatId = [int]$ask.chat_id
    Check 'E2E ask: devuelve chat_id' ($chatId -gt 0) "chat=$chatId"

    $tok = Probe $remProbe @('chat-token', "$chatId")
    # El worker puede haber terminado ya (es rápido): se acepta pending/running/done.
    Check 'E2E ask: estado inicial coherente' (@('pending', 'running', 'done') -contains [string]$tok.status) "status=$($tok.status)"

    # El worker lo debe lanzar la propia aplicación (background_request).
    # NO se llama a mano: así se detecta un fallo de URL o de permisos.
    $done = WaitChatStatus -ChatId $chatId -Want 'done' -Seconds 40
    Check 'E2E ask: termina en done (worker automático)' ([string]$done.status -eq 'done') "status=$($done.status) error=$($done.error)"

    $logText = ''
    if (Test-Path (Join-Path $storage 'app.log')) {
        $logText = Get-Content (Join-Path $storage 'app.log') -Raw
    }
    Check 'E2E ask: URL del worker es la del fichero raíz' ($logText -match '"worker":"[^"]*/remediation-worker\.php"') 'sin URL correcta en app.log'
    Check 'E2E ask: la URL no pasa por index.php' (-not ($logText -match '"worker":"[^"]*/index\.php/remediation-worker\.php"'))

    $msgs = Probe $remProbe @('chat-messages', "$chatId")
    $assistant = @($msgs.messages | Where-Object { $_.role -eq 'assistant' })
    Check 'E2E ask: guarda la respuesta del asistente' ($assistant.Count -ge 1) "mensajes=$($assistant.Count)"
    Check 'E2E ask: contenido del modelo' ($assistant.Count -ge 1 -and ([string]$assistant[-1].content) -match 'E2E-ORIN-OK')

    # --- 502 del proxy en segundo plano: mensaje legible, sin HTML ---
    $ask502 = @{ org_id = $orgId; task_id = $taskId; question = 'TRIGGER-502'; profile_id = $profileId } | ConvertTo-Json -Compress
    $r502 = Invoke-WebRequest -Uri $askUrl -Method POST -WebSession $ws -Headers $headers `
        -ContentType 'application/json' -Body $ask502 -UseBasicParsing -TimeoutSec 60
    $a502 = $r502.Content | ConvertFrom-Json
    Check 'E2E 502: encola' ($a502.success -eq $true -and $a502.pending -eq $true) ($a502.error)
    $chat502 = [int]$a502.chat_id
    $err502 = WaitChatStatus -ChatId $chat502 -Want 'error' -Seconds 40
    Check 'E2E 502: estado error' ([string]$err502.status -eq 'error') "status=$($err502.status)"
    Check 'E2E 502: mensaje traducido' ([string]$err502.error -match '502 Bad Gateway') ([string]$err502.error)
    Check 'E2E 502: no se muestra HTML' (-not ([string]$err502.error -match '<html')) ([string]$err502.error)

    # --- consultas colgadas: mensaje distinto según el estado ---
    $stuckPending = Probe $remProbe @('seed-chat', "$orgId", "$taskId", 'pending')
    $pagePending = Invoke-WebRequest -Uri "$base/index.php/modules/remediation?tab=assistant&org=$orgId&chat=$($stuckPending.chat_id)" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    Check 'E2E colgado: pending avisa del lanzamiento' ($pagePending.Content -match 'no pudo lanzar el trabajo en segundo plano') 'sin aviso de lanzamiento'

    $stuckRunning = Probe $remProbe @('seed-chat', "$orgId", "$taskId", 'running')
    $pageRunning = Invoke-WebRequest -Uri "$base/index.php/modules/remediation?tab=assistant&org=$orgId&chat=$($stuckRunning.chat_id)" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    Check 'E2E colgado: running avisa del modelo' ($pageRunning.Content -match 'El modelo no respondió a tiempo') 'sin aviso del modelo'
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
