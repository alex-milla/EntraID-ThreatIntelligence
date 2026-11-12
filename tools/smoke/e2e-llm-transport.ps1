# ============================================================
#  E2E del transporte LLM (API compatible OpenAI / Ollama)
#
#  Levanta la app y un llama-server falso (fake-llm-openai.php) que:
#    - exige "Authorization: Bearer" (401 sin ella),
#    - devuelve 404 "File Not Found" en /api/chat (como la Orin),
#    - sirve /v1/models y /v1/chat/completions en formato OpenAI.
#
#  Comprueba la auto-detección: un perfil "Ollama" con la Base URL raíz
#  debe caer a /v1/chat/completions y resolver el modelo desde /v1/models,
#  sin 404. También los errores traducidos, «Listar modelos», «Verificar
#  clave» y el reintento ante 503.
#
#  Restaura la BD en `finally`; no usa red externa.
#
#  Uso:
#    pwsh tools/smoke/e2e-llm-transport.ps1
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
$probe   = Join-Path $PSScriptRoot 'llm-probe.php'
$fake    = Join-Path $PSScriptRoot 'fake-llm-openai.php'
$base    = "http://127.0.0.1:$Port"
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
    param([string[]]$cmdArgs)
    $raw = & php -f $probe @cmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Probe falló: $($cmdArgs -join ' ')"
    }
    return ($raw | ConvertFrom-Json)
}

# --- rutas de estado del LLM falso ---
$tempDir  = (& php -r 'echo sys_get_temp_dir();')
$fakeLog  = Join-Path $tempDir 'entraid-fake-llm-openai.log'
$fakeFlag = Join-Path $tempDir 'entraid-fake-llm-openai-503.flag'
foreach ($p in @($fakeLog, $fakeFlag)) { if (Test-Path $p) { Remove-Item $p -Force } }

# --- copia de seguridad de la BD principal (perfiles de IA y actividad) ---
$names = @('database.sqlite', 'database.sqlite-wal', 'database.sqlite-shm')
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('llm-e2e-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
foreach ($name in $names) {
    $src = Join-Path $storage $name
    if (Test-Path $src) { Copy-Item $src (Join-Path $tmp $name) -Force }
}

# --- .env temporal: la clave del perfil se cifra, hace falta ENCRYPTION_KEY ---
$envPath    = Join-Path $docroot '.env'
$envExisted = Test-Path $envPath
$envBackup  = if ($envExisted) { Get-Content $envPath -Raw } else { $null }
$envKeyAdded = $false
if (-not $envExisted) {
    $enc = (& php -r 'echo base64_encode(random_bytes(32));').Trim()
    Set-Content -Path $envPath -Value ("ENCRYPTION_KEY=" + $enc + "`nLLM_503_RETRY_DELAY=0") -Encoding ascii -NoNewline
    $envKeyAdded = $true
} elseif ($envBackup -notmatch '(?m)^\s*ENCRYPTION_KEY\s*=') {
    $enc = (& php -r 'echo base64_encode(random_bytes(32));').Trim()
    Add-Content -Path $envPath -Value ("ENCRYPTION_KEY=" + $enc) -Encoding ascii
    $envKeyAdded = $true
}

$server = $null
$llmServer = $null
$profiles = @()

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

    # --- token CSRF de la sesión (compartido entre páginas) ---
    $apis = Invoke-WebRequest -Uri "$base/admin/apis" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    Check 'E2E: panel de APIs responde 200' ([int]$apis.StatusCode -eq 200)
    Check 'E2E: botón «Listar modelos» en el panel' ($apis.Content -match 'Listar modelos')
    $csrf = [regex]::Match($apis.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    if (-not $csrf) { throw 'No se pudo extraer el CSRF del panel de APIs' }
    $headers = @{ 'X-CSRF-Token' = $csrf }

    function Chat {
        param([int]$ProfileId, [string]$Prompt)
        $payload = @{ prompt = $Prompt; profile_id = $ProfileId } | ConvertTo-Json -Compress
        $res = Invoke-WebRequest -Uri "$base/index.php/modules/llm/chat" -Method POST -WebSession $ws `
            -Headers $headers -ContentType 'application/json' -Body $payload `
            -UseBasicParsing -TimeoutSec 150
        return ($res.Content | ConvertFrom-Json)
    }

    # ============================================================
    # 1 - Perfil "Ollama" con la raíz: fallback a OpenAI-compatible
    # ============================================================
    $p1 = Probe @('profile-create', 'ollama', $fakeBase, 'llama3.1', $fakeKey)
    $profiles += [int]$p1.id
    Check 'E2E: perfil Ollama creado con clave' ((Probe @('profile-state', "$($p1.id)")).has_key)

    $r1 = Chat -ProfileId ([int]$p1.id) -Prompt 'ping orin'
    Check 'E2E Ollama raíz: chat OK' ($r1.success -eq $true) ($r1.error)
    Check 'E2E Ollama raíz: contenido del modelo' ($r1.content -match 'E2E-ORIN-OK')
    Check 'E2E Ollama raíz: modelo resuelto por /v1/models' ($r1.model -eq $fakeModel) "model=$($r1.model)"

    $log = if (Test-Path $fakeLog) { Get-Content $fakeLog } else { @() }
    $paths = @($log | ForEach-Object { ($_ | ConvertFrom-Json).path })
    Check 'E2E Ollama raíz: probó /api/chat primero' ($paths -contains '/api/chat')
    Check 'E2E Ollama raíz: cayó a /v1/chat/completions' ($paths -contains '/v1/chat/completions')
    $chatReq = @($log | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.path -eq '/v1/chat/completions' }) | Select-Object -Last 1
    Check 'E2E Ollama raíz: stream=false explícito' ($chatReq.stream -eq $false)
    Check 'E2E Ollama raíz: envió Bearer' ($chatReq.auth -eq $true)

    # ============================================================
    # 2 - Perfil «Personalizado» con la raíz y sin modelo
    # ============================================================
    $p2 = Probe @('profile-create', 'custom', $fakeBase, '-', $fakeKey)
    $profiles += [int]$p2.id
    $r2 = Chat -ProfileId ([int]$p2.id) -Prompt 'ping custom'
    Check 'E2E custom raíz: chat OK' ($r2.success -eq $true) ($r2.error)
    Check 'E2E custom raíz: modelo resuelto' ($r2.model -eq $fakeModel) "model=$($r2.model)"

    # ============================================================
    # 3 - Perfil con /v1 y modelo explícito (sin adivinar rutas)
    # ============================================================
    $p3 = Probe @('profile-create', 'custom', "$fakeBase/v1", $fakeModel, $fakeKey)
    $profiles += [int]$p3.id
    $r3 = Chat -ProfileId ([int]$p3.id) -Prompt 'ping /v1'
    Check 'E2E custom /v1: chat OK' ($r3.success -eq $true) ($r3.error)
    Check 'E2E custom /v1: contenido' ($r3.content -match 'E2E-ORIN-OK')

    # ============================================================
    # 4 - Listar modelos y verificar clave
    # ============================================================
    $models = Invoke-WebRequest -Uri "$base/admin/apis/models" -Method POST -WebSession $ws `
        -Headers $headers -ContentType 'application/json' -Body (@{ id = "$($p1.id)" } | ConvertTo-Json -Compress) `
        -UseBasicParsing -TimeoutSec 60
    $m = $models.Content | ConvertFrom-Json
    Check 'E2E modelos: success' ($m.success -eq $true) ($m.error)
    Check 'E2E modelos: incluye el cargado' (@($m.models) -contains $fakeModel)
    Check 'E2E modelos: sugiere el primero' ($m.suggested -eq $fakeModel)

    $verify = Invoke-WebRequest -Uri "$base/admin/apis/verify" -Method POST -WebSession $ws `
        -Headers $headers -ContentType 'application/json' -Body (@{ id = "$($p1.id)" } | ConvertTo-Json -Compress) `
        -UseBasicParsing -TimeoutSec 60
    $v = $verify.Content | ConvertFrom-Json
    Check 'E2E verificar: success' ($v.success -eq $true) ($v.error)
    Check 'E2E verificar: detecta la API compatible' ($v.message -match 'compatible con OpenAI')

    # ============================================================
    # 5 - Errores traducidos
    # ============================================================
    $pBadKey = Probe @('profile-create', 'ollama', $fakeBase, $fakeModel, 'clave-incorrecta')
    $profiles += [int]$pBadKey.id
    $rBadKey = Chat -ProfileId ([int]$pBadKey.id) -Prompt 'ping'
    Check 'E2E 401: falla' ($rBadKey.success -eq $false)
    Check 'E2E 401: mensaje de API key' ($rBadKey.error -match 'API key')

    $pBadUrl = Probe @('profile-create', 'custom', "$fakeBase/nope", $fakeModel, $fakeKey)
    $profiles += [int]$pBadUrl.id
    $rBadUrl = Chat -ProfileId ([int]$pBadUrl.id) -Prompt 'ping'
    Check 'E2E 404: falla' ($rBadUrl.success -eq $false)
    Check 'E2E 404: mensaje de Base URL / ruta' ($rBadUrl.error -match 'Ruta inexistente \(404\)' -or $rBadUrl.error -match 'Base URL') ($rBadUrl.error)

    # ============================================================
    # 6 - Reintento ante 503 (modelo cargando)
    # ============================================================
    if (Test-Path $fakeFlag) { Remove-Item $fakeFlag -Force }
    $r503 = Chat -ProfileId ([int]$p1.id) -Prompt 'TRIGGER-503'
    Check 'E2E 503: reintento con éxito' ($r503.success -eq $true) ($r503.error)
    Check 'E2E 503: respuesta del segundo intento' ($r503.content -match 'E2E-RETRY-OK')

    # ============================================================
    # 7 - Ollama nativo intacto (el LLM falso de los otros E2E)
    # ============================================================
    $nativePort = $fakePort + 1
    $native = Start-Process -FilePath 'php' `
        -ArgumentList @('-S', "127.0.0.1:$nativePort", (Join-Path $PSScriptRoot 'fake-llm.php')) `
        -WorkingDirectory $PSScriptRoot -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 1200
    try {
        $pNative = Probe @('profile-create', 'ollama', "http://127.0.0.1:$nativePort", 'e2e-fake-model', '-')
        $profiles += [int]$pNative.id
        $rNative = Chat -ProfileId ([int]$pNative.id) -Prompt 'ping nativo'
        Check 'E2E nativo: /api/chat sigue funcionando' ($rNative.success -eq $true) ($rNative.error)
        Check 'E2E nativo: modelo nativo sin cambios' ($rNative.model -eq 'e2e-fake-model')
    }
    finally {
        if ($native -and -not $native.HasExited) { Stop-Process -Id $native.Id -Force }
    }
}
finally {
    foreach ($id in $profiles) { if ($id -gt 0) { try { Probe @('profile-delete', "$id") | Out-Null } catch { } } }
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
    foreach ($p in @($fakeLog, $fakeFlag)) { if (Test-Path $p) { try { Remove-Item $p -Force } catch { } } }
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
