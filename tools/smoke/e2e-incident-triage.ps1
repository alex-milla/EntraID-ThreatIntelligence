# ============================================================
#  E2E del triaje IA de Incidentes Story (v0.3.20)
#
#  Levanta la app y un LLM falso local (OpenAI-compatible), crea un
#  perfil de IA temporal, ingesta un story, ejecuta el triaje y
#  comprueba que el resultado aparece en la ficha. Restaura las BD
#  en `finally`; no usa datos reales ni red externa.
#
#  Uso:
#    pwsh tools/smoke/e2e-incident-triage.ps1
# ============================================================
param(
    [int]$Port = 8896,
    [string]$User = 'admin',
    [string]$Pass = 'admin'
)

$ErrorActionPreference = 'Stop'
$root    = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$docroot = Join-Path $root 'public_html'
$storage = Join-Path $docroot 'storage'
$probe   = Join-Path $PSScriptRoot 'incident-story-probe.php'
$fake    = Join-Path $PSScriptRoot 'fake-llm.php'
$base    = "http://127.0.0.1:$Port"
$fakePort = $Port + 1
$fakeBase = "http://127.0.0.1:$fakePort"

$fail = 0
function Check {
    param([string]$label, [bool]$ok, [string]$detail = '')
    if ($ok) {
        Write-Host "OK   $label" -ForegroundColor Green
        return
    }
    $script:fail++
    Write-Host "FALLO $label" -NoNewline -ForegroundColor Red
    if ($detail -ne '') { Write-Host " — $detail" } else { Write-Host '' }
}

function Probe {
    param([string[]]$cmdArgs)
    $raw = & php -f $probe @cmdArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Probe falló: $($cmdArgs -join ' ')"
    }
    return ($raw | ConvertFrom-Json)
}

$names = @(
    'database.sqlite', 'database.sqlite-wal', 'database.sqlite-shm',
    'incident_story.sqlite', 'incident_story.sqlite-wal', 'incident_story.sqlite-shm'
)
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('incident-e2e-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
foreach ($name in $names) {
    $src = Join-Path $storage $name
    if (Test-Path $src) { Copy-Item $src (Join-Path $tmp $name) -Force }
}

$server = $null
$llmServer = $null
try {
    # --- LLM falso (OpenAI-compatible) ---
    $llmServer = Start-Process -FilePath 'php' `
        -ArgumentList @('-S', "127.0.0.1:$fakePort", $fake) `
        -WorkingDirectory $PSScriptRoot -PassThru -WindowStyle Hidden
    # --- app ---
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

    # --- perfil de IA temporal apuntando al LLM falso ---
    $profile = Probe @('profile-create', $fakeBase)
    $profileId = [int]$profile.id
    Check 'E2E: perfil de IA temporal creado' ($profileId -gt 0) "id=$profileId"

    # --- ingesta de un story ---
    $new = Invoke-WebRequest -Uri "$base/index.php/modules/incident_story/new" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    $csrf = [regex]::Match($new.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    $story = @'
10/30/2026 8:10:38 AM
 [41544] powershell.exe -NoProfile -Command "Get-ChildItem"
Command line powershell.exe -NoProfile -Command "Get-ChildItem"
Process id 41544
Execution details Token elevation: Limited, Integrity level: Medium
Image file path C:\Users\pinedarp\AppData\Local\Programs\Git\cmd\git.exe
Image file SHA1 a4f874f663d4b2e682bbae87fd121865a42dddbb
User DIBA\pinedarp
Sensitive information lookup New Detected Medium
 powershell.exe executed a script
Content Write-Host "hola"
'@
    $ingest = Invoke-WebRequest -Uri "$base/index.php/modules/incident_story/ingest" -Method POST -WebSession $ws `
        -Body @{ mode = 'text'; story_text = $story; client_domains = 'diba.es'; csrf_token = $csrf } `
        -UseBasicParsing -TimeoutSec 60 -MaximumRedirection 5
    $caseUrl = $ingest.BaseResponse.RequestMessage.RequestUri.AbsoluteUri
    $caseId = [regex]::Match($caseUrl, '/case/(\d+)').Groups[1].Value
    Check 'E2E: caso creado' ([int]$caseId -gt 0) $caseUrl
    Check 'E2E: vista pseudonimizada por defecto' ($ingest.Content -match 'Usu001' -and -not ($ingest.Content -match 'pinedarp'))

    # --- triaje IA contra el LLM falso ---
    $casePage = Invoke-WebRequest -Uri "$base/index.php/modules/incident_story/case/$caseId" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    $csrf2 = [regex]::Match($casePage.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    $triage = Invoke-WebRequest -Uri "$base/index.php/modules/incident_story/case/$caseId/triage" -Method POST -WebSession $ws `
        -Body @{ profile_id = $profileId; csrf_token = $csrf2 } `
        -UseBasicParsing -TimeoutSec 120 -MaximumRedirection 5
    $triageUrl = $triage.BaseResponse.RequestMessage.RequestUri.AbsoluteUri
    Check 'E2E: redirect del triaje' ($triageUrl -match 'triage_ok=1') $triageUrl
    Check 'E2E: aviso de triaje completado' ($triage.Content -match 'Triaje IA completado')
    Check 'E2E: veredicto visible en la ficha' ($triage.Content -match 'Sospechosa' -or $triage.Content -match 'sospechosa')
    Check 'E2E: análisis completo plegado disponible' ($triage.Content -match 'Ver análisis completo')
    Check 'E2E: resumen ejecutivo del modelo' ($triage.Content -match 'PowerShell ejecutó un script de descubrimiento')
    Check 'E2E: secciones contraídas' ($triage.Content -match '<details class="card' -and $triage.Content -match 'Resumen del story \(sin IA\)')

    # --- persistencia en BD ---
    $state = Probe @('state')
    Check 'E2E: veredicto persistido' ($state.verdict -eq 'sospechosa') "$($state.verdict)"
    Check 'E2E: triaje no vacío' ([int]$state.triage_length -gt 100) "len=$($state.triage_length)"
    Check 'E2E: campos del triaje' (($state.triage_keys -contains 'resumen_ejecutivo') -and ($state.triage_keys -contains 'confianza_pct'))

    # --- limpieza funcional del caso ---
    $csrf3 = [regex]::Match($triage.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    $deleted = Invoke-WebRequest -Uri "$base/index.php/modules/incident_story/case/$caseId/delete" -Method POST -WebSession $ws `
        -Body @{ csrf_token = $csrf3 } -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    Check 'E2E: caso eliminado' ($deleted.Content -match 'Caso eliminado')
}
finally {
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
    if (Test-Path $tmp) {
        for ($i = 0; $i -lt 10 -and (Test-Path $tmp); $i++) {
            Start-Sleep -Milliseconds 300
            try { Remove-Item $tmp -Recurse -Force -ErrorAction Stop } catch { }
        }
    }
}

Write-Host ''
if ($fail -gt 0) {
    Write-Host "RESULTADO: $fail comprobación(es) fallidas" -ForegroundColor Red
    exit 1
}
Write-Host 'RESULTADO: OK' -ForegroundColor Green
