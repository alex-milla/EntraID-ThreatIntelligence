# ============================================================
#  E2E de Equipos expuestos (exposed_report)
#
#  Levanta la app y un LLM falso local (estilo Ollama), crea un perfil de
#  IA temporal, sube un CSV por multipart y comprueba el informe generado
#  en los dos modos. Restaura la BD en `finally`; no usa red externa.
#
#  Uso:
#    pwsh tools/smoke/e2e-exposed-report.ps1
# ============================================================
param(
    [int]$Port = 8897,
    [string]$User = 'admin',
    [string]$Pass = 'admin'
)

$ErrorActionPreference = 'Stop'
$root     = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$docroot  = Join-Path $root 'public_html'
$storage  = Join-Path $docroot 'storage'
$probe    = Join-Path $PSScriptRoot 'exposed-report-probe.php'
$fake     = Join-Path $PSScriptRoot 'fake-llm-report.php'
$base     = "http://127.0.0.1:$Port"
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

# --- CSV de prueba (el de la especificación, con BOM y CRLF) ---
$csvPath = Join-Path ([System.IO.Path]::GetTempPath()) ('exposed-e2e-' + [guid]::NewGuid().ToString('N') + '.csv')
$csvLines = @(
    'DeviceName,ExposureLevel,OSPlatform,PublicIP,KBsPendientes,PaquetesPendientes,CVEs,Criticos,ExploitsPublicos,CVEsConExploit,SinParchearDesde,PaqueteMasAntiguo,DiasSinParchear,TieneExploit'
    'srv01.contoso.com,High,WindowsServer2019,203.0.113.10,12,"[""October 2026 Security Updates"",""October 2026 Security Updates (Last updated at Nov 1, 2026)"",""November 2026 Security Updates""]",240,18,3,"[""CVE-2026-1111"",""CVE-2026-2222"",""CVE-2026-3333""]","Sep 8, 2026 10:00:00 PM","October 2026 Security Updates (Last updated at Nov 1, 2026)",64,1'
    'srv02.contoso.com,Medium,WindowsServer2022,203.0.113.11,2,"[""November 2026 Security Updates"",""""]",30,1,0,"[]","Nov 10, 2026 6:30:00 PM","November 2026 Security Updates",1,0'
)
Set-Content -Path $csvPath -Value ($csvLines -join "`r`n") -Encoding utf8BOM -NoNewline

$invalidPath = Join-Path ([System.IO.Path]::GetTempPath()) ('exposed-e2e-bad-' + [guid]::NewGuid().ToString('N') + '.csv')
Set-Content -Path $invalidPath -Value "DeviceName,ExposureLevel`r`nsrv,High" -Encoding utf8

# --- copia de seguridad de la BD principal (perfiles de IA y actividad) ---
$names = @('database.sqlite', 'database.sqlite-wal', 'database.sqlite-shm')
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('exposed-e2e-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
foreach ($name in $names) {
    $src = Join-Path $storage $name
    if (Test-Path $src) { Copy-Item $src (Join-Path $tmp $name) -Force }
}

$server = $null
$llmServer = $null
$profileId = 0
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

    # --- perfil de IA temporal apuntando al LLM falso ---
    $profile = Probe @('profile-create', $fakeBase)
    $profileId = [int]$profile.id
    Check 'E2E: perfil de IA temporal creado' ($profileId -gt 0) "id=$profileId"

    # --- pantalla del módulo ---
    $page = Invoke-WebRequest -Uri "$base/index.php/modules/exposed_report" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    Check 'E2E: módulo responde 200' ([int]$page.StatusCode -eq 200)
    Check 'E2E: muestra la consulta de origen' ($page.Content -match 'DeviceTvmSoftwareVulnerabilities')
    Check 'E2E: explica el contrato de columnas' ($page.Content -match 'DiasSinParchear')
    Check 'E2E: enlace a plantillas de prompts' ($page.Content -match 'Editar prompts')

    $csrf = [regex]::Match($page.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    if (-not $csrf) { throw 'No se pudo extraer el CSRF del módulo' }

    # --- modo compacto ---
    $compact = Invoke-WebRequest -Uri "$base/index.php/modules/exposed_report/generate" -Method POST `
        -WebSession $ws -Form @{
            csrf_token = $csrf
            mode       = 'compact'
            profile_id = $profileId
            csv        = Get-Item $csvPath
        } -UseBasicParsing -TimeoutSec 120
    Check 'E2E compacto: 200' ([int]$compact.StatusCode -eq 200)
    Check 'E2E compacto: informe visible' ($compact.Content -match 'Informe generado')
    Check 'E2E compacto: contenido del modelo' ($compact.Content -match 'Informe de parcheo \(prueba\)')
    Check 'E2E compacto: el modelo recibió el CSV' ($compact.Content -match 'CSV recibido: sí')
    Check 'E2E compacto: sin JSON de especificación' ($compact.Content -match 'Modo detectado: compacto')
    Check 'E2E compacto: sin KQL en el prompt' ($compact.Content -match 'KQL recibida: no')
    Check 'E2E compacto: tabla del modelo' ($compact.Content -match 'srv01\.contoso\.com')
    Check 'E2E compacto: botón de descarga' ($compact.Content -match 'Descargar \.md' -and $compact.Content -match 'informe-parcheo-')
    Check 'E2E compacto: KPIs deterministas' ($compact.Content -match 'Con exploit público' -and $compact.Content -match '64')
    Check 'E2E compacto: CSV con BOM aceptado' (-not ($compact.Content -match 'El CSV no se puede usar'))

    # --- modo detallado ---
    $detailed = Invoke-WebRequest -Uri "$base/index.php/modules/exposed_report/generate" -Method POST `
        -WebSession $ws -Form @{
            csrf_token = $csrf
            mode       = 'detailed'
            profile_id = $profileId
            csv        = Get-Item $csvPath
        } -UseBasicParsing -TimeoutSec 120
    Check 'E2E detallado: 200' ([int]$detailed.StatusCode -eq 200)
    Check 'E2E detallado: el modelo recibió el JSON' ($detailed.Content -match 'Modo detectado: detallado')
    Check 'E2E detallado: KQL incrustada en el JSON' ($detailed.Content -match 'KQL recibida: sí')
    Check 'E2E detallado: el informe apareció' ($detailed.Content -match 'Informe de parcheo \(prueba\)')

    # --- validación: CSV con columnas incorrectas ---
    $bad = Invoke-WebRequest -Uri "$base/index.php/modules/exposed_report/generate" -Method POST `
        -WebSession $ws -Form @{
            csrf_token = $csrf
            mode       = 'compact'
            profile_id = $profileId
            csv        = Get-Item $invalidPath
        } -UseBasicParsing -TimeoutSec 60
    Check 'E2E inválido: error de contrato' ($bad.Content -match 'El CSV no se puede usar')
    Check 'E2E inválido: no se generó informe' (-not ($bad.Content -match 'Informe generado'))

    # --- validación: sin fichero ---
    $noFile = Invoke-WebRequest -Uri "$base/index.php/modules/exposed_report/generate" -Method POST `
        -WebSession $ws -Form @{ csrf_token = $csrf; mode = 'compact'; profile_id = $profileId } `
        -UseBasicParsing -TimeoutSec 60
    Check 'E2E sin fichero: avisa' ($noFile.Content -match 'Selecciona el CSV')
}
finally {
    if ($profileId -gt 0) { try { Probe @('profile-delete', "$profileId") | Out-Null } catch { } }
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
    foreach ($path in @($csvPath, $invalidPath)) {
        for ($i = 0; $i -lt 8 -and (Test-Path $path); $i++) {
            try { Remove-Item $path -Force -ErrorAction Stop } catch { Start-Sleep -Milliseconds 200 }
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
