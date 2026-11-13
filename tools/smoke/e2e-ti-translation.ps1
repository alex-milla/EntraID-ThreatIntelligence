# ============================================================
#  E2E de la traducción por bloques de Threat Intelligence
#
#  Levanta la app y el llama-server falso, crea un artículo largo, traduce
#  bloque a bloque (plan -> chunk -> save) y comprueba:
#    - el troceado y el progreso,
#    - que la traducción queda guardada (chunks + traducción final),
#    - que la ficha, el listado y el badge «ES» la muestran,
#    - que el análisis de artículo recorta el contexto y avisa.
#
#  Restaura la BD en `finally`; no usa red externa.
#
#  Uso:
#    pwsh tools/smoke/e2e-ti-translation.ps1
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
$llmProbe = Join-Path $PSScriptRoot 'llm-probe.php'
$tiProbe  = Join-Path $PSScriptRoot 'ti-translation-probe.php'
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
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('ti-e2e-' + [guid]::NewGuid().ToString('N'))
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
$articleId = 0

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

    $tenants = Probe $tiProbe @('tenants')
    $tenantId = [int]($tenants.tenants[0].id ?? 0)
    $tenantCreated = 0
    if ($tenantId -le 0) {
        $newTenant = Probe $tiProbe @('seed-tenant')
        $tenantId = [int]$newTenant.tenant_id
        $tenantCreated = $tenantId
    }
    Check 'E2E: hay un tenant para la prueba' ($tenantId -gt 0) "tenant=$tenantId"

    # --- perfil con ventana pequeña y timeout corto (escenario local) ---
    $profile = Probe $llmProbe @('profile-create', 'custom', "$fakeBase/v1", $fakeModel, $fakeKey, '4096', '2048', '60')
    $profileId = [int]$profile.id
    Check 'E2E: perfil con ventana 2048' ($profileId -gt 0) "id=$profileId"

    # --- artículo largo con Markdown variado ---
    $seed = Probe $tiProbe @('seed-article', "$tenantId", '3000')
    $articleId = [int]$seed.article_id
    Check 'E2E: artículo sembrado' ($articleId -gt 0) "id=$articleId chars=$($seed.chars)"

    $planUrl  = "$base/index.php/modules/llm/translate-article-plan/$articleId"
    $chunkUrl = "$base/index.php/modules/llm/translate-article-chunk/$articleId"
    $saveUrl  = "$base/index.php/modules/llm/translate-article-save/$articleId"

    # --- plan ---
    $planRes = Invoke-WebRequest -Uri $planUrl -Method POST -WebSession $ws -Headers $headers `
        -ContentType 'application/json' -Body '{}' -UseBasicParsing -TimeoutSec 60
    $plan = $planRes.Content | ConvertFrom-Json
    Check 'E2E plan: success' ($plan.success -eq $true) ($plan.error)
    $totalChunks = @($plan.chunks).Count
    Check 'E2E plan: artículo troceado' ($totalChunks -ge 2) "bloques=$totalChunks"
    Check 'E2E plan: cada bloque acotado' ((@($plan.chunks) | Measure-Object -Property chars -Maximum).Maximum -le 1400)
    $codeSegments = @($plan.chunks | Where-Object { $_.type -eq 'codigo' })
    Check 'E2E plan: hay segmento de código' ($codeSegments.Count -ge 1) "codigo=$($codeSegments.Count)"
    $inlineCodeSegments = @($codeSegments | Where-Object { ([string]$_.text) -match 'DeviceProcessEvents' })
    Check 'E2E plan: detecta el código en línea (KQL)' ($inlineCodeSegments.Count -ge 1) 'sin KQL en línea'

    # --- traducir todos los bloques ---
    $okChunks = 0
    foreach ($ch in @($plan.chunks)) {
        $payload = @{ index = [int]$ch.index; text = [string]$ch.text; type = [string]$ch.type; profile_id = $profileId } | ConvertTo-Json -Compress
        $r = Invoke-WebRequest -Uri $chunkUrl -Method POST -WebSession $ws -Headers $headers `
            -ContentType 'application/json' -Body $payload -UseBasicParsing -TimeoutSec 90
        $cr = $r.Content | ConvertFrom-Json
        $content = [string]$cr.content
        if ($ch.type -eq 'codigo') {
            # El código se devuelve literal (byte a byte).
            if ($cr.success -and $content -eq [string]$ch.text) { $okChunks++ }
        } elseif ($cr.success -and ($content -match '\[ES\]')) {
            $okChunks++
        }
    }
    Check 'E2E chunks: todos traducidos' ($okChunks -eq $totalChunks) "$okChunks/$totalChunks"

    # --- guardar y comprobar persistencia ---
    $saveRes = Invoke-WebRequest -Uri $saveUrl -Method POST -WebSession $ws -Headers $headers `
        -ContentType 'application/json' -Body '{}' -UseBasicParsing -TimeoutSec 60
    $saved = $saveRes.Content | ConvertFrom-Json
    Check 'E2E save: success' ($saved.success -eq $true) ($saved.error)
    Check 'E2E save: sin bloques fallidos' ([int]$saved.failed_chunks -eq 0) "failed=$($saved.failed_chunks)"
    Check 'E2E save: contenido ensamblado' (([string]$saved.content) -match '\[ES\]')
    Check 'E2E save: el código se copia literal' (([string]$saved.content) -match 'Get-ChildItem C:\\Users') 'sin código'
    Check 'E2E save: el KQL en línea se copia literal' (([string]$saved.content) -match '\| where RemoteIP in \(AttackerInfra\)') 'sin KQL en línea'
    Check 'E2E save: líneas de código coinciden' ([int]$saved.code_lines_original -eq [int]$saved.code_lines_translation) "original=$($saved.code_lines_original) traduccion=$($saved.code_lines_translation)"
    Check 'E2E save: sin aviso de código' (-not ([string]$saved.notice -match 'código')) ([string]$saved.notice)
    Check 'E2E save: sin vallas crudas en el HTML' (-not (([string]$saved.content_html) -match '```'))
    Check 'E2E save: encabezados renderizados' (([string]$saved.content_html) -match '<h2')
    Check 'E2E save: bloque de código renderizado' (([string]$saved.content_html) -match 'language-powershell') 'sin bloque de código'

    # El segmento de código no debe haberse enviado al modelo.
    $fakeLog = Join-Path (& php -r 'echo sys_get_temp_dir();') 'entraid-fake-llm-openai.log'
    $logText = if (Test-Path $fakeLog) { Get-Content $fakeLog -Raw } else { '' }
    Check 'E2E: el código no se envió al modelo' (-not ($logText -match 'Get-ChildItem')) 'se envió al modelo'
    Check 'E2E: el KQL en línea no se envió al modelo' (-not ($logText -match 'RemoteIP in')) 'se envió al modelo'

    $state = Probe $tiProbe @('translation-state', "$articleId")
    Check 'E2E estado: traducción guardada' ($state.exists -eq $true)
    Check 'E2E estado: bloques guardados' ([int]$state.saved_chunks -eq $totalChunks) "saved=$($state.saved_chunks)/$totalChunks"
    Check 'E2E estado: modo chunks' ([string]$state.mode -eq 'chunks') ([string]$state.mode)
    Check 'E2E estado: contenido con marca' ($state.has_marker -eq $true)

    # --- ficha, listado y badge ---
    $articleUrl = "$base/index.php/modules/threat_intelligence/article/$articleId`?tenant=$tenantId"
    try {
        $page = Invoke-WebRequest -Uri $articleUrl -WebSession $ws -UseBasicParsing -TimeoutSec 30
        Check 'E2E ficha: 200' ([int]$page.StatusCode -eq 200) $articleUrl
        Check 'E2E ficha: muestra la traducción' ($page.Content -match '\[ES\]')
        Check 'E2E ficha: botón «Ver traducción»' ($page.Content -match 'Ver traducción')
    } catch {
        Check 'E2E ficha: responde' $false "$articleUrl -> $($_.Exception.Message)"
    }

    $listing = Invoke-WebRequest -Uri "$base/index.php/modules/threat_intelligence/translations?tenant=$tenantId" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    Check 'E2E listado: 200' ([int]$listing.StatusCode -eq 200)
    $listingData = Probe $tiProbe @('listing', "$tenantId")
    Check 'E2E listado: la consulta devuelve el artículo' ([int]$listingData.count -ge 1) "count=$($listingData.count)"
    Check 'E2E listado: aparece el enlace al artículo' ($listing.Content -match "article/$articleId") "articleId=$articleId"
    Check 'E2E listado: muestra el título' ($listing.Content -match 'E2E traducci')

    $articles = Invoke-WebRequest -Uri "$base/index.php/modules/threat_intelligence?tenant=$tenantId" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    Check 'E2E listado de noticias: badge ES' ($articles.Content -match 'Traducción al español guardada')

    # --- análisis de artículo con ventana 2048: recorte + aviso ---
    $analysisBody = @{ action_id = 0; question = ''; profile_id = $profileId; defang = 0 } | ConvertTo-Json -Compress
    $analysisRes = Invoke-WebRequest -Uri "$base/index.php/modules/llm/analyze-article/$articleId" -Method POST `
        -WebSession $ws -Headers $headers -ContentType 'application/json' -Body $analysisBody `
        -UseBasicParsing -TimeoutSec 90
    $analysis = $analysisRes.Content | ConvertFrom-Json
    Check 'E2E análisis: success' ($analysis.success -eq $true) ($analysis.error)
    Check 'E2E análisis: avisa del recorte' ([string]$analysis.notice -match 'recortado') ([string]$analysis.notice)
}
finally {
    if ($articleId -gt 0) { try { Probe $tiProbe @('article-delete', "$articleId") | Out-Null } catch { } }
    if ($profileId -gt 0) { try { Probe $llmProbe @('profile-delete', "$profileId") | Out-Null } catch { } }
    if ($null -ne $tenantCreated -and $tenantCreated -gt 0) { try { Probe $tiProbe @('tenant-delete', "$tenantCreated") | Out-Null } catch { } }
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
