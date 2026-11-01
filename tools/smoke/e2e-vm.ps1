# ============================================================
#  E2E del seguimiento de vulnerabilidades (v0.3.0)
#
#  Usa copias temporales de database.sqlite y cve.sqlite y las
#  restaura siempre en `finally`. No usa datos reales de clientes.
#
#  Uso:
#    pwsh tools/smoke/e2e-vm.ps1
# ============================================================
param(
    [int]$Port = 8897,
    [string]$User = 'admin',
    [string]$Pass = 'admin'
)

$ErrorActionPreference = 'Stop'
$root    = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$docroot = Join-Path $root 'public_html'
$storage = Join-Path $docroot 'storage'
$probe   = Join-Path $PSScriptRoot 'vm-probe.php'
$base    = "http://127.0.0.1:$Port"

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
    'cve.sqlite', 'cve.sqlite-wal', 'cve.sqlite-shm'
)
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('vm-e2e-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
foreach ($name in $names) {
    $src = Join-Path $storage $name
    if (Test-Path $src) { Copy-Item $src (Join-Path $tmp $name) -Force }
}

$server = $null
try {
    $server = Start-Process -FilePath 'php' `
        -ArgumentList @('-S', "127.0.0.1:$Port", '-t', $docroot, (Join-Path $PSScriptRoot 'router.php')) `
        -WorkingDirectory $docroot -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2

    # --- login ---
    $login = Invoke-WebRequest -Uri "$base/admin/login" -SessionVariable ws -UseBasicParsing -TimeoutSec 30
    $token = [regex]::Match($login.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    if (-not $token) { throw 'No se pudo extraer el token CSRF' }
    $post = Invoke-WebRequest -Uri "$base/admin/login" -Method POST -WebSession $ws `
        -Body @{ username = $User; password = $Pass; csrf_token = $token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    if ($post.Content -match 'name="password"') { throw 'Login fallido' }

    Start-Sleep -Milliseconds 300
    $token = [regex]::Match(
        (Invoke-WebRequest -Uri "$base/index.php/modules/cve?tab=vm" -WebSession $ws -UseBasicParsing -TimeoutSec 30).Content,
        'name="csrf_token"\s+value="([^"]+)"'
    ).Groups[1].Value

    # --- empresa de prueba ---
    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/groups/save" -Method POST -WebSession $ws `
        -Body @{ id = 0; name = 'E2E VM'; kind = 'company'; parent_id = 0; position = 0; csrf_token = $token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    $companyId = [int](Probe @('company', 'E2E VM')).id
    Check 'E2E: empresa creada' ($companyId -gt 0) "id=$companyId"

    # --- fixture CSV (datos sintéticos) ---
    $csvPath = Join-Path $tmp 'tvm-1.csv'
    @(
        'Vulnerabilities Export,30 Oct 2026 09:55 PM +00:00',
        'Name,Severity,CVSS v3,Epss score,Age (days),Published,First detected,Updated,Has Exploit,Has Known Threats,Has Associated Alerts,Related Software,Exposed Machines,Description,Status',
        'CVE-2026-96951,High,8.8,0.09813,25,"05 Oct, 2026","05 Oct, 2026","29 Oct, 2026",True,False,False,microsoft:edge_chromium-based,4848,"Command injection",RemediationRequired',
        'CVE-2026-21589,Critical,9.3,0.99477,25,"05 Oct, 2026","17 Oct, 2026","29 Oct, 2026",True,False,False,atlassian:jira,1,"Acceso a ficheros",RemediationRequired',
        'CVE-2026-00001,Low,3.1,0.00100,2,"29 Oct, 2026","29 Oct, 2026","29 Oct, 2026",False,False,False,nginx:nginx,0,"Otra vulnerabilidad",Fixed'
    ) | Set-Content -Path $csvPath -Encoding utf8

    $upload = Invoke-WebRequest -Uri "$base/index.php/modules/cve/import/tvm" -Method POST -WebSession $ws `
        -Form @{ company_id = $companyId; csrf_token = $token; csv = Get-Item $csvPath } `
        -UseBasicParsing -TimeoutSec 60 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $imports = (Probe @('imports', "$companyId")).imports
    Check 'E2E: importación registrada' ($imports.Count -eq 1) "n=$($imports.Count)"
    $importId = [int]$imports[0].id
    Check 'E2E: importación completada' ($imports[0].status -eq 'done') $imports[0].status
    Check 'E2E: 3 CVEs importados' ([int]$imports[0].rows_imported -eq 3) "$($imports[0].rows_imported)"

    # --- crear casos (botón manual, todos los CVE) ---
    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/vm/create" -Method POST -WebSession $ws `
        -Body @{ import_id = $importId; csrf_token = $token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $cases = (Probe @('cases', "$companyId")).cases
    Check 'E2E: 3 casos creados' ($cases.Count -eq 3) "n=$($cases.Count)"
    $criticalCase = $cases | Where-Object { $_.cve_id -eq 'CVE-2026-21589' }
    Check 'E2E: prioridad crítica por CVSS+EPSS' ($criticalCase.priority -eq 'critical') $criticalCase.priority
    Check 'E2E: estado inicial Detectada' (($cases | Where-Object { $_.status -ne 'detected' }).Count -eq 0)
    Check 'E2E: fecha objetivo guardada' (-not [string]::IsNullOrWhiteSpace([string]$criticalCase.due_date)) "$($criticalCase.due_date)"
    $criticalId = [int]$criticalCase.id
    $firstSeenImport = [int]$criticalCase.last_seen_import_id

    # --- idempotencia: repetir la creación ---
    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/vm/create" -Method POST -WebSession $ws `
        -Body @{ import_id = $importId; csrf_token = $token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $casesAgain = (Probe @('cases', "$companyId")).cases
    Check 'E2E: repetir creación no duplica' ($casesAgain.Count -eq 3) "n=$($casesAgain.Count)"

    # --- riesgo aceptado sin motivo: debe rechazarse ---
    $riskCase = $cases | Where-Object { $_.cve_id -eq 'CVE-2026-96951' }
    $riskResp = Invoke-WebRequest -Uri "$base/index.php/modules/cve/vm/update" -Method POST -WebSession $ws `
        -Body @{
            case_id = [int]$riskCase.id; status = 'risk_accepted'; priority = '';
            due_date = [string]$riskCase.due_date; assignee_name = ''; external_ticket = '';
            accepted_reason = ''; accepted_until = ''; comment = '';
            verification_comment = ''; verification_reference = ''; csrf_token = $token
        } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    $riskAfter = (Probe @('case', [string]$riskCase.id)).case
    Check 'E2E: riesgo aceptado exige motivo' ($riskResp.Content -match 'exige un motivo') 'sin mensaje de error'
    Check 'E2E: estado no cambia si falta motivo' ($riskAfter.status -eq 'detected') $riskAfter.status

    # --- cierre verificado con evidencia manual ---
    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/vm/update" -Method POST -WebSession $ws `
        -Body @{
            case_id = $criticalId; status = 'resolved_verified'; priority = '';
            due_date = [string]$criticalCase.due_date; assignee_name = 'Alex';
            external_ticket = 'INC-E2E-1'; accepted_reason = ''; accepted_until = '';
            comment = 'Cierre E2E'; verification_comment = 'Comprobado en el entorno de pruebas';
            verification_reference = 'E2E-REF-1'; csrf_token = $token
        } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $closed = Probe @('case', "$criticalId")
    Check 'E2E: cierre verificado' ($closed.case.status -eq 'resolved_verified') $closed.case.status
    Check 'E2E: verificación marcada como manual' ($closed.case.verification_kind -eq 'manual') $closed.case.verification_kind
    Check 'E2E: evidencia de verificación guardada' (($closed.evidence | Where-Object { $_.kind -eq 'verification' }).Count -eq 1)
    Check 'E2E: evento de cambio de estado' (($closed.events | Where-Object { $_.event_type -eq 'status' }).Count -ge 1)
    Check 'E2E: responsable guardado' ($closed.case.assignee_name -eq 'Alex') $closed.case.assignee_name

    # --- paneles inline (sin recargar) ---
    $casePanel = Invoke-WebRequest -Uri "$base/index.php/modules/cve/vm/$criticalId/panel" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    Check 'E2E panel: fragmento del caso' ($casePanel.StatusCode -eq 200 -and $casePanel.Content -match 'Guardar cambios') "status=$($casePanel.StatusCode)"
    $cvePanel = Invoke-WebRequest -Uri "$base/index.php/modules/cve/detail/CVE-2026-21589/panel" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    Check 'E2E panel: ficha del CVE' ($cvePanel.StatusCode -eq 200) "status=$($cvePanel.StatusCode)"
    $casePage = Invoke-WebRequest -Uri "$base/index.php/modules/cve?tab=vm&company=$companyId&case=$criticalId" -WebSession $ws -UseBasicParsing -TimeoutSec 30
    Check 'E2E panel: detalle embebido sin errores' ($casePage.StatusCode -eq 200 -and $casePage.Content -match 'Historial') "status=$($casePage.StatusCode)"

    # --- segunda importación SIN el CVE cerrado ---
    $csv2 = Join-Path $tmp 'tvm-2.csv'
    @(
        'Vulnerabilities Export,31 Oct 2026 09:55 PM +00:00',
        'Name,Severity,CVSS v3,Epss score,Age (days),Published,First detected,Updated,Has Exploit,Has Known Threats,Has Associated Alerts,Related Software,Exposed Machines,Description,Status',
        'CVE-2026-00001,Low,3.1,0.00100,3,"29 Oct, 2026","29 Oct, 2026","30 Oct, 2026",False,False,False,nginx:nginx,0,"Otra vulnerabilidad",Fixed'
    ) | Set-Content -Path $csv2 -Encoding utf8
    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/import/tvm" -Method POST -WebSession $ws `
        -Form @{ company_id = $companyId; csrf_token = $token; csv = Get-Item $csv2 } `
        -UseBasicParsing -TimeoutSec 60 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $imports2 = (Probe @('imports', "$companyId")).imports
    $importId2 = [int]$imports2[0].id
    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/vm/create" -Method POST -WebSession $ws `
        -Body @{ import_id = $importId2; csrf_token = $token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $closedAgain = (Probe @('case', "$criticalId")).case
    Check 'E2E: importación sin el CVE no cierra ni altera' ($closedAgain.status -eq 'resolved_verified') $closedAgain.status
    Check 'E2E: la observación del caso cerrado no cambia' ([int]$closedAgain.last_seen_import_id -eq $firstSeenImport) "$($closedAgain.last_seen_import_id)"

    # --- tercera importación CON el CVE cerrado ---
    $csv3 = Join-Path $tmp 'tvm-3.csv'
    @(
        'Vulnerabilities Export,01 Nov 2026 09:55 PM +00:00',
        'Name,Severity,CVSS v3,Epss score,Age (days),Published,First detected,Updated,Has Exploit,Has Known Threats,Has Associated Alerts,Related Software,Exposed Machines,Description,Status',
        'CVE-2026-21589,Critical,9.3,0.99477,40,"05 Oct, 2026","17 Oct, 2026","31 Oct, 2026",True,False,False,atlassian:jira,1,"Acceso a ficheros",RemediationRequired'
    ) | Set-Content -Path $csv3 -Encoding utf8
    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/import/tvm" -Method POST -WebSession $ws `
        -Form @{ company_id = $companyId; csrf_token = $token; csv = Get-Item $csv3 } `
        -UseBasicParsing -TimeoutSec 60 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $imports3 = (Probe @('imports', "$companyId")).imports
    $importId3 = [int]$imports3[0].id
    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/vm/create" -Method POST -WebSession $ws `
        -Body @{ import_id = $importId3; csrf_token = $token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $reappeared = Probe @('case', "$criticalId")
    Check 'E2E: reaparecer no reabre solo' ($reappeared.case.status -eq 'resolved_verified') $reappeared.case.status
    Check 'E2E: evento de reobservación' (($reappeared.events | Where-Object { $_.event_type -eq 'reobserved' }).Count -ge 1)
    $totalCases = (Probe @('cases', "$companyId")).cases.Count
    Check 'E2E: sin casos duplicados al final' ($totalCases -eq 3) "n=$totalCases"

    # --- casos desde CVEs asignados en Mis CVE (sin importar CSV) ---
    $seed = Probe @('seed-assignment', "$companyId", 'CVE-2030-4242', 'CVE-2026-00001')
    Check 'E2E Mis CVE: asignaciones de prueba sembradas' ($seed.seeded.Count -eq 2) "$($seed.seeded.Count)"

    $lowBefore = (Probe @('cases', "$companyId")).cases | Where-Object { $_.cve_id -eq 'CVE-2026-00001' }
    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/vm/create-from-group" -Method POST -WebSession $ws `
        -Body @{ company_id = $companyId; csrf_token = $token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $casesFromGroup = (Probe @('cases', "$companyId")).cases
    $catalogCase = $casesFromGroup | Where-Object { $_.cve_id -eq 'CVE-2030-4242' }
    Check 'E2E Mis CVE: caso creado desde el catálogo' ($null -ne $catalogCase) 'no existe'
    Check 'E2E Mis CVE: origen catalog' ($catalogCase.source -eq 'catalog') $catalogCase.source
    Check 'E2E Mis CVE: prioridad crítica del catálogo' ($catalogCase.priority -eq 'critical') $catalogCase.priority
    Check 'E2E Mis CVE: fecha objetivo guardada' (-not [string]::IsNullOrWhiteSpace([string]$catalogCase.due_date)) "$($catalogCase.due_date)"
    Check 'E2E Mis CVE: solo crea los que faltan' ($casesFromGroup.Count -eq 4) "n=$($casesFromGroup.Count)"

    $lowAfter = $casesFromGroup | Where-Object { $_.cve_id -eq 'CVE-2026-00001' }
    Check 'E2E Mis CVE: no altera un caso de TVM' (
        $lowAfter.status -eq $lowBefore.status -and
        $lowAfter.priority -eq $lowBefore.priority -and
        [int]$lowAfter.last_seen_import_id -eq [int]$lowBefore.last_seen_import_id
    ) "antes=$($lowBefore.status)/$($lowBefore.priority) ahora=$($lowAfter.status)/$($lowAfter.priority)"

    $null = Invoke-WebRequest -Uri "$base/index.php/modules/cve/vm/create-from-group" -Method POST -WebSession $ws `
        -Body @{ company_id = $companyId; csrf_token = $token } `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    Start-Sleep -Milliseconds 300
    $casesFinal = (Probe @('cases', "$companyId")).cases
    Check 'E2E Mis CVE: repetir no duplica' ($casesFinal.Count -eq 4) "n=$($casesFinal.Count)"
}
finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    Start-Sleep -Milliseconds 500
    foreach ($name in $names) {
        $dst = Join-Path $storage $name
        if (Test-Path $dst) { Remove-Item $dst -Force }
        $backup = Join-Path $tmp $name
        if (Test-Path $backup) { Copy-Item $backup $dst -Force }
    }
    if (Test-Path $tmp) {
        for ($i = 0; $i -lt 10 -and (Test-Path $tmp); $i++) {
            Start-Sleep -Milliseconds 300
            try {
                Remove-Item $tmp -Recurse -Force -ErrorAction Stop
            } catch {
                # El servidor o el indexador pueden tardar en soltar el CSV.
            }
        }
    }
}

Write-Host ''
if ($fail -gt 0) {
    Write-Host "RESULTADO: $fail comprobación(es) fallidas" -ForegroundColor Red
    exit 1
}
Write-Host 'RESULTADO: OK' -ForegroundColor Green
exit 0
