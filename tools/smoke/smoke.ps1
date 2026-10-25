# ============================================================
#  Smoke test local — EntraID Threat Intelligence
#  Arranca `php -S` con el router de desarrollo, inicia sesión y
#  recorre admin + todos los módulos comprobando:
#    - que no hay 500 ni "Fatal error"/Warning/Parse error en el HTML
#    - que los assets referenciados (css/js/woff2) devuelven 200
#    - opcional (-CheckCss): que toda clase usada en el HTML existe en tw.css
#
#  Uso:
#    pwsh tools/smoke/smoke.ps1
#    pwsh tools/smoke/smoke.ps1 -CheckCss
# ============================================================
param(
    [int]$Port = 8899,
    [string]$User = 'admin',
    [string]$Pass = 'admin',
    [switch]$CheckCss
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$docroot = Join-Path $root 'public_html'
$base = "http://127.0.0.1:$Port"

$routes = @(
    '/admin/login',
    '/admin',
    '/admin/tenants',
    '/admin/users',
    '/admin/modules',
    '/admin/prompts',
    '/admin/settings',
    '/admin/logs',
    '/admin/apis',
    '/admin/storage',
    '/admin/security',
    '/admin/updates',
    '/admin/change-password',
    '/admin/tenant/edit',
    '/index.php/modules/entra_users',
    '/index.php/modules/export',
    '/index.php/modules/hunting',
    '/index.php/modules/incidents',
    '/index.php/modules/llm',
    '/index.php/modules/reports',
    '/index.php/modules/secure_score',
    '/index.php/modules/threat_intelligence',
    '/index.php/modules/vulnerabilities',
    '/index.php/modules/cve',
    '/index.php/modules/remediation',
    '/index.php/modules/cve?tab=catalog',
    '/index.php/modules/cve?tab=software',
    '/index.php/modules/cve?tab=reports',
    '/index.php/modules/threat_intelligence?tab=news',
    '/index.php/modules/threat_intelligence?tab=profiles',
    '/index.php/modules/remediation?tab=tasks',
    '/index.php/modules/remediation?tab=metrics',
    '/index.php/modules/remediation?tab=settings'
)

$server = Start-Process -FilePath 'php' `
    -ArgumentList @('-S', "127.0.0.1:$Port", '-t', $docroot, (Join-Path $PSScriptRoot 'router.php')) `
    -WorkingDirectory $docroot -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

$fail = 0
$results = @()

try {
    # --- login (GET token + POST) ---
    $login = Invoke-WebRequest -Uri "$base/admin/login" -SessionVariable ws -UseBasicParsing -TimeoutSec 30
    $token = [regex]::Match($login.Content, 'name="csrf_token"\s+value="([^"]+)"').Groups[1].Value
    if (-not $token) { throw 'No se pudo extraer el token CSRF del login' }

    $body = @{ username = $User; password = $Pass; csrf_token = $token }
    $post = Invoke-WebRequest -Uri "$base/admin/login" -Method POST -Body $body -WebSession $ws `
        -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
    if ($post.Content -match 'name="password"') { throw "Login fallido para '$User' (sigue mostrando el formulario)" }

    # --- rutas ---
    foreach ($r in $routes) {
        $entry = [pscustomobject]@{ Route = $r; Status = 0; Len = 0; Assets = 0; Problem = '' }
        try {
            $res = Invoke-WebRequest -Uri "$base$r" -WebSession $ws -UseBasicParsing -TimeoutSec 60 -MaximumRedirection 5
            $entry.Status = [int]$res.StatusCode
            $entry.Len = $res.Content.Length

            $errs = [regex]::Matches($res.Content, '(Fatal error|Parse error|Uncaught|Warning: [a-zA-Z_]+\(\))')
            if ($errs.Count -gt 0) {
                $entry.Problem = 'PHP: ' + (([regex]::Match($res.Content, '(Fatal error|Parse error|Uncaught|Warning:)[^<]{0,160}')).Value)
            }

            if ($entry.Status -ge 400) { $entry.Problem = "HTTP $($entry.Status)" }

            # assets referenciados
            $assets = [regex]::Matches($res.Content, '(?:href|src)="([^"]+\.(?:css|js|woff2))(?:\?[^"]*)?"') |
                ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
            foreach ($a in $assets) {
                $url = if ($a.StartsWith('http')) { $a } else { $base + $a }
                try {
                    $ar = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -Method Head
                    $entry.Assets++
                    if ([int]$ar.StatusCode -ge 400 -and -not $entry.Problem) { $entry.Problem = "asset $a -> $($ar.StatusCode)" }
                } catch {
                    if (-not $entry.Problem) { $entry.Problem = "asset $a -> KO" }
                }
            }
        } catch {
            $resp = $_.Exception.Response
            $entry.Status = if ($resp) { [int]$resp.StatusCode } else { 0 }
            if (-not $entry.Problem) { $entry.Problem = $_.Exception.Message.Substring(0, [Math]::Min(120, $_.Exception.Message.Length)) }
        }
        if ($entry.Problem) { $fail++ }
        $results += $entry
    }

    # --- comprobación de clases contra tw.css (opcional) ---
    if ($CheckCss) {
        $twPath = Join-Path $docroot 'assets/css/tw.css'
        if (-not (Test-Path $twPath)) {
            Write-Host 'AVISO: no existe assets/css/tw.css' -ForegroundColor Yellow
        } else {
            $tw = (Get-Content $twPath -Raw) -replace '\\', ''
            $known = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($m in [regex]::Matches($tw, '\.([A-Za-z0-9_:/\[\].%()#,+*~=!&-]+)')) { [void]$known.Add($m.Groups[1].Value) }
            $missing = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($r in $results) {
                try {
                    $html = (Invoke-WebRequest -Uri "$base$($r.Route)" -WebSession $ws -UseBasicParsing -TimeoutSec 60).Content
                } catch { continue }
                foreach ($cm in [regex]::Matches($html, 'class="([^"]+)"')) {
                    foreach ($cls in ($cm.Groups[1].Value -split '\s+')) {
                        if (-not $cls) { continue }
                        if (-not $known.Contains($cls)) { [void]$missing.Add($cls) }
                    }
                }
            }
            $missingArr = @($missing)
            $results += [pscustomobject]@{ Route = '(clases usadas no presentes en tw.css)'; Status = 0; Len = 0; Assets = 0; Problem = '' }
            Write-Host ''
            Write-Host "Clases sin regla en tw.css: $($missingArr.Count)" -ForegroundColor Cyan
            if ($missingArr.Count -gt 0) {
                Write-Host (($missingArr | Sort-Object | Select-Object -First 120) -join '  ')
            }
            Write-Host ''
        }
    }
}
finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}

Write-Host ''
$results | Format-Table Route, Status, Len, Assets, Problem -AutoSize

Write-Host ''
if ($fail -gt 0) {
    Write-Host "RESULTADO: $fail ruta(s) con problemas" -ForegroundColor Red
    exit 1
}
Write-Host 'RESULTADO: OK' -ForegroundColor Green
exit 0
