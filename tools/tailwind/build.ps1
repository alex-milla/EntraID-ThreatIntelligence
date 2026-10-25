# ============================================================
#  build.ps1 — Compila Tailwind v4 (CLI standalone) -> tw.css
#  Uso:
#     pwsh tools/tailwind/build.ps1
#     pwsh tools/tailwind/build.ps1 -Watch
#  El binario NO se sube al hosting; solo public_html/assets/css/tw.css
# ============================================================
param([switch]$Watch)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$cli = Join-Path $here 'tailwindcss.exe'
$input = Join-Path $here 'input.css'
$output = Join-Path $here '../../public_html/assets/css/tw.css'

if (-not (Test-Path $cli)) {
    throw "Falta el binario: $cli  (descárgalo de https://github.com/tailwindlabs/tailwindcss/releases)"
}

$args = @('-i', $input, '-o', $output, '--minify')
if ($Watch) { $args += '--watch' }

& $cli @args
if ($LASTEXITCODE -ne 0) { throw "Tailwind falló con código $LASTEXITCODE" }

if (Test-Path $output) {
    Write-Host ("OK -> {0} ({1:N0} bytes)" -f $output, (Get-Item $output).Length) -ForegroundColor Green
}
