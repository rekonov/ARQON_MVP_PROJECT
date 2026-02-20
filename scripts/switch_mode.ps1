param(
  [ValidateSet("USER", "BROWSER_GUARD")]
  [string]$Mode = "USER",
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$PythonPath = "",
  [int]$RefreshSec = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ExistingPath {
  param(
    [string]$PathValue,
    [string]$Description,
    [switch]$Directory
  )
  $pathType = if ($Directory) { "Container" } else { "Leaf" }
  if (-not (Test-Path -Path $PathValue -PathType $pathType)) {
    throw "$Description not found: $PathValue"
  }
  return (Resolve-Path -Path $PathValue).Path
}

function Invoke-Checked {
  param(
    [string]$FilePath,
    [string[]]$Arguments,
    [string]$Step
  )
  & $FilePath @Arguments
  if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {
    throw "$Step failed with exit code $LASTEXITCODE"
  }
}

$projectRootResolved = Resolve-ExistingPath -PathValue $ProjectRoot -Description "Project root" -Directory
$modeNormalized = $Mode.ToUpperInvariant()

$configResolved = switch ($modeNormalized) {
  "USER" { Resolve-ExistingPath -PathValue (Join-Path $projectRootResolved "config\user-mode.yml") -Description "USER config" }
  "BROWSER_GUARD" { Resolve-ExistingPath -PathValue (Join-Path $projectRootResolved "config\browser-guard.yml") -Description "BROWSER_GUARD config" }
  default { throw "Unsupported mode: $Mode" }
}

Write-Host "Switching ARQON mode: $modeNormalized"
Write-Host "Config: $configResolved"

Invoke-Checked `
  -FilePath "powershell" `
  -Arguments @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $projectRootResolved "scripts\stop_arqon_runtime.ps1")) `
  -Step "stop_arqon_runtime"

$runArgs = @(
  "-ExecutionPolicy", "Bypass",
  "-File", (Join-Path $projectRootResolved "scripts\run_user_console.ps1"),
  "-ProjectRoot", $projectRootResolved,
  "-ConfigPath", $configResolved,
  "-RefreshSec", [string]([Math]::Max(1, [int]$RefreshSec))
)
if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
  $runArgs += @("-PythonPath", $PythonPath)
}

if ($modeNormalized -eq "BROWSER_GUARD") {
  Write-Host ""
  Write-Host "Browser Guard mode enabled."
  Write-Host "Extension endpoint: http://127.0.0.1:8765"
  Write-Host "Get API key:"
  Write-Host "python -m arqon_guardian.cli --config `"$configResolved`" config secret-store get --name api_user_key"
  Write-Host ""
}

& powershell @runArgs
$exitCode = if ($LASTEXITCODE -ne $null) { [int]$LASTEXITCODE } else { 0 }
exit $exitCode
