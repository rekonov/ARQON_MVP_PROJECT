param(
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = "",
  [string]$PythonPath = "",
  [switch]$SkipKeyInit,
  [switch]$StrictHealth,
  [switch]$SkipTests,
  [switch]$SkipBindCheck
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

function Resolve-AnyPython {
  param(
    [string]$ProjectRootPath,
    [string]$ExplicitPython
  )
  if (-not [string]::IsNullOrWhiteSpace($ExplicitPython)) {
    return Resolve-ExistingPath -PathValue $ExplicitPython -Description "Python executable"
  }
  $venvPython = Join-Path $ProjectRootPath ".venv\Scripts\python.exe"
  if (Test-Path -Path $venvPython -PathType Leaf) {
    return (Resolve-Path -Path $venvPython).Path
  }
  $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
  if ($null -eq $pythonCmd) {
    throw "Python executable not found. Set -PythonPath or install Python."
  }
  return $pythonCmd.Source
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
$configResolved = $ConfigPath
if ([string]::IsNullOrWhiteSpace($configResolved)) {
  $configResolved = Join-Path $projectRootResolved "config\default.yml"
}
$configResolved = Resolve-ExistingPath -PathValue $configResolved -Description "Config file"
$python = Resolve-AnyPython -ProjectRootPath $projectRootResolved -ExplicitPython $PythonPath

Set-Location -Path $projectRootResolved
$env:PYTHONPATH = Join-Path $projectRootResolved "src"

Write-Host "MVP validation: compile check"
Invoke-Checked -FilePath $python -Arguments @("-m", "compileall", "src") -Step "python -m compileall src"

if (-not $SkipKeyInit) {
  Write-Host "MVP validation: ensure API keys"
  Invoke-Checked `
    -FilePath $python `
    -Arguments @("-m", "arqon_guardian.cli", "--config", $configResolved, "config", "ensure-keys", "--config-mode", "refs") `
    -Step "config ensure-keys"
}

Write-Host "MVP validation: self-check"
$selfCheckArgs = @("-m", "arqon_guardian.cli", "--config", $configResolved, "self-check")
if ($StrictHealth) {
  $selfCheckArgs += "--strict"
}
if ($SkipBindCheck) {
  $selfCheckArgs += "--skip-bind-check"
}
Invoke-Checked -FilePath $python -Arguments $selfCheckArgs -Step "self-check"

if (-not $SkipTests) {
  Write-Host "MVP validation: unit tests"
  Invoke-Checked -FilePath $python -Arguments @("-m", "pytest", "-q") -Step "python -m pytest -q"
}

Write-Host "ARQON MVP validation passed."
