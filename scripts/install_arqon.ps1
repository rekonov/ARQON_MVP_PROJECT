param(
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = "",
  [string]$PythonPath = "",
  [switch]$SkipDependencyInstall,
  [switch]$SkipTaskInstall,
  [switch]$SkipKeyInit,
  [switch]$StrictHealth,
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

$installStartupScript = Resolve-ExistingPath -PathValue (Join-Path $projectRootResolved "scripts\install_startup_task.ps1") -Description "Install startup script"
$installTrayScript = Resolve-ExistingPath -PathValue (Join-Path $projectRootResolved "scripts\install_tray_startup_task.ps1") -Description "Install tray script"

$bootstrapPython = Resolve-AnyPython -ProjectRootPath $projectRootResolved -ExplicitPython $PythonPath
$venvPath = Join-Path $projectRootResolved ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

if (-not (Test-Path -Path $venvPython -PathType Leaf)) {
  Write-Host "Creating virtual environment: $venvPath"
  Invoke-Checked -FilePath $bootstrapPython -Arguments @("-m", "venv", $venvPath) -Step "python -m venv"
}

$python = Resolve-AnyPython -ProjectRootPath $projectRootResolved -ExplicitPython $PythonPath
Set-Location -Path $projectRootResolved

if (-not $SkipDependencyInstall) {
  Write-Host "Installing dependencies..."
  Invoke-Checked -FilePath $python -Arguments @("-m", "pip", "install", "-r", "requirements.txt") -Step "pip install requirements"
  if (Test-Path -Path (Join-Path $projectRootResolved "requirements-dev.txt") -PathType Leaf) {
    Invoke-Checked -FilePath $python -Arguments @("-m", "pip", "install", "-r", "requirements-dev.txt") -Step "pip install requirements-dev"
  }
  Invoke-Checked -FilePath $python -Arguments @("-m", "pip", "install", "-e", ".") -Step "pip install -e ."
}

if (-not $SkipKeyInit) {
  Write-Host "Ensuring API keys in secure store..."
  Invoke-Checked `
    -FilePath $python `
    -Arguments @("-m", "arqon_guardian.cli", "--config", $configResolved, "config", "ensure-keys", "--config-mode", "refs") `
    -Step "config ensure-keys"
}

Write-Host "Running ARQON self-check..."
$selfCheckArgs = @("-m", "arqon_guardian.cli", "--config", $configResolved, "self-check")
if ($StrictHealth) {
  $selfCheckArgs += "--strict"
}
if ($SkipBindCheck) {
  $selfCheckArgs += "--skip-bind-check"
}
Invoke-Checked -FilePath $python -Arguments $selfCheckArgs -Step "self-check"

if (-not $SkipTaskInstall) {
  Write-Host "Installing startup tasks..."
  & $installStartupScript -ProjectRoot $projectRootResolved -ConfigPath $configResolved -PythonPath $python
  if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {
    throw "install_startup_task.ps1 failed with exit code $LASTEXITCODE"
  }
  & $installTrayScript -ProjectRoot $projectRootResolved -ConfigPath $configResolved -PythonPath $python
  if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {
    throw "install_tray_startup_task.ps1 failed with exit code $LASTEXITCODE"
  }
}

Write-Host "ARQON install completed successfully."
Write-Host "ProjectRoot: $projectRootResolved"
Write-Host "ConfigPath: $configResolved"
