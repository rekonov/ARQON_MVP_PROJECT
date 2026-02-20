param(
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = "",
  [string]$PythonPath = "",
  [switch]$Foreground,
  [switch]$Force
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

function Resolve-PythonExecutable {
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
    throw "Python executable not found. Set -PythonPath or create .venv\\Scripts\\python.exe"
  }
  return $pythonCmd.Source
}

function Get-UserModeProcesses {
  param([string]$ConfigResolved)
  $normalizedConfig = $ConfigResolved.Replace("/", "\")
  return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $name = [string]$_.Name
    $cmd = [string]$_.CommandLine
    if ($name -notmatch '^python(w)?\.exe$') {
      return $false
    }
    if ([string]::IsNullOrWhiteSpace($cmd)) {
      return $false
    }
    return $cmd.Contains("arqon_guardian.cli") -and $cmd.Contains(" run") -and $cmd.Contains($normalizedConfig)
  })
}

$projectRootResolved = Resolve-ExistingPath -PathValue $ProjectRoot -Description "Project root" -Directory
$configResolved = $ConfigPath
if ([string]::IsNullOrWhiteSpace($configResolved)) {
  $configResolved = Join-Path $projectRootResolved "config\user-mode.yml"
}
$configResolved = Resolve-ExistingPath -PathValue $configResolved -Description "Config file"
$python = Resolve-PythonExecutable -ProjectRootPath $projectRootResolved -ExplicitPython $PythonPath
$srcPath = Resolve-ExistingPath -PathValue (Join-Path $projectRootResolved "src") -Description "Source directory" -Directory

Set-Location -Path $projectRootResolved
$env:PYTHONPATH = $srcPath

if (-not $Foreground) {
  $running = @(Get-UserModeProcesses -ConfigResolved $configResolved)
  if ($running.Count -gt 0 -and -not $Force) {
    $pids = ($running | ForEach-Object { [string]$_.ProcessId }) -join ", "
    Write-Host "ARQON user protection is already running. PID(s): $pids"
    Write-Host "Use scripts\\stop_user_protection.ps1 to stop it first, or rerun with -Force."
    exit 0
  }

  $args = @("-m", "arqon_guardian.cli", "--config", $configResolved, "run")
  $proc = Start-Process -FilePath $python -ArgumentList $args -WorkingDirectory $projectRootResolved -WindowStyle Hidden -PassThru
  Start-Sleep -Seconds 1
  if ($proc.HasExited) {
    throw "Failed to start ARQON user protection (process exited immediately)."
  }
  Write-Host "ARQON protection started in background."
  Write-Host "PID: $($proc.Id)"
  Write-Host "Mode: user-mode (admin dashboard disabled)"
  Write-Host "To stop: powershell -ExecutionPolicy Bypass -File .\\scripts\\stop_user_protection.ps1"
  exit 0
}

Write-Host "Starting ARQON in foreground (user-mode, dashboard disabled)..."
& $python -m arqon_guardian.cli --config $configResolved run
$exitCode = if ($LASTEXITCODE -ne $null) { [int]$LASTEXITCODE } else { 0 }
exit $exitCode
