param(
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = "",
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
    throw "Python is not installed. Install Python 3.11+ and run again."
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

function Get-LatestProtectionEvents {
  param(
    [string]$EventsFilePath,
    [int]$Limit = 8
  )

  if (-not (Test-Path -Path $EventsFilePath -PathType Leaf)) {
    return @()
  }

  $lines = Get-Content -Path $EventsFilePath -Tail 200 -ErrorAction SilentlyContinue
  if ($null -eq $lines) {
    return @()
  }

  $parsed = New-Object System.Collections.Generic.List[object]
  foreach ($line in $lines) {
    if ([string]::IsNullOrWhiteSpace($line)) {
      continue
    }
    try {
      $item = $line | ConvertFrom-Json -ErrorAction Stop
      $type = [string]$item.type
      $level = [string]$item.level
      if ($level -in @("warning", "error") -or $type -like "blocked_*" -or $type -eq "quarantine") {
        $parsed.Add($item) | Out-Null
      }
    } catch {
      continue
    }
  }

  if ($parsed.Count -le 0) {
    return @()
  }

  $out = @($parsed | Select-Object -Last $Limit)
  return $out
}

$projectRootResolved = Resolve-ExistingPath -PathValue $ProjectRoot -Description "Project root" -Directory
$configResolved = $ConfigPath
if ([string]::IsNullOrWhiteSpace($configResolved)) {
  $configResolved = Join-Path $projectRootResolved "config\user-mode.yml"
}
$configResolved = Resolve-ExistingPath -PathValue $configResolved -Description "Config file"

$pythonBootstrap = Resolve-PythonExecutable -ProjectRootPath $projectRootResolved -ExplicitPython $PythonPath
$venvPath = Join-Path $projectRootResolved ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
if (-not (Test-Path -Path $venvPython -PathType Leaf)) {
  Write-Host "Creating virtual environment..."
  Invoke-Checked -FilePath $pythonBootstrap -Arguments @("-m", "venv", $venvPath) -Step "python -m venv"
}

$python = Resolve-PythonExecutable -ProjectRootPath $projectRootResolved -ExplicitPython $PythonPath
$srcPath = Resolve-ExistingPath -PathValue (Join-Path $projectRootResolved "src") -Description "Source directory" -Directory
$setupMarker = Join-Path $venvPath ".arqon-user-setup.done"

Set-Location -Path $projectRootResolved
$env:PYTHONPATH = $srcPath

if (-not (Test-Path -Path $setupMarker -PathType Leaf)) {
  Write-Host "Installing ARQON runtime dependencies (first run)..."
  Invoke-Checked -FilePath $python -Arguments @("-m", "pip", "install", "-r", "requirements.txt") -Step "pip install -r requirements.txt"
  Invoke-Checked -FilePath $python -Arguments @("-m", "pip", "install", "-e", ".") -Step "pip install -e ."
  New-Item -ItemType File -Path $setupMarker -Force | Out-Null
}

Write-Host "Ensuring local keys..."
Invoke-Checked `
  -FilePath $python `
  -Arguments @("-m", "arqon_guardian.cli", "--config", $configResolved, "config", "ensure-keys", "--config-mode", "refs") `
  -Step "config ensure-keys"

Write-Host "Starting ARQON protection..."
Invoke-Checked `
  -FilePath "powershell" `
  -Arguments @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $projectRootResolved "scripts\start_user_protection.ps1"), "-ProjectRoot", $projectRootResolved, "-ConfigPath", $configResolved) `
  -Step "start_user_protection"

$stateDir = Join-Path $env:LOCALAPPDATA "ARQON\state"
$eventsFile = Join-Path $stateDir "events.jsonl"
$sleepSec = [Math]::Max(1, [int]$RefreshSec)

Write-Host ""
Write-Host "ARQON user console started. Protection keeps running in background."
Write-Host "Press Ctrl+C to close this monitor window."
Start-Sleep -Seconds 1

while ($true) {
  $running = @(Get-UserModeProcesses -ConfigResolved $configResolved)
  $status = if ($running.Count -gt 0) { "RUNNING" } else { "STOPPED" }
  $statusColor = if ($running.Count -gt 0) { "Green" } else { "Red" }
  $timeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  $events = @(Get-LatestProtectionEvents -EventsFilePath $eventsFile -Limit 8)

  Clear-Host
  Write-Host "ARQON USER BUILD" -ForegroundColor Cyan
  Write-Host "Time: $timeStamp"
  Write-Host ("Protection: {0}" -f $status) -ForegroundColor $statusColor
  Write-Host ("Running process(es): {0}" -f $running.Count)
  Write-Host ""
  Write-Host "Latest protection actions:"

  if ($events.Count -eq 0) {
    Write-Host "- no recent block/quarantine events"
  } else {
    foreach ($event in $events) {
      $evtTime = [string]$event.timestamp_utc
      $evtType = [string]$event.type
      $evtMsg = [string]$event.message
      Write-Host ("- [{0}] {1}: {2}" -f $evtTime, $evtType, $evtMsg)
    }
  }

  Start-Sleep -Seconds $sleepSec
}
