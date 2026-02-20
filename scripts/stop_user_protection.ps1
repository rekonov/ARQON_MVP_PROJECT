param(
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = ""
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

$running = @(Get-UserModeProcesses -ConfigResolved $configResolved)
if ($running.Count -eq 0) {
  Write-Host "ARQON user protection is not running."
  exit 0
}

foreach ($item in $running) {
  $processId = [int]$item.ProcessId
  Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
  Write-Host "Stopped ARQON user protection process PID: $processId"
}

exit 0
