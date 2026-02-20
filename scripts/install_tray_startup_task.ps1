param(
  [string]$TaskName = "ARQONTray",
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = "",
  [string]$PythonPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-ToTaskArgument {
  param([string]$Value)
  if ($Value -match '[\s"`]') {
    return '"' + ($Value -replace '"', '`"') + '"'
  }
  return $Value
}

function Resolve-ExistingFile {
  param([string]$PathValue, [string]$Description)
  if (-not (Test-Path -Path $PathValue -PathType Leaf)) {
    throw "$Description not found: $PathValue"
  }
  return (Resolve-Path -Path $PathValue).Path
}

$projectRootResolved = (Resolve-Path -Path $ProjectRoot).Path
if (-not (Test-Path -Path $projectRootResolved -PathType Container)) {
  throw "Project root not found: $projectRootResolved"
}

$trayScript = Resolve-ExistingFile -PathValue (Join-Path $projectRootResolved "scripts\start_tray.ps1") -Description "Tray script"

$configResolved = $ConfigPath
if ([string]::IsNullOrWhiteSpace($configResolved)) {
  $configResolved = Join-Path $projectRootResolved "config\default.yml"
}
$configResolved = Resolve-ExistingFile -PathValue $configResolved -Description "Config file"

$pythonResolved = ""
if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
  $pythonResolved = Resolve-ExistingFile -PathValue $PythonPath -Description "Python executable"
}

$argsList = @(
  "-NoProfile",
  "-NonInteractive",
  "-ExecutionPolicy", "Bypass",
  "-WindowStyle", "Hidden",
  "-File", $trayScript,
  "-ProjectRoot", $projectRootResolved,
  "-ConfigPath", $configResolved
)

if (-not [string]::IsNullOrWhiteSpace($pythonResolved)) {
  $argsList += @("-PythonPath", $pythonResolved)
}

$argument = [string]::Join(" ", ($argsList | ForEach-Object { Convert-ToTaskArgument $_ }))
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -MultipleInstances IgnoreNew `
  -RestartCount 3 `
  -RestartInterval (New-TimeSpan -Minutes 1)

$userId = if ($env:USERDOMAIN) { "$($env:USERDOMAIN)\$($env:USERNAME)" } else { $env:USERNAME }
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited

Register-ScheduledTask `
  -TaskName $TaskName `
  -Action $action `
  -Trigger $trigger `
  -Principal $principal `
  -Description "ARQON tray launcher" `
  -Settings $settings `
  -Force | Out-Null

Write-Host "Tray startup task installed: $TaskName"
Write-Host "Task target script: $trayScript"
Write-Host "Config: $configResolved"
