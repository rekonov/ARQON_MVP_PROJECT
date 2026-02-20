param(
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

$projectRootResolved = Resolve-ExistingPath -PathValue $ProjectRoot -Description "Project root" -Directory
$runnerPath = Resolve-ExistingPath -PathValue (Join-Path $projectRootResolved "scripts\run_agent.ps1") -Description "Runner script"
$configResolved = $ConfigPath
if ([string]::IsNullOrWhiteSpace($configResolved)) {
  $configResolved = Join-Path $projectRootResolved "config\default.yml"
}
$configResolved = Resolve-ExistingPath -PathValue $configResolved -Description "Config file"
$pythonResolved = ""
if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
  $pythonResolved = Resolve-ExistingPath -PathValue $PythonPath -Description "Python executable"
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:AgentProcess = $null
$dashboardUrl = "http://127.0.0.1:8765/dashboard/"

function Get-AgentArguments {
  $argsList = @(
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-WindowStyle", "Hidden",
    "-File", $runnerPath,
    "-ProjectRoot", $projectRootResolved,
    "-ConfigPath", $configResolved
  )
  if (-not [string]::IsNullOrWhiteSpace($pythonResolved)) {
    $argsList += @("-PythonPath", $pythonResolved)
  }
  return [string]::Join(" ", ($argsList | ForEach-Object { Convert-ToTaskArgument $_ }))
}

function Start-ArqonAgent {
  if ($script:AgentProcess -and -not $script:AgentProcess.HasExited) {
    return
  }

  $args = Get-AgentArguments
  $script:AgentProcess = Start-Process -FilePath "powershell.exe" -ArgumentList $args -PassThru -WindowStyle Hidden
}

function Stop-ArqonAgent {
  if ($script:AgentProcess -and -not $script:AgentProcess.HasExited) {
    try {
      Stop-Process -Id $script:AgentProcess.Id -Force -ErrorAction SilentlyContinue
    } catch {
      # no-op
    }
  }
  $script:AgentProcess = $null
}

function Open-ArqonDashboard {
  Start-Process $dashboardUrl | Out-Null
}

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$startItem = $menu.Items.Add("Start Agent")
$stopItem = $menu.Items.Add("Stop Agent")
$openItem = $menu.Items.Add("Open Dashboard")
$separator = $menu.Items.Add("-")
$exitItem = $menu.Items.Add("Exit")

$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.Text = "ARQON"
$notify.ContextMenuStrip = $menu
$notify.Visible = $true

$startItem.Add_Click({ Start-ArqonAgent }) | Out-Null
$stopItem.Add_Click({ Stop-ArqonAgent }) | Out-Null
$openItem.Add_Click({ Open-ArqonDashboard }) | Out-Null
$notify.Add_DoubleClick({ Open-ArqonDashboard }) | Out-Null

$running = $true
$exitItem.Add_Click({
  $running = $false
}) | Out-Null

Start-ArqonAgent

while ($running) {
  [System.Windows.Forms.Application]::DoEvents()
  Start-Sleep -Milliseconds 250
}

Stop-ArqonAgent
$notify.Visible = $false
$notify.Dispose()
