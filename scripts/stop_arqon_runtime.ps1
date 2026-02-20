param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArqonRunProcesses {
  return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $name = [string]$_.Name
    $cmd = [string]$_.CommandLine
    if ($name -notmatch '^python(w)?\.exe$') {
      return $false
    }
    if ([string]::IsNullOrWhiteSpace($cmd)) {
      return $false
    }
    return $cmd.Contains("arqon_guardian.cli") -and $cmd.Contains(" run")
  })
}

$running = @(Get-ArqonRunProcesses)
if ($running.Count -eq 0) {
  Write-Host "ARQON runtime is not running."
  exit 0
}

$stopped = 0
foreach ($item in $running) {
  $processId = [int]$item.ProcessId
  Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
  Write-Host "Stopped ARQON process PID: $processId"
  $stopped += 1
}

Write-Host "Stopped processes: $stopped"
exit 0
