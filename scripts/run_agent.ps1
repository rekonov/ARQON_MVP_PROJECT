param(
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = "",
  [string]$PythonPath = ""
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

$projectRootResolved = Resolve-ExistingPath -PathValue $ProjectRoot -Description "Project root" -Directory
$configResolved = $ConfigPath
if ([string]::IsNullOrWhiteSpace($configResolved)) {
  $configResolved = Join-Path $projectRootResolved "config\default.yml"
}
$configResolved = Resolve-ExistingPath -PathValue $configResolved -Description "Config file"
$python = Resolve-PythonExecutable -ProjectRootPath $projectRootResolved -ExplicitPython $PythonPath
$srcPath = Resolve-ExistingPath -PathValue (Join-Path $projectRootResolved "src") -Description "Source directory" -Directory

Set-Location -Path $projectRootResolved
$env:PYTHONPATH = $srcPath

& $python -m arqon_guardian.cli --config $configResolved run
$exitCode = if ($LASTEXITCODE -ne $null) { [int]$LASTEXITCODE } else { 0 }
exit $exitCode
