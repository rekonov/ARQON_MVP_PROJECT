param(
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = "",
  [string]$PythonPath = "",
  [string]$OutputDir = "",
  [string]$SigningKeyFile = "",
  [string]$PublicKeyringFile = "",
  [string]$Version = "",
  [switch]$SkipSigningKeyInit,
  [switch]$SkipTests
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

$outputResolved = $OutputDir
if ([string]::IsNullOrWhiteSpace($outputResolved)) {
  $outputResolved = Join-Path $projectRootResolved "release"
}
if (-not [System.IO.Path]::IsPathRooted($outputResolved)) {
  $outputResolved = Join-Path $projectRootResolved $outputResolved
}
if (-not (Test-Path -Path $outputResolved -PathType Container)) {
  New-Item -Path $outputResolved -ItemType Directory -Force | Out-Null
}
$outputResolved = (Resolve-Path $outputResolved).Path

$python = Resolve-AnyPython -ProjectRootPath $projectRootResolved -ExplicitPython $PythonPath
Set-Location -Path $projectRootResolved
$env:PYTHONPATH = Join-Path $projectRootResolved "src"

Invoke-Checked -FilePath $python -Arguments @("-m", "pip", "install", "-r", "requirements.txt") -Step "pip install requirements"
Invoke-Checked -FilePath $python -Arguments @("-m", "pip", "install", "-r", "requirements-dev.txt") -Step "pip install requirements-dev"
Invoke-Checked -FilePath $python -Arguments @("-m", "pip", "install", "-e", ".") -Step "pip install -e ."

Invoke-Checked -FilePath $python -Arguments @("-m", "compileall", "src") -Step "compileall"
Invoke-Checked -FilePath $python -Arguments @("-m", "ruff", "check", "src", "tests", "--select", "F") -Step "ruff"
if (-not $SkipTests) {
  Invoke-Checked -FilePath $python -Arguments @("-m", "pytest", "-q") -Step "pytest"
}

Invoke-Checked -FilePath $python -Arguments @("-m", "build") -Step "build"

$distDir = Join-Path $projectRootResolved "dist"
if (Test-Path -Path $distDir -PathType Container) {
  Copy-Item -Path (Join-Path $distDir "*") -Destination $outputResolved -Force
}

$updatePackPath = Join-Path $outputResolved "update.pack.json"
$keyringResolved = ""
if (-not [string]::IsNullOrWhiteSpace($PublicKeyringFile)) {
  $keyringResolved = Resolve-ExistingPath -PathValue $PublicKeyringFile -Description "Public keyring file"
}
$signingKeyResolved = ""
if (-not [string]::IsNullOrWhiteSpace($SigningKeyFile)) {
  $signingKeyResolved = Resolve-ExistingPath -PathValue $SigningKeyFile -Description "Signing key file"
}

$defaultPrivateKey = Join-Path $projectRootResolved "config\\policy-signing-private.pem"
$defaultPublicKey = Join-Path $projectRootResolved "config\\policy-signing-public.pem"
$defaultKeyring = Join-Path $projectRootResolved "config\\policy-signing-public.keys.json"

if ([string]::IsNullOrWhiteSpace($signingKeyResolved) -and (Test-Path -Path $defaultPrivateKey -PathType Leaf)) {
  $signingKeyResolved = (Resolve-Path $defaultPrivateKey).Path
}
if ([string]::IsNullOrWhiteSpace($keyringResolved) -and (Test-Path -Path $defaultKeyring -PathType Leaf)) {
  $keyringResolved = (Resolve-Path $defaultKeyring).Path
}

if ([string]::IsNullOrWhiteSpace($signingKeyResolved) -and -not $SkipSigningKeyInit) {
  Write-Host "Signing key not found. Generating release signing keys..."
  $keyringTarget = if ([string]::IsNullOrWhiteSpace($keyringResolved)) { $defaultKeyring } else { $keyringResolved }
  Invoke-Checked `
    -FilePath $python `
    -Arguments @(
      "-m", "arqon_guardian.cli",
      "--config", $configResolved,
      "crypto", "keygen",
      "--private-out", $defaultPrivateKey,
      "--public-out", $defaultPublicKey,
      "--key-id", "default",
      "--keyring-out", $keyringTarget
    ) `
    -Step "crypto keygen"
  $signingKeyResolved = (Resolve-Path $defaultPrivateKey).Path
  if (Test-Path -Path $keyringTarget -PathType Leaf) {
    $keyringResolved = (Resolve-Path $keyringTarget).Path
  }
}

if ([string]::IsNullOrWhiteSpace($signingKeyResolved)) {
  throw "Signing key file is required for update-pack build. Provide -SigningKeyFile or run without -SkipSigningKeyInit."
}

$packArgs = @(
  "-m", "arqon_guardian.cli",
  "--config", $configResolved,
  "update-pack", "build",
  "--source-root", $projectRootResolved,
  "--output", $updatePackPath
)
if (-not [string]::IsNullOrWhiteSpace($signingKeyResolved)) {
  $packArgs += @("--secret-file", $signingKeyResolved)
}
if (-not [string]::IsNullOrWhiteSpace($keyringResolved)) {
  $packArgs += @("--keyring-file", $keyringResolved)
}
if (-not [string]::IsNullOrWhiteSpace($Version)) {
  $packArgs += @("--version", $Version)
}
Invoke-Checked -FilePath $python -Arguments $packArgs -Step "update-pack build"

Write-Host "ARQON release build completed."
Write-Host "OutputDir: $outputResolved"
Write-Host "UpdatePack: $updatePackPath"
