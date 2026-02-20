param(
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$OutputDir = ""
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

function Copy-PathIfExists {
  param(
    [string]$SourcePath,
    [string]$DestinationPath
  )
  if (Test-Path -Path $SourcePath) {
    $parent = Split-Path -Parent $DestinationPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
      New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
    Copy-Item -Path $SourcePath -Destination $DestinationPath -Recurse -Force
  }
}

function Remove-NoiseFiles {
  param([string]$RootPath)
  if (-not (Test-Path -Path $RootPath -PathType Container)) {
    return
  }
  Get-ChildItem -Path $RootPath -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  Get-ChildItem -Path $RootPath -Recurse -Directory -Filter "*.egg-info" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  Get-ChildItem -Path $RootPath -Recurse -File -Include "*.pyc", "*.pyo" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
}

$projectRootResolved = Resolve-ExistingPath -PathValue $ProjectRoot -Description "Project root" -Directory
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

$stagingRoot = Join-Path $outputResolved "staging"
$userStage = Join-Path $stagingRoot "arqon-user"
$adminStage = Join-Path $stagingRoot "arqon-admin"

if (Test-Path -Path $stagingRoot) {
  Remove-Item -Path $stagingRoot -Recurse -Force
}
New-Item -Path $userStage -ItemType Directory -Force | Out-Null
New-Item -Path $adminStage -ItemType Directory -Force | Out-Null

# User build: minimal package, no dashboard/admin surface.
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "src") -DestinationPath (Join-Path $userStage "src")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "requirements.txt") -DestinationPath (Join-Path $userStage "requirements.txt")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "pyproject.toml") -DestinationPath (Join-Path $userStage "pyproject.toml")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "README.md") -DestinationPath (Join-Path $userStage "README.md")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "START_ARQON_PROTECTION.cmd") -DestinationPath (Join-Path $userStage "START_ARQON_PROTECTION.cmd")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "START_ARQON_USER_MODE.cmd") -DestinationPath (Join-Path $userStage "START_ARQON_USER_MODE.cmd")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "START_ARQON_BROWSER_GUARD.cmd") -DestinationPath (Join-Path $userStage "START_ARQON_BROWSER_GUARD.cmd")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "STOP_ARQON_PROTECTION.cmd") -DestinationPath (Join-Path $userStage "STOP_ARQON_PROTECTION.cmd")

New-Item -Path (Join-Path $userStage "config") -ItemType Directory -Force | Out-Null
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "config\user-mode.yml") -DestinationPath (Join-Path $userStage "config\user-mode.yml")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "config\browser-guard.yml") -DestinationPath (Join-Path $userStage "config\browser-guard.yml")

New-Item -Path (Join-Path $userStage "scripts") -ItemType Directory -Force | Out-Null
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "scripts\run_user_console.ps1") -DestinationPath (Join-Path $userStage "scripts\run_user_console.ps1")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "scripts\start_user_protection.ps1") -DestinationPath (Join-Path $userStage "scripts\start_user_protection.ps1")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "scripts\stop_user_protection.ps1") -DestinationPath (Join-Path $userStage "scripts\stop_user_protection.ps1")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "scripts\stop_arqon_runtime.ps1") -DestinationPath (Join-Path $userStage "scripts\stop_arqon_runtime.ps1")
Copy-PathIfExists -SourcePath (Join-Path $projectRootResolved "scripts\switch_mode.ps1") -DestinationPath (Join-Path $userStage "scripts\switch_mode.ps1")

$userReadme = @"
ARQON USER BUILD

How to run:
1) Extract this archive to any folder.
2) Choose mode:
   - START_ARQON_USER_MODE.cmd (API/dashboard disabled)
   - START_ARQON_BROWSER_GUARD.cmd (API enabled for browser extension)
3) Wait for first-run setup to finish.

What it does:
- Runs ARQON protection in selected mode.
- Terminal shows running status and latest protection actions.
- Browser Guard mode keeps user/admin API keys separated.

To stop:
- Double click STOP_ARQON_PROTECTION.cmd
"@
Set-Content -Path (Join-Path $userStage "README_USER.txt") -Value $userReadme -Encoding UTF8

# Admin build: full package for analysis and management.
$adminItems = @(
  "src",
  "config",
  "dashboard",
  "browser-extension",
  "scripts",
  "requirements.txt",
  "requirements-dev.txt",
  "pyproject.toml",
  "README.md",
  "START_ARQON_PROTECTION.cmd",
  "START_ARQON_USER_MODE.cmd",
  "START_ARQON_BROWSER_GUARD.cmd",
  "STOP_ARQON_PROTECTION.cmd"
)
foreach ($item in $adminItems) {
  $source = Join-Path $projectRootResolved $item
  $dest = Join-Path $adminStage $item
  Copy-PathIfExists -SourcePath $source -DestinationPath $dest
}

Remove-Item -Path (Join-Path $adminStage "state") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $adminStage "quarantine") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $adminStage ".venv") -Recurse -Force -ErrorAction SilentlyContinue

Remove-NoiseFiles -RootPath $userStage
Remove-NoiseFiles -RootPath $adminStage

$userZip = Join-Path $outputResolved "ARQON_USER_BUILD.zip"
$adminZip = Join-Path $outputResolved "ARQON_ADMIN_BUILD.zip"
Remove-Item -Path $userZip -Force -ErrorAction SilentlyContinue
Remove-Item -Path $adminZip -Force -ErrorAction SilentlyContinue

Compress-Archive -Path (Join-Path $userStage "*") -DestinationPath $userZip -CompressionLevel Optimal
Compress-Archive -Path (Join-Path $adminStage "*") -DestinationPath $adminZip -CompressionLevel Optimal

Write-Host "Build variants created."
Write-Host "User build:  $userZip"
Write-Host "Admin build: $adminZip"
