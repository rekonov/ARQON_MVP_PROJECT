param(
  [string]$BackupPath = "",
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = "",
  [string]$PythonPath = "",
  [switch]$SkipTaskInstall,
  [switch]$SkipBindCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ArtifactList = @(
  "src",
  "dashboard",
  "scripts",
  "browser-extension",
  "config",
  "pyproject.toml",
  "requirements.txt",
  "requirements-dev.txt",
  "README.md"
)

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

function Copy-Artifact {
  param(
    [string]$SourcePath,
    [string]$DestinationPath
  )
  if (Test-Path -Path $SourcePath -PathType Container) {
    if (-not (Test-Path -Path $DestinationPath -PathType Container)) {
      New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
    }
    Copy-Item -Path (Join-Path $SourcePath "*") -Destination $DestinationPath -Recurse -Force
  } else {
    if (Test-Path -Path $DestinationPath) {
      Remove-Item -Path $DestinationPath -Force
    }
    Copy-Item -Path $SourcePath -Destination $DestinationPath -Force
  }
}

$projectRootResolved = Resolve-ExistingPath -PathValue $ProjectRoot -Description "Project root" -Directory
$backupPathResolved = $BackupPath
if ([string]::IsNullOrWhiteSpace($backupPathResolved)) {
  $backupsDir = Join-Path $projectRootResolved "backups"
  $backupsResolved = Resolve-ExistingPath -PathValue $backupsDir -Description "Backups directory" -Directory
  $latest = Get-ChildItem -Path $backupsResolved -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($null -eq $latest) {
    throw "No backups found in: $backupsResolved"
  }
  $backupPathResolved = $latest.FullName
}
$backupPathResolved = Resolve-ExistingPath -PathValue $backupPathResolved -Description "Backup path" -Directory

$configResolved = $ConfigPath
if ([string]::IsNullOrWhiteSpace($configResolved)) {
  $configResolved = Join-Path $projectRootResolved "config\default.yml"
}
if (-not [System.IO.Path]::IsPathRooted($configResolved)) {
  $configResolved = Join-Path $projectRootResolved $configResolved
}
$configResolved = Resolve-ExistingPath -PathValue $configResolved -Description "Config file"

Write-Host "Rolling back ARQON from backup: $backupPathResolved"
foreach ($artifact in $script:ArtifactList) {
  $sourceArtifact = Join-Path $backupPathResolved $artifact
  if (-not (Test-Path -Path $sourceArtifact)) {
    continue
  }
  $targetArtifact = Join-Path $projectRootResolved $artifact
  Copy-Artifact -SourcePath $sourceArtifact -DestinationPath $targetArtifact
}

$installerScript = Resolve-ExistingPath -PathValue (Join-Path $projectRootResolved "scripts\install_arqon.ps1") -Description "Installer script"
$installerArgs = @(
  "-ProjectRoot", $projectRootResolved,
  "-ConfigPath", $configResolved,
  "-SkipDependencyInstall"
)
if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
  $installerArgs += @("-PythonPath", $PythonPath)
}
if ($SkipTaskInstall) {
  $installerArgs += "-SkipTaskInstall"
}
if ($SkipBindCheck) {
  $installerArgs += "-SkipBindCheck"
}

& $installerScript @installerArgs
if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {
  throw "install_arqon.ps1 failed after rollback with exit code $LASTEXITCODE"
}

Write-Host "Rollback completed successfully."
