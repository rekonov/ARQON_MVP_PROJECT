param(
  [Parameter(Mandatory = $true)]
  [string]$SourceRoot,
  [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$ConfigPath = "",
  [string]$PythonPath = "",
  [string]$BackupRoot = "",
  [string]$UpdatePackPath = "",
  [string]$Secret = "",
  [string]$SecretFile = "",
  [string]$KeyringFile = "",
  [switch]$StrictHealth,
  [switch]$SkipDependencyInstall,
  [switch]$SkipTaskInstall,
  [switch]$SkipBindCheck,
  [switch]$SkipManifestVerification
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

function Stop-ArqonTaskIfExists {
  param([string]$TaskName)
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($null -eq $task) {
    return
  }
  try {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  } catch {
    # no-op
  }
}

function Invoke-Installer {
  param(
    [string]$ProjectRootPath,
    [string]$ConfigPathValue,
    [string]$PythonPathValue,
    [bool]$SkipDeps,
    [bool]$SkipTasks,
    [bool]$StrictCheck,
    [bool]$SkipBind
  )

  $installerScript = Resolve-ExistingPath -PathValue (Join-Path $ProjectRootPath "scripts\install_arqon.ps1") -Description "Installer script"
  $args = @(
    "-ProjectRoot", $ProjectRootPath,
    "-ConfigPath", $ConfigPathValue
  )
  if (-not [string]::IsNullOrWhiteSpace($PythonPathValue)) {
    $args += @("-PythonPath", $PythonPathValue)
  }
  if ($SkipDeps) {
    $args += "-SkipDependencyInstall"
  }
  if ($SkipTasks) {
    $args += "-SkipTaskInstall"
  }
  if ($StrictCheck) {
    $args += "-StrictHealth"
  }
  if ($SkipBind) {
    $args += "-SkipBindCheck"
  }

  & $installerScript @args
  if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {
    throw "install_arqon.ps1 failed with exit code $LASTEXITCODE"
  }
}

$projectRootResolved = Resolve-ExistingPath -PathValue $ProjectRoot -Description "Project root" -Directory
$sourceRootResolved = Resolve-ExistingPath -PathValue $SourceRoot -Description "Source root" -Directory

$configResolved = $ConfigPath
if ([string]::IsNullOrWhiteSpace($configResolved)) {
  $configResolved = Join-Path $projectRootResolved "config\default.yml"
}
if (-not [System.IO.Path]::IsPathRooted($configResolved)) {
  $configResolved = Join-Path $projectRootResolved $configResolved
}
$configResolved = Resolve-ExistingPath -PathValue $configResolved -Description "Config file"

$backupRootResolved = $BackupRoot
if ([string]::IsNullOrWhiteSpace($backupRootResolved)) {
  $backupRootResolved = Join-Path $projectRootResolved "backups"
}
if (-not [System.IO.Path]::IsPathRooted($backupRootResolved)) {
  $backupRootResolved = Join-Path $projectRootResolved $backupRootResolved
}
if (-not (Test-Path -Path $backupRootResolved -PathType Container)) {
  New-Item -Path $backupRootResolved -ItemType Directory -Force | Out-Null
}
$backupRootResolved = (Resolve-Path -Path $backupRootResolved).Path

$sourceCli = Join-Path $sourceRootResolved "src\arqon_guardian\cli.py"
if (-not (Test-Path -Path $sourceCli -PathType Leaf)) {
  throw "Source root does not look like ARQON project: missing src\\arqon_guardian\\cli.py"
}

$pythonResolved = Resolve-AnyPython -ProjectRootPath $projectRootResolved -ExplicitPython $PythonPath
if (-not $SkipManifestVerification) {
  $packCandidate = $UpdatePackPath
  if ([string]::IsNullOrWhiteSpace($packCandidate)) {
    $packCandidate = Join-Path $sourceRootResolved "update.pack.json"
  } elseif (-not [System.IO.Path]::IsPathRooted($packCandidate)) {
    $packCandidate = Join-Path $sourceRootResolved $packCandidate
  }
  $packResolved = Resolve-ExistingPath -PathValue $packCandidate -Description "Update pack file"

  Write-Host "Verifying signed update pack: $packResolved"
  $prevPythonPath = $env:PYTHONPATH
  $env:PYTHONPATH = Join-Path $projectRootResolved "src"
  try {
    $verifyArgs = @(
      "-m", "arqon_guardian.cli",
      "--config", $configResolved,
      "update-pack", "verify",
      "--pack", $packResolved,
      "--source-root", $sourceRootResolved
    )
    if (-not [string]::IsNullOrWhiteSpace($Secret)) {
      $verifyArgs += @("--secret", $Secret)
    }
    if (-not [string]::IsNullOrWhiteSpace($SecretFile)) {
      $verifyArgs += @("--secret-file", $SecretFile)
    }
    if (-not [string]::IsNullOrWhiteSpace($KeyringFile)) {
      $verifyArgs += @("--keyring-file", $KeyringFile)
    }
    & $pythonResolved @verifyArgs
    if ($LASTEXITCODE -ne $null -and [int]$LASTEXITCODE -ne 0) {
      throw "Update pack verification failed with exit code $LASTEXITCODE"
    }
  } finally {
    $env:PYTHONPATH = $prevPythonPath
  }
}

$backupId = "backup-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$backupPath = Join-Path $backupRootResolved $backupId
New-Item -Path $backupPath -ItemType Directory -Force | Out-Null

Write-Host "Creating backup snapshot: $backupPath"
foreach ($artifact in $script:ArtifactList) {
  $sourceCurrent = Join-Path $projectRootResolved $artifact
  if (-not (Test-Path -Path $sourceCurrent)) {
    continue
  }
  $targetBackup = Join-Path $backupPath $artifact
  Copy-Artifact -SourcePath $sourceCurrent -DestinationPath $targetBackup
}

$manifest = @{
  backup_id = $backupId
  created_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  project_root = $projectRootResolved
  source_root = $sourceRootResolved
  artifacts = $script:ArtifactList
}
($manifest | ConvertTo-Json -Depth 5) | Set-Content -Path (Join-Path $backupPath "backup-manifest.json") -Encoding UTF8

Stop-ArqonTaskIfExists -TaskName "ARQONAgent"
Stop-ArqonTaskIfExists -TaskName "ARQONTray"

$updateCompleted = $false
try {
  Write-Host "Applying update from: $sourceRootResolved"
  foreach ($artifact in $script:ArtifactList) {
    $sourceArtifact = Join-Path $sourceRootResolved $artifact
    if (-not (Test-Path -Path $sourceArtifact)) {
      continue
    }
    $targetArtifact = Join-Path $projectRootResolved $artifact
    Copy-Artifact -SourcePath $sourceArtifact -DestinationPath $targetArtifact
  }

  Invoke-Installer `
    -ProjectRootPath $projectRootResolved `
    -ConfigPathValue $configResolved `
    -PythonPathValue $PythonPath `
    -SkipDeps ([bool]$SkipDependencyInstall) `
    -SkipTasks ([bool]$SkipTaskInstall) `
    -StrictCheck ([bool]$StrictHealth) `
    -SkipBind ([bool]$SkipBindCheck)

  $updateCompleted = $true
  Write-Host "ARQON update completed successfully."
  Write-Host "Backup snapshot: $backupPath"
} catch {
  Write-Warning "Update failed: $($_.Exception.Message)"
  Write-Warning "Starting rollback from backup: $backupPath"

  foreach ($artifact in $script:ArtifactList) {
    $backupArtifact = Join-Path $backupPath $artifact
    if (-not (Test-Path -Path $backupArtifact)) {
      continue
    }
    $targetArtifact = Join-Path $projectRootResolved $artifact
    Copy-Artifact -SourcePath $backupArtifact -DestinationPath $targetArtifact
  }

  try {
    Invoke-Installer `
      -ProjectRootPath $projectRootResolved `
      -ConfigPathValue $configResolved `
      -PythonPathValue $PythonPath `
      -SkipDeps $true `
      -SkipTasks ([bool]$SkipTaskInstall) `
      -StrictCheck $false `
      -SkipBind ([bool]$SkipBindCheck)
  } catch {
    Write-Warning "Post-rollback installer failed: $($_.Exception.Message)"
  }

  throw
}

if (-not $updateCompleted) {
  throw "Update did not complete"
}
