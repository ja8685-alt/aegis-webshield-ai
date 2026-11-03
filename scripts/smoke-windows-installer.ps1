param(
  [string] $ArtifactDir = "target\release\bundle",
  [switch] $InstallMsi,
  [switch] $InstallNsis,
  [switch] $AllowMissingNsis,
  [ValidateRange(10, 1800)]
  [int] $ProcessTimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"

function Convert-To-RepoRelativePath {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Path,
    [Parameter(Mandatory = $true)]
    [string] $Root
  )

  $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar
  $targetPath = [System.IO.Path]::GetFullPath($Path)
  $rootUri = New-Object System.Uri($rootPath)
  $targetUri = New-Object System.Uri($targetPath)
  return [System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($targetUri).ToString()).Replace("\", "/")
}

function Resolve-InRepoPath {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Root,
    [Parameter(Mandatory = $true)]
    [string] $Path,
    [Parameter(Mandatory = $true)]
    [string] $Label
  )

  if (-not $Path.Trim()) {
    throw "$Label path must not be empty"
  }

  $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar
  $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
    [System.IO.Path]::GetFullPath($Path)
  } else {
    [System.IO.Path]::GetFullPath((Join-Path $Root $Path))
  }

  if (-not $candidate.StartsWith($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label path must stay inside the repository: $Path"
  }

  return $candidate
}

function Resolve-InstallerArtifactDirectory {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Root,
    [Parameter(Mandatory = $true)]
    [string] $Path
  )

  $legacyDefault = "src-tauri\target\release\bundle"
  $candidates = @($Path)
  if ($Path -eq "target\release\bundle" -or $Path -eq $legacyDefault) {
    $candidates = @("target\release\bundle", $legacyDefault)
  }

  foreach ($candidate in $candidates) {
    $artifactDirPath = Resolve-InRepoPath -Root $Root -Path $candidate -Label "Installer artifact directory"
    $resolvedArtifactDir = Get-Item -LiteralPath $artifactDirPath -ErrorAction SilentlyContinue
    if ($resolvedArtifactDir -and $resolvedArtifactDir.PSIsContainer) {
      return $resolvedArtifactDir
    }
  }

  throw "Installer artifact directory not found: $($candidates -join ', ')"
}

function Get-MsiProductCode {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Path
  )

  $installer = New-Object -ComObject WindowsInstaller.Installer
  $database = $installer.GetType().InvokeMember(
    "OpenDatabase",
    "InvokeMethod",
    $null,
    $installer,
    @($Path, 0)
  )
  $view = $database.GetType().InvokeMember(
    "OpenView",
    "InvokeMethod",
    $null,
    $database,
    @('SELECT `Value` FROM `Property` WHERE `Property` = ''ProductCode''')
  )
  $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null) | Out-Null
  $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
  if ($null -eq $record) {
    throw "Unable to read MSI ProductCode: $Path"
  }
  return $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 1)
}

function Invoke-HiddenProcess {
  param(
    [Parameter(Mandatory = $true)]
    [string] $FilePath,
    [Parameter(Mandatory = $true)]
    [string[]] $ArgumentList,
    [Parameter(Mandatory = $true)]
    [int] $TimeoutSeconds
  )

  $process = Start-Process `
    -FilePath $FilePath `
    -ArgumentList $ArgumentList `
    -PassThru `
    -WindowStyle Hidden
  if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    $process.WaitForExit()
    throw "$FilePath timed out after $TimeoutSeconds seconds"
  }
  return $process.ExitCode
}

function Find-NsisUninstaller {
  param(
    [Parameter(Mandatory = $true)]
    [string] $InstallDir
  )

  $candidates = @(
    (Join-Path $InstallDir "uninstall.exe"),
    (Join-Path $InstallDir "Uninstall.exe")
  )
  foreach ($candidate in $candidates) {
    if (Test-Path $candidate) {
      return $candidate
    }
  }

  $fallback = Get-ChildItem -Path $InstallDir -File -Filter "*uninstall*.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($fallback) {
    return $fallback.FullName
  }

  throw "Unable to locate NSIS uninstaller under $InstallDir"
}

Push-Location (Resolve-Path "$PSScriptRoot\..")
try {
  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "Windows installer smoke test must run on Windows PowerShell."
  }

  $root = (Get-Location).Path
  $resolvedArtifactDir = Resolve-InstallerArtifactDirectory -Root $root -Path $ArtifactDir
  $packageVersion = (Get-Content -Raw -LiteralPath (Join-Path $root "package.json") | ConvertFrom-Json).version

  $releaseDir = Join-Path $root "release"
  $smokeDir = Join-Path $releaseDir "installer-smoke"
  New-Item -ItemType Directory -Force -Path $smokeDir | Out-Null

  $artifacts = Get-ChildItem -LiteralPath $resolvedArtifactDir.FullName -Recurse -File |
    Where-Object { $_.Extension -match "^\.(msi|exe)$" -and $_.Name -like "*_$packageVersion`_*" } |
    Sort-Object FullName

  if (-not $artifacts) {
    throw "No Windows installer artifacts for version $packageVersion found under $($resolvedArtifactDir.FullName)"
  }

  $msiArtifacts = $artifacts | Where-Object { $_.Extension -ieq ".msi" }
  $nsisArtifacts = $artifacts | Where-Object {
    $_.Extension -ieq ".exe" -and $_.FullName -match "\\nsis\\"
  }

  if (-not $msiArtifacts) {
    throw "No MSI artifact found under $($resolvedArtifactDir.FullName)"
  }
  if (-not $nsisArtifacts -and -not $AllowMissingNsis) {
    throw "No NSIS .exe artifact found under $($resolvedArtifactDir.FullName)"
  }

  $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $artifactResults = @()
  foreach ($artifact in $artifacts) {
    $hash = Get-FileHash -Algorithm SHA256 -Path $artifact.FullName
    $artifactResults += [ordered]@{
      path = Convert-To-RepoRelativePath -Path $artifact.FullName -Root $root
      size_bytes = $artifact.Length
      sha256 = $hash.Hash.ToLowerInvariant()
    }
  }

  $installResults = @()
  $nsisInstallResults = @()
  if ($InstallMsi) {
    foreach ($msi in $msiArtifacts) {
      $productCode = Get-MsiProductCode -Path $msi.FullName
      $installLog = Join-Path $smokeDir "$($msi.BaseName)-install.log"
      $uninstallLog = Join-Path $smokeDir "$($msi.BaseName)-uninstall.log"

      $installExit = Invoke-HiddenProcess -FilePath "msiexec.exe" -ArgumentList @(
        "/i",
        $msi.FullName,
        "/qn",
        "/norestart",
        "/L*v",
        $installLog
      ) -TimeoutSeconds $ProcessTimeoutSeconds
      if ($installExit -notin @(0, 3010)) {
        throw "MSI silent install failed with exit code $installExit. Log: $installLog"
      }

      $uninstallExit = Invoke-HiddenProcess -FilePath "msiexec.exe" -ArgumentList @(
        "/x",
        $productCode,
        "/qn",
        "/norestart",
        "/L*v",
        $uninstallLog
      ) -TimeoutSeconds $ProcessTimeoutSeconds
      if ($uninstallExit -notin @(0, 3010)) {
        throw "MSI silent uninstall failed with exit code $uninstallExit. Log: $uninstallLog"
      }

      $installResults += [ordered]@{
        artifact = Convert-To-RepoRelativePath -Path $msi.FullName -Root $root
        product_code = $productCode
        install_exit_code = $installExit
        uninstall_exit_code = $uninstallExit
        install_log = Convert-To-RepoRelativePath -Path $installLog -Root $root
        uninstall_log = Convert-To-RepoRelativePath -Path $uninstallLog -Root $root
      }
    }
  }

  if ($InstallNsis) {
    foreach ($nsis in $nsisArtifacts) {
      $installDir = Join-Path $smokeDir "nsis-$($nsis.BaseName)-$timestamp"
      New-Item -ItemType Directory -Force -Path $installDir | Out-Null

      $installExit = Invoke-HiddenProcess -FilePath $nsis.FullName -ArgumentList @(
        "/S",
        "/D=$installDir"
      ) -TimeoutSeconds $ProcessTimeoutSeconds
      if ($installExit -notin @(0, 3010)) {
        throw "NSIS silent install failed with exit code $installExit. Install dir: $installDir"
      }

      $uninstaller = Find-NsisUninstaller -InstallDir $installDir
      $uninstallExit = Invoke-HiddenProcess `
        -FilePath $uninstaller `
        -ArgumentList @("/S") `
        -TimeoutSeconds $ProcessTimeoutSeconds
      if ($uninstallExit -notin @(0, 3010)) {
        throw "NSIS silent uninstall failed with exit code $uninstallExit. Uninstaller: $uninstaller"
      }

      $remainingFiles = @(Get-ChildItem -Path $installDir -Recurse -Force -ErrorAction SilentlyContinue)
      $nsisInstallResults += [ordered]@{
        artifact = Convert-To-RepoRelativePath -Path $nsis.FullName -Root $root
        install_dir = Convert-To-RepoRelativePath -Path $installDir -Root $root
        install_exit_code = $installExit
        uninstall_exit_code = $uninstallExit
        uninstaller = Convert-To-RepoRelativePath -Path $uninstaller -Root $root
        remaining_file_count = $remainingFiles.Count
      }
    }
  }

  $report = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    artifact_dir = Convert-To-RepoRelativePath -Path $resolvedArtifactDir.FullName -Root $root
    install_msi = [bool]$InstallMsi
    install_nsis = [bool]$InstallNsis
    allow_missing_nsis = [bool]$AllowMissingNsis
    process_timeout_seconds = $ProcessTimeoutSeconds
    artifacts = $artifactResults
    install_results = $installResults
    nsis_install_results = $nsisInstallResults
  }
  $reportPath = Join-Path $smokeDir "installer-smoke-$timestamp.json"
  $report | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $reportPath

  Write-Host "Windows installer smoke test completed."
  Write-Host "Artifacts checked: $($artifactResults.Count)"
  Write-Host "MSI install smoke: $([bool]$InstallMsi)"
  Write-Host "NSIS install smoke: $([bool]$InstallNsis)"
  Write-Host "Report: $(Convert-To-RepoRelativePath -Path $reportPath -Root $root)"
}
finally {
  Pop-Location
}
