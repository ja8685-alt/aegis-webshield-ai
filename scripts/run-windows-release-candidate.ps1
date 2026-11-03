param(
  [switch] $SkipBundle,
  [switch] $SkipSignatureVerification,
  [string] $SigningCertificateThumbprint = "",
  [string] $SigningTimestampUrl = "",
  [string] $SigningCertificateStore = "My",
  [switch] $SigningMachineStore,
  [switch] $SkipInstallerSmoke,
  [switch] $SkipAppSmokeResult,
  [switch] $SkipSmartScreenPackage,
  [switch] $StrictAudit,
  [string] $AppSmokeReportPath = "",
  [string] $MsiAppSmokeReportPath = "",
  [string] $NsisAppSmokeReportPath = "",
  [string] $SupportDiagnosticsPath = "",
  [string] $SmartScreenTrackerPath = "",
  [string] $UpdateBaseUrl = "",
  [ValidateSet("msi", "nsis")]
  [string] $UpdateArtifact = "nsis",
  [ValidateSet("stable", "beta", "internal")]
  [string] $UpdateChannel = "stable",
  [string] $UpdateManifestPath = "",
  [ValidateRange(10, 1800)]
  [int] $InstallerSmokeProcessTimeoutSeconds = 300,
  [string] $ReportPath = "release\windows-release-candidate-run.json"
)

$ErrorActionPreference = "Stop"
$stepResults = @()
$flowStartedAt = Get-Date
$flowError = $null

function Invoke-Step {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Name,
    [Parameter(Mandatory = $true)]
    [string] $Command,
    [Parameter(Mandatory = $true)]
    [string[]] $Arguments
  )

  Write-Host "== $Name =="
  $startedAt = Get-Date
  $process = Start-Process `
    -FilePath $Command `
    -ArgumentList $Arguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden
  $endedAt = Get-Date
  $script:stepResults += [ordered]@{
    name = $Name
    status = if ($process.ExitCode -eq 0) { "passed" } else { "failed" }
    command = $Command
    arguments = $Arguments
    exit_code = $process.ExitCode
    started_at = $startedAt.ToUniversalTime().ToString("o")
    ended_at = $endedAt.ToUniversalTime().ToString("o")
    duration_ms = [int]($endedAt - $startedAt).TotalMilliseconds
  }
  if ($process.ExitCode -ne 0) {
    throw "$Name failed with exit code $($process.ExitCode)"
  }
}

function Add-SkippedStep {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Name
  )

  $now = (Get-Date).ToUniversalTime().ToString("o")
  $script:stepResults += [ordered]@{
    name = $Name
    status = "skipped"
    command = $null
    arguments = @()
    exit_code = $null
    started_at = $now
    ended_at = $now
    duration_ms = 0
  }
  Write-Host "== $Name skipped =="
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

  $normalized = $Path.Replace("\", "/")
  if ([System.IO.Path]::IsPathRooted($Path) `
      -or $normalized.StartsWith("/") `
      -or @($normalized.Split("/") | Where-Object { -not $_ -or $_ -eq "." -or $_ -eq ".." }).Count -gt 0) {
    throw "$Label must be a safe repository-relative path: $Path"
  }

  $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar
  $candidate = [System.IO.Path]::GetFullPath((Join-Path $Root $Path))

  if (-not $candidate.StartsWith($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label path must stay inside the repository: $Path"
  }

  return $candidate
}

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

function Write-RunReport {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Root
  )

  if (-not $ReportPath) {
    return
  }
  $endedAt = Get-Date
  $failedSteps = @($script:stepResults | Where-Object { $_.status -eq "failed" })
  $report = [ordered]@{
    generated_at = $endedAt.ToUniversalTime().ToString("o")
    started_at = $flowStartedAt.ToUniversalTime().ToString("o")
    ended_at = $endedAt.ToUniversalTime().ToString("o")
    duration_ms = [int]($endedAt - $flowStartedAt).TotalMilliseconds
    strict_audit = [bool]$StrictAudit
    passed = $null -eq $script:flowError -and $failedSteps.Count -eq 0
    error = $script:flowError
    step_count = $script:stepResults.Count
    failed_step_count = $failedSteps.Count
    steps = $script:stepResults
  }
  $resolvedReportPath = Resolve-InRepoPath -Root $Root -Path $ReportPath -Label "Run report"
  $reportDir = Split-Path -Parent $resolvedReportPath
  New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
  $report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $resolvedReportPath
  Write-Host "Run report: $ReportPath"
}

function Resolve-AppSmokeReportPaths {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Root
  )

  $reports = [ordered]@{
    msi = $null
    nsis = $null
  }
  if ($MsiAppSmokeReportPath) {
    $resolved = Resolve-InRepoPath -Root $Root -Path $MsiAppSmokeReportPath -Label "MSI app smoke report"
    $reports.msi = Convert-To-RepoRelativePath -Path $resolved -Root $Root
  }
  if ($NsisAppSmokeReportPath) {
    $resolved = Resolve-InRepoPath -Root $Root -Path $NsisAppSmokeReportPath -Label "NSIS app smoke report"
    $reports.nsis = Convert-To-RepoRelativePath -Path $resolved -Root $Root
  }
  if ($AppSmokeReportPath) {
    $resolved = Resolve-InRepoPath -Root $Root -Path $AppSmokeReportPath -Label "App smoke report"
    $legacyReport = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json
    if ($legacyReport.installer -notin @("msi", "nsis")) {
      throw "AppSmokeReportPath must contain installer msi or nsis."
    }
    $reports[$legacyReport.installer] = Convert-To-RepoRelativePath -Path $resolved -Root $Root
    return $reports
  }

  $appSmokeDir = Join-Path $Root "release\app-smoke"
  if (-not (Test-Path -LiteralPath $appSmokeDir)) {
    return $reports
  }
  $packageVersion = (Get-Content -Raw -LiteralPath (Join-Path $Root "package.json") | ConvertFrom-Json).version
  foreach ($installer in @("msi", "nsis")) {
    if ($reports[$installer]) {
      continue
    }
    $latestReport = Get-ChildItem -LiteralPath $appSmokeDir -Filter "app-smoke-*.json" -File |
      Sort-Object LastWriteTimeUtc -Descending |
      Where-Object {
        try {
          $value = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
          return $value.installer -eq $installer -and $value.version -eq $packageVersion
        } catch {
          return $false
        }
      } |
      Select-Object -First 1
    if ($latestReport) {
      $reports[$installer] = Convert-To-RepoRelativePath -Path $latestReport.FullName -Root $Root
    }
  }
  return $reports
}

Push-Location (Resolve-Path "$PSScriptRoot\..")
try {
  $root = (Get-Location).Path
  if ($ReportPath) {
    [void](Resolve-InRepoPath -Root $root -Path $ReportPath -Label "Run report")
  }
  if ($AppSmokeReportPath) {
    [void](Resolve-InRepoPath -Root $root -Path $AppSmokeReportPath -Label "App smoke report")
  }
  if ($MsiAppSmokeReportPath) {
    [void](Resolve-InRepoPath -Root $root -Path $MsiAppSmokeReportPath -Label "MSI app smoke report")
  }
  if ($NsisAppSmokeReportPath) {
    [void](Resolve-InRepoPath -Root $root -Path $NsisAppSmokeReportPath -Label "NSIS app smoke report")
  }
  if ($AppSmokeReportPath -and ($MsiAppSmokeReportPath -or $NsisAppSmokeReportPath)) {
    throw "AppSmokeReportPath cannot be combined with installer-specific app smoke paths."
  }
  if ($SmartScreenTrackerPath) {
    [void](Resolve-InRepoPath -Root $root -Path $SmartScreenTrackerPath -Label "SmartScreen tracker")
  }
  if ($SigningCertificateThumbprint -and -not $SigningTimestampUrl) {
    throw "SigningTimestampUrl is required when SigningCertificateThumbprint is set."
  }
  if (-not $SigningCertificateThumbprint -and ($SigningTimestampUrl -or $SigningMachineStore)) {
    throw "SigningCertificateThumbprint is required when signing options are set."
  }
  if ($SkipSignatureVerification -and $SigningCertificateThumbprint) {
    throw "Signing options cannot be combined with SkipSignatureVerification."
  }
  $packageVersion = (Get-Content -Raw -LiteralPath (Join-Path $root "package.json") | ConvertFrom-Json).version
  $effectiveUpdateManifestPath = if ($UpdateManifestPath) {
    $UpdateManifestPath
  } else {
    "release/update-manifest-$packageVersion.json"
  }
  $resolvedUpdateManifestPath = Resolve-InRepoPath `
    -Root $root `
    -Path $effectiveUpdateManifestPath `
    -Label "Update manifest"
  $updateManifestRepoPath = Convert-To-RepoRelativePath -Path $resolvedUpdateManifestPath -Root $root
  if ($UpdateBaseUrl) {
    $updateUri = $null
    if (-not [System.Uri]::TryCreate($UpdateBaseUrl, [System.UriKind]::Absolute, [ref]$updateUri) `
        -or $updateUri.Scheme -ne "https" `
        -or $updateUri.HostNameType -ne [System.UriHostNameType]::Dns `
        -or -not $updateUri.Host.Contains(".") `
        -or $updateUri.Host -eq "localhost" `
        -or $updateUri.Host.EndsWith(".local") `
        -or $updateUri.UserInfo `
        -or $updateUri.Query `
        -or $updateUri.Fragment) {
      throw "UpdateBaseUrl must be a public HTTPS URL without credentials, query, or fragment."
    }
    if (-not $env:AEGIS_RELEASE_SIGNATURE -or $env:AEGIS_RELEASE_SIGNATURE.Trim().Length -lt 32) {
      throw "AEGIS_RELEASE_SIGNATURE must contain the release signature when UpdateBaseUrl is set."
    }
  }
  if ($SupportDiagnosticsPath) {
    $resolvedSupportDiagnosticsPath = Resolve-InRepoPath `
      -Root $root `
      -Path $SupportDiagnosticsPath `
      -Label "Support diagnostics"
    $rootPrefix = [System.IO.Path]::GetFullPath($root).TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar
    $env:AEGIS_SUPPORT_DIAGNOSTICS_PATH = $resolvedSupportDiagnosticsPath.Substring($rootPrefix.Length).Replace("\", "/")
  }
  Invoke-Step "release machine check" "npm.cmd" @("run", "release:machine-check")
  Invoke-Step "RC security/performance" "npm.cmd" @("run", "rc:security-performance")
  Invoke-Step "RC functional E2E" "npm.cmd" @("run", "rc:functional-e2e")
  Invoke-Step "release preflight" "npm.cmd" @("run", "release:preflight")
  Invoke-Step "Windows native verification" "npm.cmd" @("run", "verify:windows")

  if (-not $SkipBundle) {
    Invoke-Step "Windows bundle build" "npm.cmd" @("run", "bundle:windows")
  } else {
    Add-SkippedStep "Windows bundle build"
  }

  if (-not $SkipSignatureVerification) {
    if ($SigningCertificateThumbprint) {
      $signingArguments = @(
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "scripts/sign-windows-installers.ps1",
        "-CertificateThumbprint",
        $SigningCertificateThumbprint,
        "-TimestampUrl",
        $SigningTimestampUrl,
        "-CertificateStore",
        $SigningCertificateStore
      )
      if ($SigningMachineStore) {
        $signingArguments += "-MachineStore"
      }
      Invoke-Step "Windows installer signing" "powershell" $signingArguments
    } else {
      Add-SkippedStep "Windows installer signing"
    }
    Invoke-Step "Windows signature verification" "powershell" @(
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      "scripts/verify-windows-signatures.ps1",
      "-ReportPath",
      "release/signature-verification.json"
    )
  } else {
    Add-SkippedStep "Windows signature verification"
  }

  if (-not $SkipInstallerSmoke) {
    $installerSmokeArguments = @(
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      "scripts/smoke-windows-installer.ps1",
      "-ProcessTimeoutSeconds",
      $InstallerSmokeProcessTimeoutSeconds.ToString()
    )
    if ($StrictAudit) {
      $installerSmokeArguments += @("-InstallMsi", "-InstallNsis")
    }
    Invoke-Step "Windows installer smoke" "powershell" $installerSmokeArguments
  } else {
    Add-SkippedStep "Windows installer smoke"
  }

  if (-not $SkipAppSmokeResult) {
    $resolvedAppSmokeReportPaths = Resolve-AppSmokeReportPaths -Root $root
    foreach ($installer in @("msi", "nsis")) {
      $reportPath = $resolvedAppSmokeReportPaths[$installer]
      if ($reportPath) {
        Invoke-Step "installed app smoke result $installer" "npm.cmd" @(
          "run",
          "verify:app-smoke",
          "--",
          "--file",
          $reportPath
        )
      } elseif ($StrictAudit) {
        Invoke-Step "installed app smoke result $installer" "npm.cmd" @(
          "run",
          "verify:app-smoke",
          "--",
          "--file",
          "release/app-smoke/app-smoke-$packageVersion-$installer-missing.json"
        )
      } else {
        Add-SkippedStep "installed app smoke result $installer"
      }
    }
  } else {
    Add-SkippedStep "installed app smoke result msi"
    Add-SkippedStep "installed app smoke result nsis"
  }

  if ($UpdateBaseUrl) {
    Invoke-Step "update manifest preparation" "npm.cmd" @(
      "run",
      "update:prepare-manifest",
      "--",
      "--artifact",
      $UpdateArtifact,
      "--channel",
      $UpdateChannel,
      "--base-url",
      $UpdateBaseUrl,
      "--out",
      $updateManifestRepoPath
    )
    $env:AEGIS_UPDATE_MANIFEST_PATH = $updateManifestRepoPath
    Invoke-Step "update manifest verification" "npm.cmd" @(
      "run",
      "update:verify-manifest",
      "--",
      "--file",
      $updateManifestRepoPath
    )
  } elseif (Test-Path -LiteralPath $resolvedUpdateManifestPath -PathType Leaf) {
    $env:AEGIS_UPDATE_MANIFEST_PATH = $updateManifestRepoPath
    Invoke-Step "update manifest verification" "npm.cmd" @(
      "run",
      "update:verify-manifest",
      "--",
      "--file",
      $updateManifestRepoPath
    )
  } else {
    Add-SkippedStep "update manifest preparation"
    Add-SkippedStep "update manifest verification"
  }

  Invoke-Step "release prepare" "npm.cmd" @("run", "release:prepare")
  if (-not $SkipSmartScreenPackage) {
    Invoke-Step "SmartScreen package" "npm.cmd" @("run", "smartscreen:prepare")
  } else {
    Add-SkippedStep "SmartScreen package"
  }

  if ($SmartScreenTrackerPath) {
    $resolvedSmartScreenTrackerPath = Resolve-InRepoPath `
      -Root $root `
      -Path $SmartScreenTrackerPath `
      -Label "SmartScreen tracker"
    $smartScreenTrackerRepoPath = Convert-To-RepoRelativePath -Path $resolvedSmartScreenTrackerPath -Root $root
    Invoke-Step "SmartScreen tracker verification" "npm.cmd" @(
      "run",
      "smartscreen:verify-tracker",
      "--",
      "--file",
      $smartScreenTrackerRepoPath
    )
  } else {
    Add-SkippedStep "SmartScreen tracker verification"
  }

  Invoke-Step "release verify" "npm.cmd" @("run", "release:verify")

  if ($StrictAudit) {
    Invoke-Step "release candidate audit strict" "npm.cmd" @("run", "release:audit", "--", "--strict")
  } else {
    Invoke-Step "release candidate audit" "npm.cmd" @("run", "release:audit")
  }

  Write-Host "Windows release candidate flow completed."
}
catch {
  $script:flowError = $_.Exception.Message
  throw
}
finally {
  if ($root) {
    Write-RunReport -Root $root
  }
  Pop-Location
}
