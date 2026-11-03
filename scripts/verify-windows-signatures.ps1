param(
  [string] $ArtifactDir = "target\release\bundle",
  [string] $ReportPath = "",
  [switch] $Json
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
    $resolvedArtifactDir = Resolve-Path $artifactDirPath -ErrorAction SilentlyContinue
    if ($resolvedArtifactDir) {
      return $resolvedArtifactDir
    }
  }

  throw "Installer artifact directory not found: $($candidates -join ', ')"
}

Push-Location (Resolve-Path "$PSScriptRoot\..")
try {
  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "Windows signature verification must run on Windows PowerShell."
  }

  $root = (Get-Location).Path
  $resolvedArtifactDir = Resolve-InstallerArtifactDirectory -Root $root -Path $ArtifactDir
  $packageVersion = (Get-Content -Raw -LiteralPath (Join-Path $root "package.json") | ConvertFrom-Json).version

  $artifacts = Get-ChildItem -Path $resolvedArtifactDir -Recurse -File |
    Where-Object { $_.Extension -match "^\.(msi|exe)$" -and $_.Name -like "*_$packageVersion`_*" } |
    Sort-Object FullName

  if (-not $artifacts) {
    throw "No Windows installer artifacts for version $packageVersion found under $($resolvedArtifactDir.Path)"
  }

  $results = @()
  foreach ($artifact in $artifacts) {
    $signature = Get-AuthenticodeSignature -FilePath $artifact.FullName
    $certificate = $signature.SignerCertificate
    $results += [ordered]@{
      path = Convert-To-RepoRelativePath -Path $artifact.FullName -Root $root
      sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact.FullName).Hash.ToLowerInvariant()
      size_bytes = $artifact.Length
      status = $signature.Status.ToString()
      status_message = $signature.StatusMessage
      signer_subject = if ($certificate) { $certificate.Subject } else { $null }
      signer_thumbprint = if ($certificate) { $certificate.Thumbprint } else { $null }
      certificate_not_before = if ($certificate) { $certificate.NotBefore.ToUniversalTime().ToString("o") } else { $null }
      certificate_not_after = if ($certificate) { $certificate.NotAfter.ToUniversalTime().ToString("o") } else { $null }
    }
  }

  $failed = @($results | Where-Object { $_.status -ne "Valid" })
  $report = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    artifact_dir = Convert-To-RepoRelativePath -Path $resolvedArtifactDir.Path -Root $root
    passed = $failed.Count -eq 0
    checked_artifacts = $results.Count
    failed_artifacts = $failed.Count
    artifacts = $results
  }

  if ($ReportPath) {
    $resolvedReportPath = Resolve-InRepoPath -Root $root -Path $ReportPath -Label "Signature verification report"
    $reportDir = Split-Path -Parent $resolvedReportPath
    New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
    $report | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $resolvedReportPath
  }

  if ($Json) {
    $report | ConvertTo-Json -Depth 6
  } else {
    Write-Host "Windows signature verification completed."
    Write-Host "Artifacts checked: $($results.Count)"
    Write-Host "Invalid signatures: $($failed.Count)"
    if ($ReportPath) {
      Write-Host "Report: $(Convert-To-RepoRelativePath -Path $resolvedReportPath -Root $root)"
    }
  }

  if ($failed.Count -gt 0) {
    exit 2
  }
}
finally {
  Pop-Location
}
