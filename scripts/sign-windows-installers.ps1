param(
  [Parameter(Mandatory = $true)]
  [string] $CertificateThumbprint,
  [Parameter(Mandatory = $true)]
  [string] $TimestampUrl,
  [string] $CertificateStore = "My",
  [switch] $MachineStore,
  [string] $ArtifactDir = "target\release\bundle",
  [string] $ReportPath = "release\signature-verification.json",
  [switch] $ForceResign,
  [switch] $DryRun
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

function Test-CodeSigningEku {
  param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
  )

  $ekuExtension = $Certificate.Extensions |
    Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
    Select-Object -First 1
  if (-not $ekuExtension) {
    return $false
  }
  $typedExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExtension
  return [bool]($typedExtension.EnhancedKeyUsages | Where-Object { $_.Value -eq "1.3.6.1.5.5.7.3.3" })
}

Push-Location (Resolve-Path "$PSScriptRoot\..")
try {
  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "Windows installer signing must run on Windows PowerShell."
  }

  $root = (Get-Location).Path
  $thumbprint = ($CertificateThumbprint -replace "\s", "").ToUpperInvariant()
  if ($thumbprint -notmatch "^[A-F0-9]{40}$") {
    throw "CertificateThumbprint must be exactly 40 hexadecimal characters."
  }
  if ($CertificateStore -notmatch "^[A-Za-z0-9_-]{1,64}$") {
    throw "CertificateStore contains unsupported characters."
  }

  $timestampUri = $null
  if (-not [System.Uri]::TryCreate($TimestampUrl, [System.UriKind]::Absolute, [ref]$timestampUri) `
      -or $timestampUri.Scheme -ne "https" `
      -or $timestampUri.HostNameType -ne [System.UriHostNameType]::Dns `
      -or -not $timestampUri.Host.Contains(".") `
      -or $timestampUri.Host -eq "localhost" `
      -or $timestampUri.Host.EndsWith(".local") `
      -or $timestampUri.UserInfo `
      -or $timestampUri.Query `
      -or $timestampUri.Fragment) {
    throw "TimestampUrl must be a public HTTPS URL without credentials, query, or fragment."
  }

  . "$PSScriptRoot\windows-toolchain.ps1"
  $signTool = Resolve-RequiredDeveloperCommand -Name "signtool.exe"
  $resolvedArtifactDir = Resolve-InstallerArtifactDirectory -Root $root -Path $ArtifactDir
  $resolvedReportPath = Resolve-InRepoPath -Root $root -Path $ReportPath -Label "Signature verification report"
  $packageVersion = (Get-Content -Raw -LiteralPath (Join-Path $root "package.json") | ConvertFrom-Json).version
  $artifacts = @(Get-ChildItem -LiteralPath $resolvedArtifactDir.FullName -Recurse -File |
      Where-Object { $_.Extension -match "^\.(msi|exe)$" -and $_.Name -like "*_$packageVersion`_*" } |
      Sort-Object FullName)
  $msiArtifacts = @($artifacts | Where-Object { $_.Extension -ieq ".msi" })
  $nsisArtifacts = @($artifacts | Where-Object { $_.Extension -ieq ".exe" -and $_.FullName -match "\\nsis\\" })
  if ($msiArtifacts.Count -eq 0 -or $nsisArtifacts.Count -eq 0) {
    throw "Current version $packageVersion requires both MSI and NSIS installer artifacts."
  }

  $storeLocation = if ($MachineStore) { "LocalMachine" } else { "CurrentUser" }
  $certificatePath = "Cert:\$storeLocation\$CertificateStore\$thumbprint"
  $certificate = Get-Item -LiteralPath $certificatePath -ErrorAction SilentlyContinue
  if (-not $certificate) {
    throw "Code-signing certificate was not found in $storeLocation/$CertificateStore for the supplied thumbprint."
  }
  $now = Get-Date
  if (-not $certificate.HasPrivateKey) {
    throw "The selected code-signing certificate does not expose a private key."
  }
  if ($certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) {
    throw "The selected code-signing certificate is not currently valid."
  }
  if (-not (Test-CodeSigningEku -Certificate $certificate)) {
    throw "The selected certificate does not include the Code Signing EKU."
  }

  $signedCount = 0
  $skippedCount = 0
  foreach ($artifact in $artifacts) {
    $existing = Get-AuthenticodeSignature -FilePath $artifact.FullName
    $existingThumbprint = if ($existing.SignerCertificate) {
      $existing.SignerCertificate.Thumbprint.ToUpperInvariant()
    } else {
      $null
    }
    if ($existing.Status -eq "Valid" -and $existingThumbprint -eq $thumbprint) {
      Write-Host "Already signed: $(Convert-To-RepoRelativePath -Path $artifact.FullName -Root $root)"
      $skippedCount += 1
      continue
    }
    if ($existing.Status -ne "NotSigned" -and -not $ForceResign) {
      throw "Artifact already has a non-matching or invalid signature; use -ForceResign only after review: $(Convert-To-RepoRelativePath -Path $artifact.FullName -Root $root)"
    }

    if ($DryRun) {
      Write-Host "Would sign: $(Convert-To-RepoRelativePath -Path $artifact.FullName -Root $root)"
      continue
    }

    $signArguments = @("sign", "/sha1", $thumbprint, "/s", $CertificateStore)
    if ($MachineStore) {
      $signArguments += "/sm"
    }
    $signArguments += @(
      "/fd",
      "SHA256",
      "/tr",
      $timestampUri.AbsoluteUri,
      "/td",
      "SHA256",
      $artifact.FullName
    )
    Invoke-CheckedCommand -Path $signTool.path -Arguments $signArguments

    $verified = Get-AuthenticodeSignature -FilePath $artifact.FullName
    $verifiedThumbprint = if ($verified.SignerCertificate) {
      $verified.SignerCertificate.Thumbprint.ToUpperInvariant()
    } else {
      $null
    }
    if ($verified.Status -ne "Valid" -or $verifiedThumbprint -ne $thumbprint) {
      throw "Authenticode verification failed immediately after signing: $(Convert-To-RepoRelativePath -Path $artifact.FullName -Root $root)"
    }
    $signedCount += 1
  }

  if (-not $DryRun) {
    $verifyScript = Join-Path $PSScriptRoot "verify-windows-signatures.ps1"
    & powershell.exe `
      -NoProfile `
      -ExecutionPolicy Bypass `
      -File $verifyScript `
      -ArtifactDir (Convert-To-RepoRelativePath -Path $resolvedArtifactDir.FullName -Root $root) `
      -ReportPath (Convert-To-RepoRelativePath -Path $resolvedReportPath -Root $root)
    if ($LASTEXITCODE -ne 0) {
      throw "Post-signing signature verification failed with exit code $LASTEXITCODE."
    }
  }

  Write-Host "Windows installer signing completed."
  Write-Host "Version: $packageVersion"
  Write-Host "Artifacts selected: $($artifacts.Count)"
  Write-Host "Artifacts signed: $signedCount"
  Write-Host "Artifacts already valid: $skippedCount"
  Write-Host "Dry run: $([bool]$DryRun)"
  if (-not $DryRun) {
    Write-Host "Verification report: $(Convert-To-RepoRelativePath -Path $resolvedReportPath -Root $root)"
  }
}
finally {
  Pop-Location
}
