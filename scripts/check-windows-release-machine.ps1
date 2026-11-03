param(
  [string] $ReportPath = "release\windows-release-machine-check.json",
  [switch] $Json
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "windows-toolchain.ps1")

function Test-CommandAvailable {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Name
  )

  $command = Resolve-DeveloperCommand -Name $Name
  if (-not $command.present) {
    return [ordered]@{
      name = $Name
      present = $false
      path = $null
      source = $null
      version = $null
      valid = $false
      issue = "command not found"
      searched_paths = $command.searched_paths
    }
  }

  $version = $null
  $valid = $true
  $issue = $null
  try {
    if ($Name -eq "node") {
      $version = (& $command.path --version) -join "`n"
      if (-not (Test-NodeVersionSupported $version)) {
        $valid = $false
        $issue = "Node must be >=20.19.0 or >=22.12.0 for Vite 8"
      }
    } elseif ($Name -eq "npm.cmd") {
      $version = (& $command.path --version) -join "`n"
    } elseif ($Name -eq "rustc") {
      $version = (& $command.path --version) -join "`n"
    } elseif ($Name -eq "cargo") {
      $version = (& $command.path --version) -join "`n"
    } elseif ($Name -eq "signtool.exe") {
      $version = "signtool.exe found"
    }
  } catch {
    $version = "version check failed: $($_.Exception.Message)"
    $valid = $false
    $issue = "version check failed"
  }

  return [ordered]@{
    name = $Name
    present = $true
    path = $command.path
    source = $command.source
    version = $version
    valid = $valid
    issue = $issue
    searched_paths = $command.searched_paths
  }
}

function ConvertTo-VersionParts {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Version
  )

  $clean = $Version.Trim().TrimStart("v")
  $parts = $clean.Split(".")
  if ($parts.Length -lt 3) {
    return $null
  }

  try {
    return [int[]] @($parts[0], $parts[1], ($parts[2] -replace "[^0-9].*$", ""))
  } catch {
    return $null
  }
}

function Test-VersionAtLeast {
  param(
    [Parameter(Mandatory = $true)]
    [int[]] $Actual,
    [Parameter(Mandatory = $true)]
    [int[]] $Minimum
  )

  for ($index = 0; $index -lt 3; $index++) {
    if ($Actual[$index] -gt $Minimum[$index]) {
      return $true
    }
    if ($Actual[$index] -lt $Minimum[$index]) {
      return $false
    }
  }
  return $true
}

function Test-NodeVersionSupported {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Version
  )

  $actual = ConvertTo-VersionParts $Version
  if (-not $actual) {
    return $false
  }

  $node20Minimum = [int[]] @(20, 19, 0)
  $node22Minimum = [int[]] @(22, 12, 0)
  return (($actual[0] -eq 20 -and (Test-VersionAtLeast -Actual $actual -Minimum $node20Minimum)) -or
    ($actual[0] -ge 22 -and (Test-VersionAtLeast -Actual $actual -Minimum $node22Minimum)))
}

function Test-VisualCppBuildTools {
  $programFilesX86 = ${env:ProgramFiles(x86)}
  $vswherePath = if ($programFilesX86) {
    Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
  } else {
    $null
  }

  if (-not $vswherePath -or -not (Test-Path -LiteralPath $vswherePath)) {
    return [ordered]@{
      name = "visual_cpp_build_tools"
      present = $false
      path = $null
      version = $null
      valid = $false
      issue = "vswhere.exe not found; install Visual Studio Build Tools with Desktop development with C++"
    }
  }

  $installationPath = (& $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) -join "`n"
  if (-not $installationPath) {
    return [ordered]@{
      name = "visual_cpp_build_tools"
      present = $false
      path = $vswherePath
      version = $null
      valid = $false
      issue = "VC++ x86/x64 tools component is not installed"
    }
  }

  return [ordered]@{
    name = "visual_cpp_build_tools"
    present = $true
    path = $installationPath
    version = "VC++ x86/x64 tools component found"
    valid = $true
    issue = $null
  }
}

function Convert-ToRepoRelativePath {
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

Push-Location (Resolve-Path "$PSScriptRoot\..")
try {
  $root = (Get-Location).Path
  $requiredCommands = @("node", "npm.cmd", "rustc", "cargo")
  $optionalCommands = @("signtool.exe")
  $required = @($requiredCommands | ForEach-Object { Test-CommandAvailable $_ })
  $required += Test-VisualCppBuildTools
  $optional = @($optionalCommands | ForEach-Object { Test-CommandAvailable $_ })
  $missingRequired = @($required | Where-Object { -not $_.present })
  $invalidRequired = @($required | Where-Object { $_.present -and -not $_.valid })
  $missingOptional = @($optional | Where-Object { -not $_.present })
  $isWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT

  $report = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    os_platform = [System.Environment]::OSVersion.Platform.ToString()
    os_version = [System.Environment]::OSVersion.VersionString
    is_windows = $isWindows
    passed = $isWindows -and $missingRequired.Count -eq 0 -and $invalidRequired.Count -eq 0
    required = $required
    optional = $optional
    missing_required = @($missingRequired | ForEach-Object { $_.name })
    invalid_required = @($invalidRequired | ForEach-Object { $_.name })
    missing_optional = @($missingOptional | ForEach-Object { $_.name })
    next_steps = @(
      "Install Rust with rustup or set AEGIS_CARGO_PATH and AEGIS_RUSTC_PATH to explicit tool locations.",
      "Install Node >=20.19.0 or >=22.12.0, or set AEGIS_NODE_PATH and AEGIS_NPM_PATH to explicit tool locations.",
      "Install Microsoft Visual Studio Build Tools with Desktop development with C++ workload.",
      "Install Windows SDK or Visual Studio components that provide signtool.exe, or set AEGIS_SIGNTOOL_PATH before signing release artifacts.",
      "Run npm run verify:windows, npm run bundle:windows, installer smoke tests, signature verification, and release:audit -- --strict on the prepared release machine."
    )
  }

  if ($ReportPath) {
    $resolvedReportPath = Resolve-InRepoPath -Root $root -Path $ReportPath -Label "Machine check report"
    $reportDir = Split-Path -Parent $resolvedReportPath
    New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
    $report | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $resolvedReportPath
  }

  if ($Json) {
    $report | ConvertTo-Json -Depth 6
  } else {
    $status = "failed"
    if ($report.passed) {
      $status = "passed"
    }
    Write-Host "Windows release machine check: $status"
    Write-Host "OS: $($report.os_version)"
    Write-Host "Missing required: $($report.missing_required -join ', ')"
    Write-Host "Invalid required: $($report.invalid_required -join ', ')"
    Write-Host "Missing optional: $($report.missing_optional -join ', ')"
    if ($ReportPath) {
      Write-Host "Report: $(Convert-ToRepoRelativePath -Path $resolvedReportPath -Root $root)"
    }
  }

  if (-not $report.passed) {
    exit 2
  }
}
finally {
  Pop-Location
}
