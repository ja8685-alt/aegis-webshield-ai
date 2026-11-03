param(
  [switch] $Bundle
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "windows-toolchain.ps1")

function ConvertTo-VersionParts {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Version
  )

  $clean = $Version.Trim().TrimStart("v")
  $parts = $clean.Split(".")
  if ($parts.Length -lt 3) {
    throw "Unable to parse semantic version: $Version"
  }

  return [int[]] @($parts[0], $parts[1], ($parts[2] -replace "[^0-9].*$", ""))
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

function Assert-Node-Version {
  param(
    [Parameter(Mandatory = $true)]
    [string] $NodePath
  )

  $nodeVersion = (& $NodePath --version) -join "`n"
  $actual = ConvertTo-VersionParts $nodeVersion
  $node20Minimum = [int[]] @(20, 19, 0)
  $node22Minimum = [int[]] @(22, 12, 0)

  if (($actual[0] -eq 20 -and (Test-VersionAtLeast -Actual $actual -Minimum $node20Minimum)) -or
      ($actual[0] -ge 22 -and (Test-VersionAtLeast -Actual $actual -Minimum $node22Minimum))) {
    Write-Host "node $nodeVersion"
    return
  }

  throw "Node $nodeVersion is not supported. Use Node >=20.19.0 or >=22.12.0 for Vite 8."
}

Push-Location (Resolve-Path "$PSScriptRoot\..")
try {
  $cargo = Resolve-RequiredDeveloperCommand "cargo"
  $rustc = Resolve-RequiredDeveloperCommand "rustc"
  $node = Resolve-RequiredDeveloperCommand "node"
  $npm = Resolve-RequiredDeveloperCommand "npm.cmd"
  Add-ResolvedCommandToProcessPath $cargo
  Add-ResolvedCommandToProcessPath $rustc
  Add-ResolvedCommandToProcessPath $node
  Add-ResolvedCommandToProcessPath $npm

  Write-Host "== Rust =="
  Write-Host "rustc path: $($rustc.path)"
  & $rustc.path --version
  Write-Host "cargo path: $($cargo.path)"
  & $cargo.path --version

  Write-Host "== Node =="
  Write-Host "node path: $($node.path)"
  Assert-Node-Version -NodePath $node.path
  Write-Host "npm path: $($npm.path)"
  & $npm.path --version

  Write-Host "== Frontend build =="
  Invoke-CheckedCommand -Path $npm.path -Arguments @("run", "build")

  Write-Host "== Formatting =="
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("fmt", "--all", "--check")

  Write-Host "== Workspace checks =="
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-ai")
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-core")
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-crawler")
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-cli")
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-openapi")
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-scanner")
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-secrets")
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-storage")
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-triage")
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("test", "-p", "aegis-urlseed")

  Write-Host "== Windows Credential Manager compile check =="
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("check", "-p", "aegis-secrets", "--target", "x86_64-pc-windows-msvc")

  Write-Host "== Tauri app compile check =="
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("check", "-p", "aegis-webshield-ai")

  if ($Bundle) {
    Write-Host "== Tauri bundle build =="
    Invoke-CheckedCommand -Path $npm.path -Arguments @("run", "tauri", "--", "build")
  }

  Write-Host "Windows native verification completed."
}
finally {
  Pop-Location
}
