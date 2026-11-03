param(
  [switch] $SkipWingetInstall
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "windows-toolchain.ps1")

function Get-OptionalDeveloperCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Name
  )

  $resolved = Resolve-DeveloperCommand -Name $Name
  if ($resolved.present) {
    return $resolved
  }
  return $null
}

function Assert-Winget {
  $winget = Get-Command "winget" -ErrorAction SilentlyContinue
  if (-not $winget -or -not $winget.Source) {
    throw "winget is required for automatic Rust installation. Install rustup manually or set AEGIS_CARGO_PATH/AEGIS_RUSTC_PATH/AEGIS_RUSTUP_PATH."
  }
  return $winget.Source
}

function Install-RustupWithWinget {
  $wingetPath = Assert-Winget
  Write-Host "Installing Rustup with winget..."
  Invoke-CheckedCommand -Path $wingetPath -Arguments @(
    "install",
    "--id",
    "Rustlang.Rustup",
    "--exact",
    "--silent",
    "--accept-package-agreements",
    "--accept-source-agreements",
    "--disable-interactivity"
  )
}

Push-Location (Resolve-Path "$PSScriptRoot\..")
try {
  $rustup = Get-OptionalDeveloperCommand "rustup"
  if (-not $rustup -and -not $SkipWingetInstall) {
    Install-RustupWithWinget
    $rustup = Get-OptionalDeveloperCommand "rustup"
  }

  if (-not $rustup) {
    throw "rustup was not found after bootstrap. Reopen PowerShell or set AEGIS_RUSTUP_PATH to the rustup.exe location."
  }

  Write-Host "rustup path: $($rustup.path)"
  Invoke-CheckedCommand -Path $rustup.path -Arguments @("--version")

  Write-Host "Installing stable MSVC Rust toolchain..."
  Invoke-CheckedCommand -Path $rustup.path -Arguments @("toolchain", "install", "stable-x86_64-pc-windows-msvc", "--profile", "minimal")
  Invoke-CheckedCommand -Path $rustup.path -Arguments @("default", "stable-x86_64-pc-windows-msvc")
  Invoke-CheckedCommand -Path $rustup.path -Arguments @("component", "add", "rustfmt", "--toolchain", "stable-x86_64-pc-windows-msvc")
  Invoke-CheckedCommand -Path $rustup.path -Arguments @("target", "add", "x86_64-pc-windows-msvc", "--toolchain", "stable-x86_64-pc-windows-msvc")

  $cargo = Resolve-RequiredDeveloperCommand "cargo"
  $rustc = Resolve-RequiredDeveloperCommand "rustc"
  Add-ResolvedCommandToProcessPath $rustup
  Add-ResolvedCommandToProcessPath $cargo
  Add-ResolvedCommandToProcessPath $rustc
  Write-Host "cargo path: $($cargo.path)"
  Invoke-CheckedCommand -Path $cargo.path -Arguments @("--version")
  Write-Host "rustc path: $($rustc.path)"
  Invoke-CheckedCommand -Path $rustc.path -Arguments @("--version")
  Write-Host "Windows Rust bootstrap completed."
}
finally {
  Pop-Location
}
