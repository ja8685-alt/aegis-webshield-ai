$ErrorActionPreference = "Stop"

function Get-EnvValue {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Name
  )

  $value = [System.Environment]::GetEnvironmentVariable($Name)
  if ($value -and $value.Trim()) {
    return $value.Trim()
  }
  return $null
}

function Add-CommandCandidate {
  param(
    [System.Collections.ArrayList] $Candidates,
    [string] $Path,
    [Parameter(Mandatory = $true)]
    [string] $Source
  )

  if (-not $Path -or -not $Path.Trim()) {
    return
  }

  $expanded = [System.Environment]::ExpandEnvironmentVariables($Path.Trim())
  if ($Candidates | Where-Object { $_.path -eq $expanded }) {
    return
  }

  [void]$Candidates.Add([ordered]@{
    path = $expanded
    source = $Source
  })
}

function Add-FirstExistingWildcardCandidate {
  param(
    [System.Collections.ArrayList] $Candidates,
    [Parameter(Mandatory = $true)]
    [string] $Pattern,
    [Parameter(Mandatory = $true)]
    [string] $Source
  )

  $matches = @(Get-ChildItem -Path $Pattern -File -ErrorAction SilentlyContinue |
      Sort-Object FullName -Descending)
  if ($matches.Count -gt 0) {
    Add-CommandCandidate -Candidates $Candidates -Path $matches[0].FullName -Source $Source
  }
}

function Add-PathCommandCandidate {
  param(
    [System.Collections.ArrayList] $Candidates,
    [Parameter(Mandatory = $true)]
    [string] $Name
  )

  $command = Get-Command $Name -ErrorAction SilentlyContinue
  if ($command -and $command.Source) {
    Add-CommandCandidate -Candidates $Candidates -Path $command.Source -Source "PATH"
  }
}

function Get-DeveloperCommandCandidates {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Name
  )

  $candidates = New-Object System.Collections.ArrayList
  $userProfile = Get-EnvValue "USERPROFILE"
  $cargoHome = Get-EnvValue "CARGO_HOME"
  $programFiles = Get-EnvValue "ProgramFiles"
  $programFilesX86 = Get-EnvValue "ProgramFiles(x86)"
  $localAppData = Get-EnvValue "LOCALAPPDATA"

  switch ($Name) {
    "cargo" {
      Add-CommandCandidate -Candidates $candidates -Path (Get-EnvValue "AEGIS_CARGO_PATH") -Source "AEGIS_CARGO_PATH"
      Add-PathCommandCandidate -Candidates $candidates -Name $Name
      if ($cargoHome) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $cargoHome "bin\cargo.exe") -Source "CARGO_HOME"
      }
      if ($userProfile) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $userProfile ".cargo\bin\cargo.exe") -Source "USERPROFILE rustup"
      }
      if ($localAppData) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $localAppData "Programs\Rust\bin\cargo.exe") -Source "LOCALAPPDATA Rust"
      }
    }
    "rustc" {
      Add-CommandCandidate -Candidates $candidates -Path (Get-EnvValue "AEGIS_RUSTC_PATH") -Source "AEGIS_RUSTC_PATH"
      Add-PathCommandCandidate -Candidates $candidates -Name $Name
      if ($cargoHome) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $cargoHome "bin\rustc.exe") -Source "CARGO_HOME"
      }
      if ($userProfile) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $userProfile ".cargo\bin\rustc.exe") -Source "USERPROFILE rustup"
      }
      if ($localAppData) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $localAppData "Programs\Rust\bin\rustc.exe") -Source "LOCALAPPDATA Rust"
      }
    }
    "rustup" {
      Add-CommandCandidate -Candidates $candidates -Path (Get-EnvValue "AEGIS_RUSTUP_PATH") -Source "AEGIS_RUSTUP_PATH"
      Add-PathCommandCandidate -Candidates $candidates -Name $Name
      if ($cargoHome) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $cargoHome "bin\rustup.exe") -Source "CARGO_HOME"
      }
      if ($userProfile) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $userProfile ".cargo\bin\rustup.exe") -Source "USERPROFILE rustup"
      }
      if ($localAppData) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $localAppData "Programs\Rust\bin\rustup.exe") -Source "LOCALAPPDATA Rust"
      }
    }
    "node" {
      Add-CommandCandidate -Candidates $candidates -Path (Get-EnvValue "AEGIS_NODE_PATH") -Source "AEGIS_NODE_PATH"
      Add-PathCommandCandidate -Candidates $candidates -Name $Name
      if ($programFiles) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $programFiles "nodejs\node.exe") -Source "ProgramFiles nodejs"
      }
      if ($programFilesX86) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $programFilesX86 "nodejs\node.exe") -Source "ProgramFiles(x86) nodejs"
      }
    }
    "npm.cmd" {
      Add-CommandCandidate -Candidates $candidates -Path (Get-EnvValue "AEGIS_NPM_PATH") -Source "AEGIS_NPM_PATH"
      Add-PathCommandCandidate -Candidates $candidates -Name $Name
      if ($programFiles) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $programFiles "nodejs\npm.cmd") -Source "ProgramFiles nodejs"
      }
      if ($programFilesX86) {
        Add-CommandCandidate -Candidates $candidates -Path (Join-Path $programFilesX86 "nodejs\npm.cmd") -Source "ProgramFiles(x86) nodejs"
      }
    }
    "signtool.exe" {
      Add-CommandCandidate -Candidates $candidates -Path (Get-EnvValue "AEGIS_SIGNTOOL_PATH") -Source "AEGIS_SIGNTOOL_PATH"
      Add-PathCommandCandidate -Candidates $candidates -Name $Name
      if ($programFilesX86) {
        Add-FirstExistingWildcardCandidate `
          -Candidates $candidates `
          -Pattern (Join-Path $programFilesX86 "Windows Kits\10\bin\*\x64\signtool.exe") `
          -Source "Windows Kits 10 x64"
      }
    }
    default {
      Add-PathCommandCandidate -Candidates $candidates -Name $Name
    }
  }

  return @($candidates)
}

function Resolve-DeveloperCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Name
  )

  $candidates = @(Get-DeveloperCommandCandidates -Name $Name)
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate.path -PathType Leaf) {
      return [ordered]@{
        name = $Name
        present = $true
        path = $candidate.path
        source = $candidate.source
        searched_paths = @($candidates | ForEach-Object { $_.path })
      }
    }
  }

  return [ordered]@{
    name = $Name
    present = $false
    path = $null
    source = $null
    searched_paths = @($candidates | ForEach-Object { $_.path })
  }
}

function Resolve-RequiredDeveloperCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Name
  )

  $resolved = Resolve-DeveloperCommand -Name $Name
  if ($resolved.present) {
    return $resolved
  }

  $searched = if ($resolved.searched_paths.Count -gt 0) {
    $resolved.searched_paths -join ", "
  } else {
    "PATH only"
  }
  throw "Required command not found: $Name. Checked $searched. You can set AEGIS_CARGO_PATH, AEGIS_RUSTC_PATH, AEGIS_RUSTUP_PATH, AEGIS_NODE_PATH, AEGIS_NPM_PATH, or AEGIS_SIGNTOOL_PATH for explicit tool locations."
}

function Invoke-CheckedCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Path,
    [string[]] $Arguments = @()
  )

  & $Path @Arguments
  if ($LASTEXITCODE -ne 0) {
    $joinedArguments = $Arguments -join " "
    throw "Command failed with exit code $LASTEXITCODE`: $Path $joinedArguments"
  }
}

function Add-DirectoryToProcessPath {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Directory
  )

  if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
    return
  }

  $separator = [System.IO.Path]::PathSeparator
  $existing = @($env:PATH -split [regex]::Escape($separator) | Where-Object { $_ -and $_.Trim() })
  if ($existing | Where-Object { $_.TrimEnd("\", "/") -eq $Directory.TrimEnd("\", "/") }) {
    return
  }

  $env:PATH = "$Directory$separator$env:PATH"
}

function Add-ResolvedCommandToProcessPath {
  param(
    [Parameter(Mandatory = $true)]
    $Command
  )

  if ($Command.path) {
    Add-DirectoryToProcessPath -Directory (Split-Path -Parent $Command.path)
  }
}
