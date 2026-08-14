<#
.SYNOPSIS
    Install security tools required by erreetool agent.

.DESCRIPTION
    Installs nmap, nuclei, whatweb, gobuster, sqlmap, and wordlists on Windows.
    Uses winget, chocolatey, or scoop as available, with manual fallbacks.

.NOTES
    Run as Administrator for best results (some tools require elevated install).
    After installation, restart your shell or run 'refreshenv' if using chocolatey.
#>

[CmdletBinding()]
param(
    [switch]$Force,                    # Skip confirmation prompts
    [switch]$SkipWordlists,            # Skip SecLists wordlist download
    [string]$InstallDir = "C:\Tools",  # Fallback manual install directory
    [ValidateSet("winget", "choco", "scoop", "auto")]
    [string]$PackageManager = "auto"   # Preferred package manager
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Colors for output
$green  = [ConsoleColor]::Green
$yellow = [ConsoleColor]::Yellow
$red    = [ConsoleColor]::Red
$cyan   = [ConsoleColor]::Cyan
$gray   = [ConsoleColor]::Gray

function Write-Log {
    param([string]$Message, [ConsoleColor]$Color = $gray)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline -ForegroundColor $gray
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { param([string]$Msg) Write-Log "��� $Msg" $green }
function Write-Warn    { param([string]$Msg) Write-Log "��� $Msg" $yellow }
function Write-Error   { param([string]$Msg) Write-Log "��� $Msg" $red }
function Write-Info    { param([string]$Msg) Write-Log "�� $Msg" $cyan }

function Test-Command { param([string]$Cmd) (Get-Command $Cmd -ErrorAction SilentlyContinue) -ne $null }
function Test-PathExists { param([string]$Path) (Test-Path $Path) }

# Detect package manager
function Get-PackageManager {
    if ($PackageManager -ne "auto") { return $PackageManager }
    if (Test-Command "winget") { return "winget" }
    if (Test-Command "choco")  { return "choco" }
    if (Test-Command "scoop")  { return "scoop" }
    return $null
}

$pm = Get-PackageManager
if (-not $pm) {
    Write-Error "No supported package manager found (winget, choco, scoop)."
    Write-Info "Install winget (built into Windows 10/11), or:"
    Write-Info "  choco:  https://chocolatey.org/install"
    Write-Info "  scoop:  https://scoop.sh"
    exit 1
}
Write-Info "Using package manager: $pm"

# Ensure install directory exists
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Info "Created $InstallDir"
}

# Add to PATH if not already
$envPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($envPath -notlike "*$InstallDir*") {
    Write-Warn "Adding $InstallDir to user PATH (restart shell after)"
    [Environment]::SetEnvironmentVariable("Path", "$envPath;$InstallDir", "User")
}

# ---- Tool definitions ----
# Each entry: @{ Name, WingetId, ChocoId, ScoopId, BinaryName, VersionCheck, Url (manual fallback) }
$tools = @(
    @{
        Name         = "Nmap"
        WingetId     = "Insecure.Nmap"
        ChocoId      = "nmap"
        ScoopId      = "nmap"
        BinaryName   = "nmap.exe"
        VersionCheck = "nmap --version | Select-Object -First 1"
        Url          = "https://nmap.org/dist/nmap-7.95-setup.exe"
    }
    @{
        Name         = "Nuclei"
        WingetId     = "ProjectDiscovery.Nuclei"
        ChocoId      = "nuclei"
        ScoopId      = "nuclei"
        BinaryName   = "nuclei.exe"
        VersionCheck = "nuclei -version"
        Url          = "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.7_windows_amd64.zip"
    }
    @{
        Name         = "WhatWeb"
        WingetId     = ""           # Not in winget
        ChocoId      = "whatweb"
        ScoopId      = "whatweb"
        BinaryName   = "whatweb.exe"
        VersionCheck = "whatweb --version"
        Url          = "https://github.com/urbanadventurer/WhatWeb/releases/latest/download/whatweb-0.5.5-windows.zip"
    }
    @{
        Name         = "Gobuster"
        WingetId     = "OJ.Gobuster"
        ChocoId      = "gobuster"
        ScoopId      = "gobuster"
        BinaryName   = "gobuster.exe"
        VersionCheck = "gobuster version"
        Url          = "https://github.com/OJ/gobuster/releases/latest/download/gobuster_3.6.0_windows_amd64.zip"
    }
    @{
        Name         = "SQLMap"
        WingetId     = "SQLMapProject.SQLMap"
        ChocoId      = "sqlmap"
        ScoopId      = "sqlmap"
        BinaryName   = "sqlmap.exe"
        VersionCheck = "sqlmap --version | Select-Object -First 1"
        Url          = "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip"
    }
    @{
        Name         = "Feroxbuster"
        WingetId     = "Epieci.Feroxbuster"
        ChocoId      = "feroxbuster"
        ScoopId      = "feroxbuster"
        BinaryName   = "feroxbuster.exe"
        VersionCheck = "feroxbuster --version"
        Url          = "https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_windows_amd64.zip"
    }
)

# Install a single tool via package manager or manual download
function Install-Tool {
    param($tool)
    $name = $tool.Name
    $binary = $tool.BinaryName

    # Check if already installed
    if (Test-Command $binary -or (Test-PathExists "$InstallDir\$binary")) {
        Write-Success "$name already installed ($binary)"
        return $true
    }

    Write-Info "Installing $name..."

    $installed = $false
    try {
        switch ($pm) {
            "winget" {
                if ($tool.WingetId) {
                    winget install --id $tool.WingetId --silent --accept-source-agreements --accept-package-agreements
                    $installed = $true
                }
            }
            "choco" {
                if ($tool.ChocoId) {
                    choco install $tool.ChocoId -y --no-progress
                    $installed = $true
                }
            }
            "scoop" {
                if ($tool.ScoopId) {
                    scoop install $tool.ScoopId
                    $installed = $true
                }
            }
        }
    } catch {
        Write-Warn "Package manager install failed for $name: $_"
        $installed = $false
    }

    if (-not $installed -and $tool.Url) {
        Write-Info "Falling back to manual download for $name..."
        $installed = Install-Manual $tool
    }

    if ($installed -and (Test-Command $binary -or (Test-PathExists "$InstallDir\$binary"))) {
        Write-Success "$name installed successfully"
        return $true
    }

    Write-Error "Failed to install $name"
    return $false
}

# Manual download + extract for tools not in package managers
function Install-Manual {
    param($tool)
    $url = $tool.Url
    $binary = $tool.BinaryName
    $tempZip = "$env:TEMP\$binary.zip"

    try {
        Write-Info "Downloading $name from $url..."
        Invoke-WebRequest -Uri $url -OutFile $tempZip -UseBasicParsing

        Write-Info "Extracting..."
        Expand-Archive -Path $tempZip -DestinationPath $InstallDir -Force

        # If extracted to subdir, find binary
        $found = Get-ChildItem -Path $InstallDir -Recurse -Filter $binary -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found -and $found.FullName -ne "$InstallDir\$binary") {
            Copy-Item $found.FullName "$InstallDir\$binary" -Force
        }

        Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Error "Manual install failed for $($tool.Name): $_"
        Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# ---- Main ----
Write-Info "erreetool tool installer starting..."
Write-Info "Target directory: $InstallDir"

if (-not $Force) {
    $confirm = Read-Host "Continue? [Y/n]"
    if ($confirm -inotmatch '^y') { Write-Warn "Cancelled"; exit 0 }
}

$results = @{}
foreach ($tool in $tools) {
    $results[$tool.Name] = Install-Tool $tool
}

# ---- Wordlists ----
if (-not $SkipWordlists) {
    Write-Info "Fetching SecLists wordlists..."
    $wordlistDir = "$InstallDir\wordlists"
    if (-not (Test-Path $wordlistDir)) { New-Item -ItemType Directory -Path $wordlistDir -Force | Out-Null }

    try {
        $repoUrl = "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip"
        $tempZip = "$env:TEMP\SecLists.zip"
        Invoke-WebRequest -Uri $repoUrl -OutFile $tempZip -UseBasicParsing
        Expand-Archive -Path $tempZip -DestinationPath $wordlistDir -Force
        # Flatten: move contents up one level
        $extracted = Get-ChildItem -Path $wordlistDir -Directory | Select-Object -First 1
        if ($extracted) {
            Move-Item "$($extracted.FullName)\*" $wordlistDir -Force
            Remove-Item $extracted.FullName -Recurse -Force
        }
        Remove-Item $tempZip -Force
        Write-Success "Wordlists downloaded to $wordlistDir"
    } catch {
        Write-Warn "Wordlist download failed: $_"
    }
} else {
    Write-Info "Skipping wordlists (--SkipWordlists)"
}

# ---- Nuclei templates ----
Write-Info "Updating Nuclei templates..."
try {
    if (Test-Command "nuclei") {
        nuclei -update-templates -silent
        Write-Success "Nuclei templates updated"
    }
} catch {
    Write-Warn "Nuclei template update failed (run manually later): $_"
}

# ---- Summary ----
Write-Info "`n=== Installation Summary ==="
foreach ($name in $results.Keys) {
    $status = if ($results[$name]) { "OK" } else { "FAIL" }
    $color  = if ($results[$name]) { $green } else { $red }
    Write-Host "  $name: " -NoNewline
    Write-Host $status -ForegroundColor $color
}

$failed = $results.Values | Where-Object { -not $_ } | Measure-Object
if ($failed.Count -gt 0) {
    Write-Warn "`n$($failed.Count) tool(s) failed. Check output above."
    exit 1
} else {
    Write-Success "`nAll tools installed! Restart your shell or run 'refreshenv' (choco)."
    Write-Info "Verify with: erreetool doctor"
}