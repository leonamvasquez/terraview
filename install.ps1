# terraview installer for Windows
# Usage: irm https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "leonamvasquez/terraview"
$BinaryName = "terraview"
$InstallDir = "$env:LOCALAPPDATA\Programs\terraview"
$AssetsDir = "$env:USERPROFILE\.terraview"

function Write-Info  { param($msg) Write-Host "[info]  $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[ok]    $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[warn]  $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[error] $msg" -ForegroundColor Red }

# Detect architecture — multiple fallbacks for maximum compatibility
function Get-Arch {
    # Try every possible method and return the first that works

    # Method 1: env var
    $cpu = $env:PROCESSOR_ARCHITECTURE
    if ($cpu -eq "AMD64") { return "amd64" }
    if ($cpu -eq "ARM64") { return "arm64" }

    # Method 2: WOW64 override
    $cpu = $env:PROCESSOR_ARCHITEW6432
    if ($cpu -eq "AMD64") { return "amd64" }
    if ($cpu -eq "ARM64") { return "arm64" }

    # Method 3: wmic (available on all Windows versions)
    try {
        $wmic = (wmic os get osarchitecture 2>$null | Select-String "64")
        if ($wmic) { return "amd64" }
    } catch {}

    # Method 4: .NET pointer size (8 bytes = 64-bit)
    if ([System.IntPtr]::Size -eq 8) { return "amd64" }

    # Method 5: Is64BitOperatingSystem
    try {
        if ([System.Environment]::Is64BitOperatingSystem) { return "amd64" }
    } catch {}

    # Default: amd64 (99%+ of Windows machines)
    Write-Warn "Could not detect architecture, defaulting to amd64"
    return "amd64"
}

# Get latest release version
function Get-LatestVersion {
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "terraview-installer" }
        return $release.tag_name
    } catch {
        Write-Warn "Could not fetch latest version, defaulting to v0.1.0"
        return "v0.1.0"
    }
}

# Main
Write-Host ""
Write-Host "  +---------------------------------------+"
Write-Host "  |      terraview installer (Windows)    |"
Write-Host "  +---------------------------------------+"
Write-Host ""

$arch = Get-Arch
$version = if ($env:TERRAVIEW_VERSION) { $env:TERRAVIEW_VERSION } else { Get-LatestVersion }

Write-Info "OS:       Windows"
Write-Info "Arch:     $arch"
Write-Info "Version:  $version"
Write-Host ""

$downloadUrl = "https://github.com/$Repo/releases/download/$version/$BinaryName-windows-$arch.tar.gz"
$assetsUrl   = "https://github.com/$Repo/releases/download/$version/terraview-assets.tar.gz"
$tmpDir      = Join-Path $env:TEMP "terraview-install-$(Get-Random)"

try {
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    # Download binary
    Write-Info "Downloading $BinaryName $version..."
    $tarPath = Join-Path $tmpDir "binary.tar.gz"
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tarPath -UseBasicParsing
    } catch {
        Write-Err "Failed to download from $downloadUrl"
        Write-Err ""
        Write-Err "The release may not exist yet. You can build from source instead:"
        Write-Err "  git clone https://github.com/$Repo.git"
        Write-Err "  cd terraview"
        Write-Err "  go build -o terraview.exe ."
        exit 1
    }

    # Extract binary
    Write-Info "Extracting binary..."
    tar -xzf $tarPath -C $tmpDir

    # Download assets
    Write-Info "Downloading assets..."
    $assetsTar = Join-Path $tmpDir "assets.tar.gz"
    try {
        Invoke-WebRequest -Uri $assetsUrl -OutFile $assetsTar -UseBasicParsing
        New-Item -ItemType Directory -Path $AssetsDir -Force | Out-Null
        tar -xzf $assetsTar -C $AssetsDir
        Write-Ok "Assets installed to $AssetsDir"
    } catch {
        Write-Warn "Could not download assets. You can copy prompts/ and rules/ manually to $AssetsDir"
    }

    # Install binary
    Write-Info "Installing to $InstallDir..."
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    $srcBinary = Join-Path $tmpDir "$BinaryName-windows-$arch.exe"
    if (-not (Test-Path $srcBinary)) {
        # Fallback: search for any .exe in the tmp dir
        $srcBinary = Get-ChildItem -Path $tmpDir -Filter "*.exe" | Select-Object -First 1 -ExpandProperty FullName
    }

    if (-not $srcBinary -or -not (Test-Path $srcBinary)) {
        Write-Err "Binary not found after extraction"
        exit 1
    }

    Copy-Item -Path $srcBinary -Destination (Join-Path $InstallDir "$BinaryName.exe") -Force
    # Also create tv.exe alias (copy)
    Copy-Item -Path $srcBinary -Destination (Join-Path $InstallDir "tv.exe") -Force
    Write-Ok "Alias 'tv' -> $InstallDir\tv.exe"

    # Add to PATH if not already present
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    $needsRestart = $false
    if ($userPath -notlike "*$InstallDir*") {
        Write-Info "Adding $InstallDir to user PATH..."
        [Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$userPath", "User")
        $needsRestart = $true
    }
    # Always refresh current session PATH
    $env:PATH = "$InstallDir;" + [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [Environment]::GetEnvironmentVariable("PATH", "User")

    # Verify
    $installed = Join-Path $InstallDir "$BinaryName.exe"
    if (Test-Path $installed) {
        Write-Ok "Installed successfully!"
        Write-Host ""
        & $installed version
        Write-Host ""
        if ($needsRestart) {
            Write-Host ""
            Write-Warn "IMPORTANTE: Feche e reabra o terminal para usar 'terraview' e 'tv'."
            Write-Host ""
            Write-Host "  Ou rode agora nesta sessao:"
            Write-Host "    `$env:PATH = [Environment]::GetEnvironmentVariable('PATH','User') + ';' + [Environment]::GetEnvironmentVariable('PATH','Machine')" -ForegroundColor DarkGray
            Write-Host ""
        }
        Write-Host "  Get started:"
        Write-Host "    cd your-terraform-project"
        Write-Host "    terraview review   # or: tv review"
        Write-Host ""
    } else {
        Write-Warn "Binary installed but verification failed."
    }
} finally {
    # Cleanup
    if (Test-Path $tmpDir) {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
