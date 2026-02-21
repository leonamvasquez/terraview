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

# Detect architecture using multiple methods for maximum compatibility
function Get-Arch {
    # Method 1: WMI/CIM — most reliable, works on all Windows versions
    # Architecture: 0=x86, 9=x64/AMD64, 12=ARM64
    try {
        $cpuArch = (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1).Architecture
        switch ($cpuArch) {
            9  { return "amd64" }
            12 { return "arm64" }
            0  {
                Write-Err "32-bit (x86) is not supported. Please use a 64-bit system."
                exit 1
            }
        }
    } catch {}

    # Method 2: PROCESSOR_ARCHITECTURE env var (may be empty in piped iex sessions)
    $cpu = $env:PROCESSOR_ARCHITECTURE
    if ([string]::IsNullOrEmpty($cpu) -and $env:PROCESSOR_ARCHITEW6432) {
        $cpu = $env:PROCESSOR_ARCHITEW6432
    }
    if (-not [string]::IsNullOrEmpty($cpu)) {
        switch ($cpu.ToUpper()) {
            "AMD64" { return "amd64" }
            "ARM64" { return "arm64" }
        }
    }

    # Method 3: .NET IntPtr size + Is64BitOperatingSystem
    if ([System.Environment]::Is64BitOperatingSystem) {
        try {
            $rtArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
            if ($rtArch -eq "Arm64") { return "arm64" }
        } catch {}
        return "amd64"
    }

    Write-Err "Could not determine system architecture. Please download manually from:"
    Write-Err "  https://github.com/$Repo/releases/latest"
    exit 1
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
    if ($userPath -notlike "*$InstallDir*") {
        Write-Info "Adding $InstallDir to user PATH..."
        [Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$userPath", "User")
        $env:PATH = "$InstallDir;$env:PATH"
        Write-Ok "Added to PATH. You may need to restart your terminal."
    }

    # Verify
    $installed = Join-Path $InstallDir "$BinaryName.exe"
    if (Test-Path $installed) {
        Write-Ok "Installed successfully!"
        Write-Host ""
        & $installed version
        Write-Host ""
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
