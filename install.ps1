<#
.SYNOPSIS
    Installs Xentree Connect on Windows.

.DESCRIPTION
    Downloads xentree-connect.exe and SHA256SUMS from the release, verifies the
    checksum, and only then installs it to $HOME\.xentree\bin and adds that
    directory to your user PATH.

    Run it directly, or pass options through a script block (a piped script
    cannot take parameters):

        irm https://get.xentree.ai/connect.ps1 | iex
        & ([scriptblock]::Create((irm https://get.xentree.ai/connect.ps1))) -NoInit

.PARAMETER Version
    Release to install, e.g. v1.2.3 (default: latest). Also XENTREE_CONNECT_VERSION.

.PARAMETER InstallDir
    Where to put xentree-connect.exe (default: $HOME\.xentree\bin).

.PARAMETER NoInit
    Do not run `xentree-connect init` after installing (for scripts and CI).
    By default the setup wizard starts right after installation.

.NOTES
    Environment: XENTREE_CONNECT_REPO ("owner/name") and XENTREE_CONNECT_BASE_URL
    (an https releases URL, for mirrors).
#>
[CmdletBinding()]
param(
    [string]$Version = $env:XENTREE_CONNECT_VERSION,
    [string]$InstallDir = (Join-Path $HOME '.xentree\bin'),
    [switch]$NoInit
)

# Everything lives in Main, called on the last line: a truncated download
# defines a function and never runs.
function Main {
    param([string]$Version, [string]$InstallDir, [bool]$NoInit)

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $repo = if ($env:XENTREE_CONNECT_REPO) { $env:XENTREE_CONNECT_REPO } else { 'godfreu/xentree-connect' }
    $baseUrl = if ($env:XENTREE_CONNECT_BASE_URL) { $env:XENTREE_CONNECT_BASE_URL } else { "https://github.com/$repo/releases" }
    $baseUrl = $baseUrl.TrimEnd('/')
    if ($baseUrl -notmatch '^https://') { throw "Release URL must start with https:// (got: $baseUrl)" }

    # Windows PowerShell 5.1 may default to TLS 1.0/1.1.
    $tls = [Net.SecurityProtocolType]::Tls12
    if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
        $tls = $tls -bor [Net.SecurityProtocolType]::Tls13
    }
    [Net.ServicePointManager]::SecurityProtocol = $tls

    # The version ends up in a URL path: accept only release-tag shapes.
    if (-not $Version -or $Version -eq 'latest') {
        $releaseUrl = "$baseUrl/latest/download"
        $Version = 'latest'
    } else {
        if (-not $Version.StartsWith('v')) { $Version = "v$Version" }
        if ($Version -notmatch '^v\d+\.\d+\.\d+([-+.][0-9A-Za-z.-]+)?$') {
            throw "Invalid version: $Version (expected something like v1.2.3)"
        }
        $releaseUrl = "$baseUrl/download/$Version"
    }

    # Only x64 is published. Windows on ARM runs it through emulation.
    $arch = Get-OsArchitecture
    switch ($arch) {
        'X64'   { }
        'Arm64' { Write-Warning 'ARM64 detected: installing the x64 build, which runs under emulation.' }
        default { throw "Unsupported architecture: $arch (supported: x64, arm64)" }
    }
    $asset = 'xentree-connect-x86_64-pc-windows-msvc.exe'
    Write-Host "Installing Xentree Connect ($Version, windows/$arch)"

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("xentree-connect-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $exeTmp = Join-Path $tmp $asset
        $sumsTmp = Join-Path $tmp 'SHA256SUMS'

        Write-Host "Downloading $asset"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$releaseUrl/$asset" -OutFile $exeTmp
            Invoke-WebRequest -UseBasicParsing -Uri "$releaseUrl/SHA256SUMS" -OutFile $sumsTmp
        } catch {
            throw "Download failed from $releaseUrl : $($_.Exception.Message)"
        }

        # The checksum must come from SHA256SUMS and name this exact asset once.
        $expected = @(
            Get-Content -LiteralPath $sumsTmp | ForEach-Object {
                if ($_ -match '^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $asset) { $Matches[1].ToLowerInvariant() }
            }
        )
        if ($expected.Count -eq 0) { throw "SHA256SUMS has no entry for $asset" }
        if ($expected.Count -gt 1) { throw "SHA256SUMS lists $asset more than once" }
        $actual = (Get-FileHash -LiteralPath $exeTmp -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected[0]) {
            throw "Checksum mismatch for $asset`n  expected: $($expected[0])`n  actual:   $actual`nNothing was installed."
        }
        Write-Host "Checksum verified (sha256 $actual)"

        # Stage inside the target directory, then rename: no half-written exe.
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        $dest = Join-Path $InstallDir 'xentree-connect.exe'
        $staged = Join-Path $InstallDir ".xentree-connect.$PID.tmp"
        Copy-Item -LiteralPath $exeTmp -Destination $staged -Force
        Move-Item -LiteralPath $staged -Destination $dest -Force
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $installed = ''
    try {
        $installed = (& $dest --version 2>&1 | Out-String).Trim()
    } catch {
        $installed = ''
    }
    if ($installed -and $LASTEXITCODE -eq 0) {
        Write-Host "Installed $installed to $dest"
    } else {
        Write-Warning "Installed to $dest, but it did not run on this system."
    }

    Add-ToUserPath -Dir $InstallDir

    if (-not $NoInit) {
        Write-Host ''
        & $dest init
    } else {
        Write-Host ''
        Write-Host 'Next: xentree-connect init   (open a new terminal first if the command is not found)'
    }
}

function Get-OsArchitecture {
    try {
        return [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        # Windows PowerShell on older .NET Framework versions.
        $a = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
        switch ($a) { 'AMD64' { 'X64' } 'ARM64' { 'Arm64' } default { $a } }
    }
}

# Appends Dir to the *user* PATH. Reads the raw registry value so %VARIABLES%
# already in PATH are preserved, not expanded and frozen.
function Add-ToUserPath {
    param([string]$Dir)

    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $raw = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $wanted = $Dir.TrimEnd('\')
        $present = ($raw -split ';') |
            Where-Object { $_ -and ([Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ieq $wanted) }
        if ($present) { return }
        $new = if ($raw) { $raw.TrimEnd(';') + ';' + $Dir } else { $Dir }
        $key.SetValue('Path', $new, [Microsoft.Win32.RegistryValueKind]::ExpandString)
    } finally {
        $key.Close()
    }
    $env:Path = $env:Path.TrimEnd(';') + ';' + $Dir
    Write-Host "Added $Dir to your user PATH."

    # Tell running programs (Explorer, new terminals) the environment changed.
    try {
        Add-Type -Namespace XentreeConnect -Name Native -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
        $result = [UIntPtr]::Zero
        [void][XentreeConnect.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
    } catch {
        Write-Verbose "Could not broadcast the environment change: $($_.Exception.Message)"
    }
}

Main -Version $Version -InstallDir $InstallDir -NoInit ([bool]$NoInit)
