param(
    [string]$Version = "0.1.0",
    [string]$OutputRoot = "dist/windows-installer",
    [string]$WintunDllPath = "",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$resolvedOutputRoot = Join-Path $repoRoot $OutputRoot
$stageDir = Join-Path $resolvedOutputRoot "stage"
$outDir = Join-Path $resolvedOutputRoot "out"
$cacheDir = Join-Path $repoRoot ".gocache-windows-installer"
$installerScript = Join-Path $scriptDir "installer\ole.iss"

New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

Remove-Item -Path (Join-Path $stageDir "*") -Force -ErrorAction SilentlyContinue

$buildEnv = @{
    GOOS = "windows"
    GOARCH = "amd64"
    CGO_ENABLED = "0"
    GOCACHE = $cacheDir
}

function Invoke-GoBuild {
    param(
        [string]$OutputPath,
        [string]$PackagePath
    )

    $previous = @{
        GOOS = $env:GOOS
        GOARCH = $env:GOARCH
        CGO_ENABLED = $env:CGO_ENABLED
        GOCACHE = $env:GOCACHE
    }

    try {
        $env:GOOS = $buildEnv.GOOS
        $env:GOARCH = $buildEnv.GOARCH
        $env:CGO_ENABLED = $buildEnv.CGO_ENABLED
        $env:GOCACHE = $buildEnv.GOCACHE

        & go build -buildvcs=false -trimpath -ldflags "-s -w" -o $OutputPath $PackagePath
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $PackagePath"
        }
        if (-not (Test-Path $OutputPath)) {
            throw "expected build output not found: $OutputPath"
        }
    }
    finally {
        $env:GOOS = $previous.GOOS
        $env:GOARCH = $previous.GOARCH
        $env:CGO_ENABLED = $previous.CGO_ENABLED
        $env:GOCACHE = $previous.GOCACHE
    }
}

function Write-FallbackInstaller {
    param(
        [string]$Version,
        [string]$StageDir,
        [string]$OutDir
    )

    $payloadDir = Join-Path $OutDir "Ole-Setup-$Version-files"
    if (Test-Path $payloadDir) {
        Remove-Item -Path $payloadDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $payloadDir | Out-Null
    Copy-Item -Path (Join-Path $StageDir "*") -Destination $payloadDir -Recurse -Force

    $installScriptPath = Join-Path $OutDir "Ole-Install-$Version.ps1"
    $installScript = @"
param(
    [string]`$InstallDir = (Join-Path `${env:ProgramFiles} "Ole"),
    [switch]`$NoDesktopShortcut,
    [switch]`$NoLaunch
)

`$ErrorActionPreference = "Stop"

`$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
`$principal = New-Object Security.Principal.WindowsPrincipal(`$identity)
if (-not `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell window."
}

`$scriptDir = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$payloadDir = Join-Path `$scriptDir "Ole-Setup-$Version-files"
if (-not (Test-Path `$payloadDir)) {
    throw "Installer payload folder not found: `$payloadDir"
}

New-Item -ItemType Directory -Force -Path `$InstallDir | Out-Null
Copy-Item -Path (Join-Path `$payloadDir "*") -Destination `$InstallDir -Recurse -Force

`$agentExe = Join-Path `$InstallDir "ole-agent.exe"
`$clientExe = Join-Path `$InstallDir "ole-client.exe"

if (Test-Path `$agentExe) {
    try { & `$agentExe stop 2>`$null | Out-Null } catch {}
    try { & `$agentExe uninstall 2>`$null | Out-Null } catch {}
    & `$agentExe install
    & `$agentExe start
}

`$shell = New-Object -ComObject WScript.Shell
`$startMenuShortcut = Join-Path `$env:ProgramData "Microsoft\Windows\Start Menu\Programs\Ole.lnk"
`$shortcut = `$shell.CreateShortcut(`$startMenuShortcut)
`$shortcut.TargetPath = `$clientExe
`$shortcut.WorkingDirectory = `$InstallDir
`$shortcut.IconLocation = "`$clientExe,0"
`$shortcut.Save()

if (-not `$NoDesktopShortcut) {
    `$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "Ole.lnk"
    `$desktop = `$shell.CreateShortcut(`$desktopShortcut)
    `$desktop.TargetPath = `$clientExe
    `$desktop.WorkingDirectory = `$InstallDir
    `$desktop.IconLocation = "`$clientExe,0"
    `$desktop.Save()
}

Write-Host "Ole installed to `$InstallDir"
Write-Host "Ole Agent service installed and started."
Write-Host "Start Ole from: `$clientExe"

if (-not `$NoLaunch -and (Test-Path `$clientExe)) {
    Start-Process `$clientExe
}
"@
    Set-Content -Path $installScriptPath -Value $installScript -Encoding UTF8

    $readmePath = Join-Path $OutDir "INSTALLER-README.txt"
    @"
Ole installer fallback
======================

Inno Setup was not found on this machine, so a script-based Windows installer was generated instead.

Files:
- Ole-Install-$Version.ps1
- Ole-Setup-$Version-files\
- Ole-Portable-$Version.zip

How to install:
1. Open PowerShell as Administrator.
2. Run:
   powershell -ExecutionPolicy Bypass -File .\Ole-Install-$Version.ps1

What it does:
- copies Ole into Program Files\Ole
- installs and starts the Ole Agent service
- creates Start Menu and desktop shortcuts
"@ | Set-Content -Path $readmePath -Encoding UTF8

    $zipPath = Join-Path $OutDir "Ole-Portable-$Version.zip"
    if (Test-Path $zipPath) {
        Remove-Item -Path $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $payloadDir "*") -DestinationPath $zipPath -Force

    Write-Host "Inno Setup compiler not found; generated fallback installer script at $installScriptPath"
    Write-Host "Portable bundle is in $zipPath"
}

Push-Location $repoRoot
try {
    Write-Host "Building ole-client.exe..."
    Invoke-GoBuild -OutputPath (Join-Path $stageDir "ole-client.exe") -PackagePath ".\cmd\client"

    Write-Host "Building ole-agent.exe..."
    Invoke-GoBuild -OutputPath (Join-Path $stageDir "ole-agent.exe") -PackagePath ".\cmd\agent"
}
finally {
    Pop-Location
}

$candidateWintunPaths = @()
if ($WintunDllPath) {
    $candidateWintunPaths += $WintunDllPath
}
if ($env:OLE_WINTUN_DLL_PATH) {
    $candidateWintunPaths += $env:OLE_WINTUN_DLL_PATH
}
$candidateWintunPaths += @(
    (Join-Path $repoRoot "wintun.dll"),
    (Join-Path $repoRoot "third_party\wintun\wintun.dll")
)

$resolvedWintunDll = $candidateWintunPaths |
    Where-Object { $_ -and (Test-Path $_) } |
    Select-Object -First 1

if ($resolvedWintunDll) {
    Copy-Item -Path $resolvedWintunDll -Destination (Join-Path $stageDir "wintun.dll") -Force
    Write-Host "Included wintun.dll from $resolvedWintunDll"
} else {
    Write-Host "wintun.dll not found; continuing without bundling it"
}

if ($SkipInstaller) {
    Write-Host "Skipping installer compilation; staged files are in $stageDir"
    exit 0
}

$isccCandidates = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)

$iscc = $isccCandidates |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1

if (-not $iscc) {
    $isccFromPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($isccFromPath) {
        $iscc = $isccFromPath.Source
    }
}

if (-not $iscc) {
    Write-FallbackInstaller -Version $Version -StageDir $stageDir -OutDir $outDir
    exit 0
}

Write-Host "Compiling installer with $iscc..."
& $iscc "/DOLEVersion=$Version" "/DOLESourceDir=$stageDir" "/DOLEOutputDir=$outDir" $installerScript

Write-Host "Installer output is in $outDir"
