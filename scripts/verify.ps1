#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Full')][string]$Mode = 'Quick',
    [string[]]$Packages = @('./internal/clientagent'),
    [string]$PostgresBin = 'C:\Program Files\PostgreSQL\16\bin'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$runName = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
$logRoot = Join-Path $repoRoot ('out/verification/' + $runName)
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$watch = [Diagnostics.Stopwatch]::StartNew()
$summary = [ordered]@{ ok = $false; mode = $Mode; packagesPassed = 0; sqlPassed = 0; testsSkipped = 0; failedTests = @(); stages = [ordered]@{}; logs = $logRoot }
$savedEnvironment = @{}
foreach ($name in @('GOCACHE', 'GOOS', 'GOARCH', 'OLE_TEST_DATABASE_URL')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$verifyClusterRoot = $null
$verifyPgProcess = $null
$verifyPgBin = $PostgresBin

# Use ArgumentList rather than shell text; large stdout/stderr stream to disk.
function Invoke-LoggedProcess([string]$Executable, [string[]]$Arguments, [string]$Name, [int]$TimeoutSeconds = 600) {
    $stdoutPath = Join-Path $logRoot ($Name + '.stdout.log')
    $stderrPath = Join-Path $logRoot ($Name + '.stderr.log')
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.WorkingDirectory = $repoRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $stdout = [IO.File]::Create($stdoutPath)
    $stderr = [IO.File]::Create($stderrPath)
    try {
        $process.Start() | Out-Null
        $copyOut = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $copyErr = $process.StandardError.BaseStream.CopyToAsync($stderr)
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "Stage timed out: $Name; see logs"
        }
        $copyOut.GetAwaiter().GetResult()
        $copyErr.GetAwaiter().GetResult()
        return [pscustomobject]@{ code = $process.ExitCode; stdout = $stdoutPath; stderr = $stderrPath }
    } finally {
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
}

function Invoke-GoStage([string]$Name, [string[]]$GoArguments) {
    $result = Invoke-LoggedProcess $script:goExe $GoArguments $Name
    $summary.stages[$Name] = $result.code
    if ($result.code -ne 0) { throw "Stage failed: $Name; see logs" }
}

function Start-VerifyDatabase {
    foreach ($binary in @('initdb.exe', 'postgres.exe', 'pg_isready.exe', 'pg_ctl.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $verifyPgBin $binary))) {
            throw 'Full requires PostgreSQL tools; pass -PostgresBin. No existing database will be used.'
        }
    }
    $script:verifyClusterRoot = Join-Path $env:TEMP ('ole-verify-pg-' + [guid]::NewGuid().ToString('N'))
    $data = Join-Path $verifyClusterRoot 'data'
    New-Item -ItemType Directory -Path $data -Force | Out-Null
    $init = Invoke-LoggedProcess (Join-Path $verifyPgBin 'initdb.exe') @('-D', $data, '-U', 'ole_verify', '-A', 'trust', '--encoding=UTF8', '--locale=C') 'postgres-init' 60
    if ($init.code -ne 0) { throw 'Test PostgreSQL initialization failed; see logs' }
    $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $probe.Start()
    $port = $probe.LocalEndpoint.Port
    $probe.Stop()
    $script:verifyPgProcess = Start-Process -FilePath (Join-Path $verifyPgBin 'postgres.exe') -ArgumentList @('-D', ('"' + $data + '"'), '-h', '127.0.0.1', '-p', $port) -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logRoot 'postgres.stdout.log') -RedirectStandardError (Join-Path $logRoot 'postgres.stderr.log') -PassThru
    $ready = $false
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        if ($verifyPgProcess.HasExited) { break }
        $check = Invoke-LoggedProcess (Join-Path $verifyPgBin 'pg_isready.exe') @('-h', '127.0.0.1', '-p', "$port") 'postgres-ready' 5
        if ($check.code -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw 'Test PostgreSQL did not become ready; see logs' }
    $env:OLE_TEST_DATABASE_URL = "postgres://ole_verify@127.0.0.1:$port/postgres?sslmode=disable"
}

function Stop-VerifyDatabase {
    if (-not $verifyClusterRoot) { return }
    $root = [IO.Path]::GetFullPath($verifyClusterRoot)
    $tempPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
    if (-not $root.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path $root -Leaf) -notmatch '^ole-verify-pg-[0-9a-f]{32}$') {
        throw 'Refusing unexpected PostgreSQL cleanup path'
    }
    $data = Join-Path $root 'data'
    $pidPath = Join-Path $data 'postmaster.pid'
    if (Test-Path -LiteralPath $pidPath) {
        $identity = Get-Content -LiteralPath $pidPath -TotalCount 2
        if (-not $verifyPgProcess -or [int]$identity[0] -ne $verifyPgProcess.Id -or [IO.Path]::GetFullPath($identity[1]) -ne $data) {
            throw 'Test cluster identity mismatch; manual cleanup required'
        }
        $stop = Invoke-LoggedProcess (Join-Path $verifyPgBin 'pg_ctl.exe') @('-D', $data, '-m', 'fast', '-w', '-t', '15', 'stop') 'postgres-stop' 20
        if ($stop.code -ne 0) { throw 'Test PostgreSQL shutdown failed; see logs' }
    }
    if ($verifyPgProcess -and -not $verifyPgProcess.HasExited) {
        if (-not $verifyPgProcess.WaitForExit(5000)) { throw 'Test PostgreSQL is still running' }
    }
    if (Test-Path -LiteralPath $pidPath) { throw 'Refusing to delete an active test cluster' }
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint -or @(Get-ChildItem -LiteralPath $root -Force -Recurse -Attributes ReparsePoint).Count -gt 0) {
        throw 'Refusing recursive cleanup through links'
    }
    Remove-Item -LiteralPath $root -Recurse -Force
}

try {
    if (-not $IsWindows) { throw 'This verifier currently targets the Windows Ole workspace' }
    $script:goExe = (Get-Command go -ErrorAction Stop).Source
    $env:GOCACHE = Join-Path $env:TEMP 'ole-audit-go-cache'
    [Environment]::SetEnvironmentVariable('GOOS', $null, 'Process')
    [Environment]::SetEnvironmentVariable('GOARCH', $null, 'Process')
    if ($Mode -eq 'Full') {
        Start-VerifyDatabase
        $testPackages = @('./...')
    } else {
        # Avoid accidental SQL access to an inherited working database.
        $env:OLE_TEST_DATABASE_URL = 'postgres://ole_verify@127.0.0.1:1/unused?sslmode=disable'
        $testPackages = $Packages
        if ($testPackages.Count -eq 0) { throw 'Quick requires at least one package' }
    }
    $tests = Invoke-LoggedProcess $goExe (@('test') + $testPackages + @('-count=1', '-timeout=180s', '-json')) 'tests'
    $summary.stages['tests'] = $tests.code
    foreach ($line in [IO.File]::ReadLines($tests.stdout)) {
        if (-not $line.StartsWith('{')) { continue }
        $event = $line | ConvertFrom-Json
        if ($event.Action -eq 'pass' -and -not $event.Test) { $summary.packagesPassed++ }
        if ($event.Action -eq 'skip' -and $event.Test) { $summary.testsSkipped++ }
        if ($event.Action -eq 'pass' -and $event.Test -like 'TestPostgres*' -and $event.Test -notmatch '/|ProcessHelper') { $summary.sqlPassed++ }
        if ($event.Action -eq 'fail' -and $event.Test -and $summary.failedTests.Count -lt 10) { $summary.failedTests += ($event.Package + '/' + $event.Test) }
    }
    if ($tests.code -ne 0) { throw 'Tests failed; inspect failedTests and tests logs' }
    if ($Mode -eq 'Full' -and ($summary.testsSkipped -ne 0 -or $summary.sqlPassed -eq 0)) {
        throw 'Full requires SQL execution and zero skipped tests'
    }
    Invoke-GoStage 'vet' (@('vet') + $testPackages)
    if ($Mode -eq 'Full') {
        $env:GOARCH = 'amd64'
        $env:GOOS = 'linux'
        Invoke-GoStage 'build-linux-amd64' @('build', './...')
        $env:GOOS = 'windows'
        Invoke-GoStage 'build-windows-amd64' @('build', './...')
    }
    $summary.ok = $true
} catch {
    $summary['error'] = $_.Exception.Message
} finally {
    try { Stop-VerifyDatabase } catch {
        $summary.ok = $false
        $summary['cleanupError'] = $_.Exception.Message
        $summary['clusterToInspect'] = $verifyClusterRoot
    }
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
    $summary['seconds'] = [Math]::Round($watch.Elapsed.TotalSeconds, 2)
    $rendered = $summary | ConvertTo-Json -Depth 5 -Compress
    [IO.File]::WriteAllText((Join-Path $logRoot 'summary.json'), $rendered + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Write-Output $rendered
}
if (-not $summary.ok) { exit 1 }
