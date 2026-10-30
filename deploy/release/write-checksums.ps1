param(
    [Parameter(Mandatory = $true)]
    [string]$InputDir,
    [string]$OutputFile = ""
)

$ErrorActionPreference = "Stop"

$resolvedInputDir = Resolve-Path $InputDir
if (-not $OutputFile) {
    $OutputFile = Join-Path $resolvedInputDir "SHA256SUMS.txt"
}

$files = Get-ChildItem -Path $resolvedInputDir -File |
    Where-Object { $_.Name -notmatch '\.sig$|\.pem$|^SHA256SUMS\.txt$' } |
    Sort-Object Name

if (-not $files) {
    throw "No files found to checksum in $resolvedInputDir"
}

$lines = foreach ($file in $files) {
    $hash = Get-FileHash -Algorithm SHA256 -Path $file.FullName
    "{0}  {1}" -f $hash.Hash.ToLowerInvariant(), $file.Name
}

Set-Content -Path $OutputFile -Value $lines -Encoding ascii
Write-Host "Wrote checksum manifest to $OutputFile"
