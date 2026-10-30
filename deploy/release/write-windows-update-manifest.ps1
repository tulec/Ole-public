param(
    [Parameter(Mandatory = $true)]
    [string]$InputDir,
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$BaseDownloadUrl,
    [ValidateSet("stable", "beta")]
    [string]$Channel = "stable",
    [string]$ReleaseNotesUrl = "",
    [string]$OutputFile = "",
    [string]$MinimumServerVersion = "",
    [string]$MaximumServerVersion = "",
    [string]$MinimumRollbackVersion = "",
    [string]$RollbackVersion = "",
    [string]$RollbackInstallerUrl = "",
    [string]$RollbackSHA256 = "",
    [string]$RollbackSignatureUrl = "",
    [string]$RollbackCertificateUrl = "",
    [string]$RollbackReleaseNotesUrl = "",
    [string]$RollbackReason = ""
)

$ErrorActionPreference = "Stop"

function Resolve-ManifestUrl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $trimmed = $Value.Trim()
    if (-not $trimmed) {
        return ""
    }
    if ($trimmed -match '^https?://') {
        return $trimmed
    }
    return ($BaseUrl.TrimEnd("/") + "/" + $trimmed.TrimStart("/"))
}

$resolvedInputDir = (Resolve-Path $InputDir).Path
$installer = Get-ChildItem -Path $resolvedInputDir -File |
    Where-Object { $_.Extension -eq ".exe" } |
    Sort-Object Name |
    Select-Object -First 1

if (-not $installer) {
    throw "No installer .exe found in $resolvedInputDir"
}

if (-not $OutputFile) {
    $OutputFile = Join-Path $resolvedInputDir "ole-update-$Channel.json"
}

$hash = (Get-FileHash -Algorithm SHA256 -Path $installer.FullName).Hash.ToLowerInvariant()
$base = $BaseDownloadUrl.TrimEnd("/")
$fileName = $installer.Name
$manifest = [ordered]@{
    channel = $Channel
    version = $Version.Trim()
    publishedAtUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    installerUrl = "$base/$fileName"
    sha256 = $hash
    releaseNotesUrl = $ReleaseNotesUrl
    signatureUrl = "$base/$fileName.sig"
    certificateUrl = "$base/$fileName.pem"
}

if ($MinimumServerVersion.Trim() -or $MaximumServerVersion.Trim() -or $MinimumRollbackVersion.Trim()) {
    $compatibility = [ordered]@{}
    if ($MinimumServerVersion.Trim()) {
        $compatibility.minimumServerVersion = $MinimumServerVersion.Trim()
    }
    if ($MaximumServerVersion.Trim()) {
        $compatibility.maximumServerVersion = $MaximumServerVersion.Trim()
    }
    if ($MinimumRollbackVersion.Trim()) {
        $compatibility.minimumRollbackVersion = $MinimumRollbackVersion.Trim()
    }
    $manifest.compatibility = $compatibility
}

if ($RollbackVersion.Trim() -or $RollbackInstallerUrl.Trim()) {
    if (-not $RollbackVersion.Trim()) {
        throw "RollbackVersion is required when rollback metadata is emitted"
    }
    if (-not $RollbackInstallerUrl.Trim()) {
        throw "RollbackInstallerUrl is required when rollback metadata is emitted"
    }
    if (-not $RollbackSHA256.Trim()) {
        throw "RollbackSHA256 is required when rollback metadata is emitted"
    }

    $rollback = [ordered]@{
        version = $RollbackVersion.Trim()
        installerUrl = Resolve-ManifestUrl -BaseUrl $base -Value $RollbackInstallerUrl
        sha256 = $RollbackSHA256.Trim().ToLowerInvariant()
    }
    if ($RollbackReleaseNotesUrl.Trim()) {
        $rollback.releaseNotesUrl = Resolve-ManifestUrl -BaseUrl $base -Value $RollbackReleaseNotesUrl
    }
    if ($RollbackSignatureUrl.Trim()) {
        $rollback.signatureUrl = Resolve-ManifestUrl -BaseUrl $base -Value $RollbackSignatureUrl
    }
    if ($RollbackCertificateUrl.Trim()) {
        $rollback.certificateUrl = Resolve-ManifestUrl -BaseUrl $base -Value $RollbackCertificateUrl
    }
    if ($RollbackReason.Trim()) {
        $rollback.reason = $RollbackReason.Trim()
    }
    $manifest.rollback = $rollback
}

$manifest | ConvertTo-Json | Set-Content -Path $OutputFile -Encoding utf8
Write-Host "Wrote Windows update manifest to $OutputFile"
