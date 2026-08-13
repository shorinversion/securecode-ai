[CmdletBinding()]
param(
    [string]$RepositoryCopy,
    [string]$SourcePath
)

$ErrorActionPreference = 'Stop'
$expectedNormalizedSha256 = '537c8c5c1fd0c016d214f21dee3b369a4838715c6fc4ae2be60690ae093bb9ac'

if ([string]::IsNullOrWhiteSpace($RepositoryCopy)) {
    $RepositoryCopy = Join-Path $PSScriptRoot 'deep-research-methodology-2026-08-12.md'
}

function Get-NormalizedText {
    param([string]$Path)
    return [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8).Replace("`r`n", "`n").TrimEnd()
}

function Get-Utf8Sha256 {
    param([string]$Text)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $algorithm.Dispose()
    }
}

$repositoryText = Get-NormalizedText -Path $RepositoryCopy
$repositoryHash = Get-Utf8Sha256 -Text $repositoryText
$lines = [IO.File]::ReadAllLines($RepositoryCopy, [Text.Encoding]::UTF8).Count
$citationMarkers = [regex]::Matches($repositoryText, '\uE200cite\uE202').Count
$urls = [regex]::Matches($repositoryText, 'https?://[^\s\)\]>]+').Count
$referenceHeadings = [regex]::Matches(
    $repositoryText,
    '(?mi)^#{1,4}\s+(references|sources|bibliography)\s*$'
).Count

$result = [ordered]@{
    repository_copy = [IO.Path]::GetFullPath($RepositoryCopy)
    lines = $lines
    citation_markers = $citationMarkers
    resolvable_urls = $urls
    reference_headings = $referenceHeadings
    normalized_sha256 = $repositoryHash
    expected_sha256 = $expectedNormalizedSha256
    hash_matches_expected = ($repositoryHash -eq $expectedNormalizedSha256)
}

if (-not [string]::IsNullOrWhiteSpace($SourcePath)) {
    $sourceText = Get-NormalizedText -Path $SourcePath
    $sourceHash = Get-Utf8Sha256 -Text $sourceText
    $result.source_path = [IO.Path]::GetFullPath($SourcePath)
    $result.source_normalized_sha256 = $sourceHash
    $result.source_matches_repository = ($sourceText -ceq $repositoryText)
}

[pscustomobject]$result | ConvertTo-Json -Depth 3

if (-not $result.hash_matches_expected) {
    throw 'Repository copy does not match the expected normalized SHA-256.'
}

if ($result.Contains('source_matches_repository') -and -not $result.source_matches_repository) {
    throw 'Source content does not match the repository copy after normalization.'
}
