[CmdletBinding()]
param(
    [string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $resolvedRoot = (& git rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($resolvedRoot)) {
        throw 'Cannot resolve repository root. Run inside the SecureCode AI repository or pass -RepositoryRoot.'
    }
    $RepositoryRoot = $resolvedRoot.Trim()
}

$RepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)

function Write-Section {
    param([string]$Title)
    Write-Output ''
    Write-Output ("=== {0} ===" -f $Title)
}

$requiredFiles = @(
    'docs\CONTEXT.md',
    'docs\PLAN.md',
    'docs\DECISIONS.md',
    'CHANGELOG.md'
)

$missingFiles = @()
foreach ($relativePath in $requiredFiles) {
    $absolutePath = Join-Path $RepositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
        $missingFiles += $relativePath
    }
}

if ($missingFiles.Count -gt 0) {
    throw ("Missing project-memory files: {0}" -f ($missingFiles -join ', '))
}

Write-Output ("SecureCode AI context snapshot: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
Write-Output ("Repository: {0}" -f $RepositoryRoot)

$planPath = Join-Path $RepositoryRoot 'docs\PLAN.md'
$planLines = Get-Content -LiteralPath $planPath -Encoding UTF8

Write-Section 'Plan position'
$position = $planLines | Select-Object -Skip 2 -First 5
$position | ForEach-Object { Write-Output $_ }

Write-Section 'Active or blocked tasks'
$activeTasks = $planLines | Where-Object {
    $_ -match '^\| `P\d+\.\d+` .*\| `(IN PROGRESS|BLOCKED)` \|$'
}
if ($activeTasks) {
    $activeTasks | ForEach-Object { Write-Output $_ }
}
else {
    Write-Output 'No tasks marked IN PROGRESS or BLOCKED.'
}

Write-Section 'Compact durable context'
Get-Content -LiteralPath (Join-Path $RepositoryRoot 'docs\CONTEXT.md') -Encoding UTF8

Write-Section 'Open architectural decisions'
$decisionLines = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'docs\DECISIONS.md') -Encoding UTF8
$insideOpenDecisions = $false
$foundOpenDecisions = $false
$openSectionHeadingSeen = $false
foreach ($line in $decisionLines) {
    if ($line -eq '<!-- OPEN_DECISIONS -->') {
        $insideOpenDecisions = $true
        $foundOpenDecisions = $true
        continue
    }
    if ($insideOpenDecisions -and $line -match '^## ') {
        if (-not $openSectionHeadingSeen) {
            $openSectionHeadingSeen = $true
            continue
        }
        break
    }
    if ($insideOpenDecisions -and -not [string]::IsNullOrWhiteSpace($line)) {
        Write-Output $line
    }
}
if (-not $foundOpenDecisions) {
    Write-Output 'Open-decisions section not found.'
}

Write-Section 'Worktree'
Push-Location $RepositoryRoot
try {
    $status = (& git status --short)
    if ($LASTEXITCODE -ne 0) {
        throw 'git status failed.'
    }
    if ($status) {
        $status | ForEach-Object { Write-Output $_ }
    }
    else {
        Write-Output 'Clean worktree.'
    }
}
finally {
    Pop-Location
}
