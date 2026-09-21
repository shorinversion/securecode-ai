[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Tag = 'securecode-ai/repair-validator:local',

    [ValidateSet('linux/amd64', 'linux/arm64')]
    [string]$Platform = 'linux/amd64',

    [switch]$PersistForCurrentUser
)

$ErrorActionPreference = 'Stop'
$docker = Get-Command docker -ErrorAction Stop
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dockerfile = Join-Path $PSScriptRoot 'repair-validator.Dockerfile'

& $docker.Source build `
    --pull `
    --platform $Platform `
    --file $dockerfile `
    --tag $Tag `
    $repositoryRoot
if ($LASTEXITCODE -ne 0) {
    throw "Repair validator image build failed with exit code $LASTEXITCODE."
}

$imageId = (& $docker.Source image inspect --format '{{.Id}}' $Tag).Trim()
if ($LASTEXITCODE -ne 0 -or $imageId -notmatch '^sha256:[0-9a-f]{64}$') {
    throw 'Docker did not return a digest-pinned repair validator image ID.'
}

$env:SECURECODE_REPAIR_VALIDATOR_IMAGE = $imageId
$env:SECURECODE_AI_VALIDATION_IMAGE = $imageId

if ($PersistForCurrentUser) {
    [Environment]::SetEnvironmentVariable(
        'SECURECODE_REPAIR_VALIDATOR_IMAGE',
        $imageId,
        [EnvironmentVariableTarget]::User
    )
    [Environment]::SetEnvironmentVariable(
        'SECURECODE_AI_VALIDATION_IMAGE',
        $imageId,
        [EnvironmentVariableTarget]::User
    )
}

Write-Host "SECURECODE_REPAIR_VALIDATOR_IMAGE=$imageId"
Write-Host "SECURECODE_AI_VALIDATION_IMAGE=$imageId"
Write-Output $imageId
