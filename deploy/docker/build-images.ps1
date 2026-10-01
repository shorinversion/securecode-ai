[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Namespace = 'securecode-ai',

    [ValidateNotNullOrEmpty()]
    [string]$Version = '1.1.0',

    [ValidateSet('linux/amd64', 'linux/arm64')]
    [string]$Platform = 'linux/amd64'
)

$ErrorActionPreference = 'Stop'
$docker = Get-Command docker -ErrorAction Stop
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$runtimeTag = "$Namespace/runtime:$Version"
$serverTag = "$Namespace/server:$Version"
$workerTag = "$Namespace/worker:$Version"

function Invoke-ImageBuild {
    param(
        [Parameter(Mandatory)]
        [string]$Dockerfile,

        [Parameter(Mandatory)]
        [string]$Tag,

        [string[]]$BuildArguments = @(),

        [switch]$Pull
    )

    $arguments = @(
        'build',
        '--platform', $Platform,
        '--file', $Dockerfile,
        '--tag', $Tag
    )
    if ($Pull) {
        $arguments += '--pull'
    }
    foreach ($argument in $BuildArguments) {
        $arguments += @('--build-arg', $argument)
    }
    $arguments += $repositoryRoot
    & $docker.Source @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Image build failed for $Tag with exit code $LASTEXITCODE."
    }
}

Invoke-ImageBuild `
    -Dockerfile (Join-Path $PSScriptRoot 'runtime.Dockerfile') `
    -Tag $runtimeTag `
    -Pull
Invoke-ImageBuild `
    -Dockerfile (Join-Path $PSScriptRoot 'server.Dockerfile') `
    -Tag $serverTag `
    -BuildArguments @("RUNTIME_IMAGE=$runtimeTag")
Invoke-ImageBuild `
    -Dockerfile (Join-Path $PSScriptRoot 'worker.Dockerfile') `
    -Tag $workerTag `
    -BuildArguments @("RUNTIME_IMAGE=$runtimeTag")

foreach ($tag in ($runtimeTag, $serverTag, $workerTag)) {
    $imageId = (& $docker.Source image inspect --format '{{.Id}}' $tag).Trim()
    if ($LASTEXITCODE -ne 0 -or $imageId -notmatch '^sha256:[0-9a-f]{64}$') {
        throw "Docker did not return an immutable image ID for $tag."
    }
    Write-Output "$tag=$imageId"
}
