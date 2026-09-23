[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug', 'All')]
    [string]$Configuration = 'Release',
    [ValidateSet('Solution', 'ColdWarClient', 'MW2019Client', 'BO4Client', 'BO6Client', 'MW3Client', 'RevampedIW8Server', 'BO4', 'ColdWar', 'MW2019', 'BO6', 'MW3', 'IW8Server')]
    [string]$Target = 'Solution',
    [ValidateRange(1, 32)]
    [int]$Jobs = 2
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Install Visual Studio with Desktop development with C++ (MSVC v143 and Windows SDK).'
}
$msbuild = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' |
    Select-Object -First 1
if (-not $msbuild) { throw 'MSBuild was not found in a Visual Studio installation.' }

$logDirectory = Join-Path $repoRoot 'artifacts\build'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$configurations = if ($Configuration -eq 'All') { @('Release', 'Debug') } else { @($Configuration) }
foreach ($buildConfiguration in $configurations) {
    $log = Join-Path $logDirectory "$Target-$buildConfiguration.log"
    $arguments = @(
        (Join-Path $repoRoot 'CodRevamped.sln'),
        "/p:Configuration=$buildConfiguration", '/p:Platform=x64',
        "/m:$Jobs", '/nologo', '/v:minimal', "/flp:logfile=$log;verbosity=normal"
    )
    if ($Target -ne 'Solution') {
        $names = @{ BO4Client='BO4'; ColdWarClient='ColdWar'; MW2019Client='MW2019'; BO6Client='BO6'; MW3Client='MW3'; RevampedIW8Server='IW8Server' }
        $project = if ($names.ContainsKey($Target)) { $names[$Target] } else { $Target }
        $folder = if ($project -eq 'IW8Server') { 'Backend' } else { 'Clients' }
        $arguments += "/t:$folder\$project"
    }
    & $msbuild @arguments
    if ($LASTEXITCODE -ne 0) { throw "Build failed ($LASTEXITCODE). See $log" }
}
