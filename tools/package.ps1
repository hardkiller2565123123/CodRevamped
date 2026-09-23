[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$Version = 'dev',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if (-not $SkipBuild) { & (Join-Path $PSScriptRoot 'build.ps1') -Configuration Release }
$releaseDirectory = Join-Path $repoRoot 'artifacts\releases'
New-Item -ItemType Directory -Force -Path $releaseDirectory | Out-Null
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Add-TreeEntries([string]$Directory, [string]$Prefix, $Entries) {
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    foreach ($file in Get-ChildItem -LiteralPath $Directory -Recurse -File) {
        if ($file.Extension -in @('.exe','.dll','.lib','.obj','.pdb','.ilk','.exp','.log','.dmp','.user','.suo','.pyc','.zip','.rartemp')) { continue }
        if ($file.Name -eq '.env' -or $file.Name.StartsWith('.env.')) { continue }
        $relative = $file.FullName.Substring($Directory.Length).TrimStart('\','/')
        $Entries.Add([pscustomobject]@{ Source=$file.FullName; Name=("$Prefix/$relative").TrimStart('/').Replace('\','/') })
    }
}

function Write-Archive([string]$Name, $Entries) {
    $path = Join-Path $releaseDirectory $Name
    $stream = [IO.File]::Open($path, [IO.FileMode]::Create, [IO.FileAccess]::Write)
    $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($entry in $Entries | Sort-Object Name) {
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $entry.Source, $entry.Name, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
    return $path
}

$clients = [ordered]@{
    BO4 = @('version.dll', 'dxgi.dll')
    ColdWar = @('version.dll')
    MW2019 = @('version.dll', 'RevampedIW8Server.exe')
    BO6 = @('version.dll')
    MW3 = @('version.dll')
}
# Check every expected build output before creating any release archive.
foreach ($client in $clients.Keys) {
    foreach ($file in $clients[$client]) {
        $path = Join-Path $repoRoot "artifacts\bin\$client\Release\$file"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing build output: $path" }
    }
}

$archives = [Collections.Generic.List[string]]::new()
$sourceEntries = [Collections.Generic.List[object]]::new()
foreach ($directory in @('src','build','assets','third_party','tools','docs','.github')) {
    Add-TreeEntries (Join-Path $repoRoot $directory) $directory $sourceEntries
}
foreach ($file in @('CodRevamped.sln','Directory.Build.props','Directory.Build.targets','.gitignore','.gitattributes','README.md','LICENSE','THIRD_PARTY_NOTICES.md')) {
    $sourceEntries.Add([pscustomobject]@{ Source=(Join-Path $repoRoot $file); Name=$file })
}
$archives.Add((Write-Archive "CodRevamped-$Version-source.zip" $sourceEntries))

foreach ($client in $clients.Keys) {
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($file in $clients[$client]) {
        $entries.Add([pscustomobject]@{ Source=(Join-Path $repoRoot "artifacts\bin\$client\Release\$file"); Name=$file })
    }
    Add-TreeEntries (Join-Path $repoRoot 'assets') '' $entries
    foreach ($file in @('README.md','LICENSE','THIRD_PARTY_NOTICES.md')) {
        $entries.Add([pscustomobject]@{ Source=(Join-Path $repoRoot $file); Name=$file })
    }
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $repoRoot 'third_party') -Recurse -File) {
        if ($file.Name -match '^(LICENSE|COPYING|COPYRIGHT|NOTICE)' -or $file.Name -eq 'SOURCE_NOTICES.txt') {
            $entries.Add([pscustomobject]@{ Source=$file.FullName; Name=$file.FullName.Substring($repoRoot.Length+1).Replace('\','/') })
        }
    }
    $archives.Add((Write-Archive "CodRevamped-$client-$Version-win64.zip" $entries))
}
$checksums = foreach ($path in $archives) {
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $([IO.Path]::GetFileName($path))"
}
$checksums | Set-Content -LiteralPath (Join-Path $releaseDirectory "SHA256SUMS-$Version.txt") -Encoding ascii
Write-Host "Release packages: $releaseDirectory"
