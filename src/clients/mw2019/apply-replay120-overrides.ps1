param(
    [Parameter(Mandatory=$true)][string]$ReplaySourceRoot
)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'replay120'
if (!(Test-Path $src)) { throw "Missing replay120 override directory: $src" }
if (!(Test-Path $ReplaySourceRoot)) { throw "Replay source root does not exist: $ReplaySourceRoot" }
Get-ChildItem -LiteralPath $src -File | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $ReplaySourceRoot $_.Name) -Force
    Write-Host "[Replay120] $($_.Name)"
}
Write-Host "Applied CodRevamped IW8 Replay 1.20 compatibility overrides."
