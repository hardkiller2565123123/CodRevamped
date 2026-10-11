$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'The backend MSVC x64 toolchain was not found.' }
& (Join-Path $installation 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation -NoLogo
$objects = Join-Path $root 'build\iw8-dw-server.dir\Release'
$target = Join-Path $root 'data\tournament-map-check'
New-Item -ItemType Directory -Force -Path $target | Out-Null
# Link the exact Release objects used by the server; do not reconstruct a
# second implementation of the selector for this comparison.
$arguments = @('/nologo', '/std:c++20', '/EHsc', '/W4', '/WX', '/MD',
    ('/Fo' + (Join-Path $target 'driver.obj')),
    ('/Fe' + (Join-Path $target 'tournament-map-check.exe')),
    (Join-Path $PSScriptRoot 'tournament-map-check.cpp'),
    (Join-Path $objects 'tournament_map_policy.obj'),
    (Join-Path $objects 'crypto.obj'), 'bcrypt.lib')
& cl.exe @arguments
if ($LASTEXITCODE) { throw 'Compiled tournament selector comparison driver failed.' }
Write-Host 'Built comparison driver using the exact server selector and crypto objects.'
