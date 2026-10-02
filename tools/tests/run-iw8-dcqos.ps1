$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Visual C++ tools not found.' }
Import-Module (Join-Path $vs 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
Push-Location $repo
try {
    New-Item -ItemType Directory -Force 'artifacts\build' | Out-Null
    cl /nologo /EHsc /std:c++17 /Fe:artifacts\build\iw8_dcqos_test.exe /Fo:artifacts\build\iw8_dcqos_test.obj tools\tests\iw8_dcqos_test.cpp
    if ($LASTEXITCODE) { throw "Test build failed: $LASTEXITCODE" }
    & .\artifacts\build\iw8_dcqos_test.exe
    if ($LASTEXITCODE) { throw "Test failed: $LASTEXITCODE" }
} finally { Pop-Location }
