$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
Import-Module (Join-Path $vs 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
Push-Location $repo
try {
    cl /nologo /EHsc /std:c++17 /Fe:artifacts\build\mw116-startup-debug.exe /Fo:artifacts\build\mw116-startup-debug.obj tools\tests\mw116-startup-debug.cpp
    if ($LASTEXITCODE) { throw 'Diagnostic build failed' }
    & .\artifacts\build\mw116-startup-debug.exe 'D:\unlock\Modern Warfare\Call of Duty Modern Warfare (1.16)\ModernWarfare.exe' |
        Tee-Object -FilePath artifacts\build\mw116-startup-debug.log
} finally { Pop-Location }
