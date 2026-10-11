param(
    [string]$Configuration = 'Release',
    [switch]$Clean
)
$ErrorActionPreference = 'Stop'
$cmake = 'C:\Program Files\CMake\bin\cmake.exe'
if (-not (Test-Path -LiteralPath $cmake)) { $cmake = (Get-Command cmake -ErrorAction Stop).Source }
& $cmake -S $PSScriptRoot -B (Join-Path $PSScriptRoot 'build') -A x64
if ($LASTEXITCODE) { throw 'DW server configuration failed.' }
$buildArguments = @('--build', (Join-Path $PSScriptRoot 'build'), '--config', $Configuration, '--parallel', '2')
if ($Clean) { $buildArguments += '--clean-first' }
& $cmake @buildArguments
if ($LASTEXITCODE) { throw 'DW server compilation failed.' }
Get-FileHash -LiteralPath (Join-Path $PSScriptRoot "build\$Configuration\iw8-dw-server.exe") -Algorithm SHA256
