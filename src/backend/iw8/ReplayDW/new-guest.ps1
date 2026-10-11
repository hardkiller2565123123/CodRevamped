param(
    [string]$Python = 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
)
$ErrorActionPreference = 'Stop'
# Compatibility entry point: this now packages the same client for everyone.
# Each Windows user creates their own identity on first game launch. The server
# is not stopped and no account, access key or initial friendship is provisioned.
& $Python -B (Join-Path $PSScriptRoot 'tools\package-remote-guest.py')
if ($LASTEXITCODE) { throw 'Universal client packaging failed.' }
