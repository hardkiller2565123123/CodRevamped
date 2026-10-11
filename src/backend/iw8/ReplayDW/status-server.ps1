$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'data\primary-backend.json')) {
    & 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' (Join-Path $PSScriptRoot 'tools\control-primary-server.py') status
    if ($LASTEXITCODE) { throw 'Primary droplet operation failed.' }
    return
}

Invoke-RestMethod -Uri 'http://127.0.0.1:8085/status' -TimeoutSec 3 | Format-List
