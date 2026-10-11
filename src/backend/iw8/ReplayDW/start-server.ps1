$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'data\primary-backend.json')) {
    & 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' (Join-Path $PSScriptRoot 'tools\control-primary-server.py') start
    if ($LASTEXITCODE) { throw 'Primary droplet operation failed.' }
    return
}

$executable = Join-Path $PSScriptRoot 'build\Release\iw8-dw-server.exe'
$data = Join-Path $PSScriptRoot 'data'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Build the server with build-server.ps1 first.' }
New-Item -ItemType Directory -Force -Path $data | Out-Null
foreach ($port in 8085,8443,3075) {
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        throw "Port $port is already occupied. Use status-server.ps1 or stop-server.ps1 before starting."
    }
}
$process = Start-Process -FilePath $executable -ArgumentList @($data) -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $data 'server.stdout.log') -RedirectStandardError (Join-Path $data 'server.stderr.log')
@{ pid=$process.Id; executable=$executable; sha256=(Get-FileHash -LiteralPath $executable).Hash.ToLowerInvariant() } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $data 'server-process.json') -Encoding utf8
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    if ($process.HasExited) { throw 'DW server exited; inspect data\server.log.' }
    try {
        $status = Invoke-RestMethod -Uri 'http://127.0.0.1:8085/health' -TimeoutSec 1
        if ($status.server -eq 'iw8-dw') { $status; return }
    } catch { Start-Sleep -Milliseconds 200 }
}
throw 'DW server did not become ready; inspect data\server.log.'
