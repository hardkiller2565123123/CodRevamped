$ErrorActionPreference = 'Stop'
$configuration = Get-Content -LiteralPath 'E:\replay-compiler\replay-project.local.json' -Raw | ConvertFrom-Json
$env:PYTHONPATH = $configuration.python_dependency_root
$python = 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $python -B (Join-Path $PSScriptRoot 'tools\verify-server-deployment.py')
if ($LASTEXITCODE) { throw 'Server deployment binding failed verification.' }
