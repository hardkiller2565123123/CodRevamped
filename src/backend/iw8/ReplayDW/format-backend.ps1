param(
    [string]$Formatter = 'C:\Program Files\LLVM\bin\clang-format.exe',
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Formatter -PathType Leaf)) {
    $Formatter = (Get-Command clang-format -ErrorAction Stop).Source
}

$sourceRoot = Join-Path $PSScriptRoot 'src'
$files = Get-ChildItem -LiteralPath $sourceRoot -File -Recurse |
    Where-Object { $_.Extension -in '.cpp', '.h' }
$arguments = @('--style=file')
if ($Check) {
    $arguments += '--dry-run', '--Werror'
} else {
    $arguments += '-i'
}

& $Formatter @arguments @($files.FullName)
if ($LASTEXITCODE -ne 0) {
    throw 'Backend C++ formatting failed.'
}

Write-Host ('Backend formatting checked/applied to {0} files.' -f $files.Count)
