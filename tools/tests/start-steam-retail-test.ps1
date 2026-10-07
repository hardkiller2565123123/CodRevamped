[CmdletBinding()]
param([switch]$ParserProbe)
$ErrorActionPreference = 'Stop'
$retailDir = 'D:\SteamLibrary\steamapps\common\Call of Duty Modern Warfare'
$repoDir = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$dll = Join-Path $repoDir 'artifacts\bin\MW2019\Debug\version.dll'
if (!(Test-Path -LiteralPath $dll)) { throw 'Build the MW2019 client before testing.' }
$targets = @('ModernWarfare.exe', 'bootstrapper.exe', 'bootstrappercrashhandler.exe') | ForEach-Object { Join-Path $retailDir $_ }
foreach ($item in @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -in $targets })) {
    $process = Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
    if ($process) {
        Stop-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
        if (!$process.WaitForExit(10000)) { throw "Test process $($item.ProcessId) did not stop." }
    }
}
$archive = Join-Path $retailDir ('codrevamped-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $archive | Out-Null
foreach ($name in @('version.dll', 'steam_retail_parser.log', 'mw2019_redirect.log')) {
    $path = Join-Path $retailDir $name
    if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination $archive }
}
Copy-Item -LiteralPath $dll -Destination $retailDir
if ((Get-FileHash $dll).Hash -ne (Get-FileHash (Join-Path $retailDir 'version.dll')).Hash) { throw 'DLL deployment mismatch' }
$settings = @{
    CODREVAMPED_BACKGROUND_TEST = '1'
    CODREVAMPED_RETAIL_IAT_ONLY = '1'
    CODREVAMPED_RETAIL_NO_VEH = '1'
    CODREVAMPED_RETAIL_PARSER_PROBE = $(if ($ParserProbe) { '1' } else { '0' })
    SteamAppId = '2000950'
    SteamGameId = '2000950'
}
$previous = @{}
try {
    foreach ($key in $settings.Keys) {
        $previous[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        [Environment]::SetEnvironmentVariable($key, $settings[$key], 'Process')
    }
    $launcher = Start-Process -FilePath (Join-Path $retailDir 'bootstrapper.exe') -WorkingDirectory $retailDir -WindowStyle Hidden -PassThru
    Write-Output "Verified deployment; hidden bootstrap PID=$($launcher.Id); parserProbe=$ParserProbe"
} finally {
    foreach ($key in $previous.Keys) { [Environment]::SetEnvironmentVariable($key, $previous[$key], 'Process') }
}
