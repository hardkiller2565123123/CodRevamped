# Opt-in launch only. Build/deploy version.dll and server beforehand.
$ErrorActionPreference = 'Stop'
$gameRoot = 'D:\unlock\Modern Warfare\Call of Duty Modern Warfare (1.20)'
$gameExe = Join-Path $gameRoot 'game_dx12_ship_replay.exe'
$serverExe = Join-Path $gameRoot 'RevampedIW8Server.exe'
if (Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -in @($gameExe, $serverExe) }) {
    throw 'Close this game and backend before using the opt-in launcher.'
}
$previous = $env:CODREVAMPED_MW120_LOCAL_MANIFESTS
try {
    $env:CODREVAMPED_MW120_LOCAL_MANIFESTS = '1'
    Start-Process -FilePath $serverExe -WorkingDirectory $gameRoot -WindowStyle Hidden
    Start-Process -FilePath $gameExe -WorkingDirectory $gameRoot -ArgumentList '-uid odin' -WindowStyle Minimized
} finally {
    $env:CODREVAMPED_MW120_LOCAL_MANIFESTS = $previous
}
