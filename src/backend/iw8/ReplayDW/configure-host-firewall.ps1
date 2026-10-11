param([switch]$Elevate)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $Elevate) { throw 'Run configure-host-firewall.ps1 -Elevate and approve its Windows administrator prompt.' }
    $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'))
    Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments | Out-Null
    return
}
$server = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'build\Release\iw8-dw-server.exe'))
$game = 'E:\IW8\Builds\1.20-replay\game_dx12_ship_replay_dw.exe'
foreach ($path in $server,$game) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing executable: $path" }
}
$rules = @(
    @{Name='ReplayDW-Backend-TCP'; Program=$server; Protocol='TCP'; Ports='8085,3075'},
    @{Name='ReplayDW-Backend-UDP'; Program=$server; Protocol='UDP'; Ports='3076,3077,3078'},
    @{Name='ReplayDW-Game-UDP'; Program=$game; Protocol='UDP'; Ports='3074'}
)
foreach ($rule in $rules) {
    $existing = Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
    if ($existing) { Remove-NetFirewallRule -Name $rule.Name }
    New-NetFirewallRule -Name $rule.Name -DisplayName $rule.Name -Direction Inbound -Action Allow -Profile Any -Program $rule.Program -Protocol $rule.Protocol -LocalPort ($rule.Ports.Split(',')) | Out-Null
}
@{schema=1; configured_utc=[DateTime]::UtcNow.ToString('o'); rules=$rules} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'data\host-firewall-receipt.json') -Encoding utf8
