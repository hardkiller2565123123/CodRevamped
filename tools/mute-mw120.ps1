[CmdletBinding()]
param([switch]$Unmute)
$ErrorActionPreference = 'Stop'
$gamePath = 'D:\unlock\Modern Warfare\Call of Duty Modern Warfare (1.20)\game_dx12_ship_replay.exe'
$gameIds = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $gamePath } | ForEach-Object { [uint32]$_.ProcessId })
if (!$gameIds.Count) { throw 'The exact MW2019 1.20 DX12 executable is not running.' }

if (-not ('Mw120SessionAudio' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class Mw120SessionAudio {
    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class Enumerator {}
    [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IDevices {
        [PreserveSig] int EnumAudioEndpoints(int flow, uint mask, out ICollection devices);
    }
    [ComImport, Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface ICollection {
        [PreserveSig] int GetCount(out uint count);
        [PreserveSig] int Item(uint index, out IDevice device);
    }
    [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IDevice {
        [PreserveSig] int Activate(ref Guid iid, uint context, IntPtr parameters, [MarshalAs(UnmanagedType.IUnknown)] out object instance);
    }
    [ComImport, Guid("77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IManager {
        [PreserveSig] int GetAudioSessionControl(IntPtr guid, uint flags, out IntPtr control);
        [PreserveSig] int GetSimpleAudioVolume(IntPtr guid, uint flags, out IntPtr volume);
        [PreserveSig] int GetSessionEnumerator(out ISessions sessions);
    }
    [ComImport, Guid("E2F5BB11-0570-40CA-ACDD-3AA01277DEE8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface ISessions {
        [PreserveSig] int GetCount(out int count);
        [PreserveSig] int GetSession(int index, [MarshalAs(UnmanagedType.IUnknown)] out object session);
    }
    [ComImport, Guid("BFB7FF88-7239-4FC9-8FA2-07C950BE9C6D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IControl {
        [PreserveSig] int GetState(out int state);
        [PreserveSig] int GetDisplayName([MarshalAs(UnmanagedType.LPWStr)] out string value);
        [PreserveSig] int SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string value, IntPtr context);
        [PreserveSig] int GetIconPath([MarshalAs(UnmanagedType.LPWStr)] out string value);
        [PreserveSig] int SetIconPath([MarshalAs(UnmanagedType.LPWStr)] string value, IntPtr context);
        [PreserveSig] int GetGroupingParam(out Guid grouping);
        [PreserveSig] int SetGroupingParam(ref Guid grouping, IntPtr context);
        [PreserveSig] int RegisterAudioSessionNotification(IntPtr notification);
        [PreserveSig] int UnregisterAudioSessionNotification(IntPtr notification);
        [PreserveSig] int GetSessionIdentifier([MarshalAs(UnmanagedType.LPWStr)] out string value);
        [PreserveSig] int GetSessionInstanceIdentifier([MarshalAs(UnmanagedType.LPWStr)] out string value);
        [PreserveSig] int GetProcessId(out uint pid);
    }
    [ComImport, Guid("87CE5498-68D6-44E5-9215-6DA47EF883D8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IVolume {
        [PreserveSig] int SetMasterVolume(float level, ref Guid context);
        [PreserveSig] int GetMasterVolume(out float level);
        [PreserveSig] int SetMute([MarshalAs(UnmanagedType.Bool)] bool mute, ref Guid context);
        [PreserveSig] int GetMute([MarshalAs(UnmanagedType.Bool)] out bool mute);
    }
    public static int SetMute(uint[] pids, bool requestedMute) {
        var enumerator = new Enumerator();
        ICollection devices = null;
        int muted = 0;
        try {
            Marshal.ThrowExceptionForHR(((IDevices)enumerator).EnumAudioEndpoints(0, 1, out devices));
            uint count; Marshal.ThrowExceptionForHR(devices.GetCount(out count));
            for (uint d = 0; d < count; ++d) {
                IDevice device = null; object managerObject = null; ISessions sessions = null;
                try {
                    Marshal.ThrowExceptionForHR(devices.Item(d, out device));
                    Guid iid = typeof(IManager).GUID;
                    Marshal.ThrowExceptionForHR(device.Activate(ref iid, 23, IntPtr.Zero, out managerObject));
                    Marshal.ThrowExceptionForHR(((IManager)managerObject).GetSessionEnumerator(out sessions));
                    int n; Marshal.ThrowExceptionForHR(sessions.GetCount(out n));
                    for (int s = 0; s < n; ++s) {
                        object session = null;
                        try {
                            Marshal.ThrowExceptionForHR(sessions.GetSession(s, out session));
                            uint pid; Marshal.ThrowExceptionForHR(((IControl)session).GetProcessId(out pid));
                            if (Array.IndexOf(pids, pid) < 0) continue;
                            var volume = (IVolume)session; Guid context = Guid.Empty;
                            Marshal.ThrowExceptionForHR(volume.SetMute(requestedMute, ref context));
                            bool isMuted; Marshal.ThrowExceptionForHR(volume.GetMute(out isMuted));
                            if (isMuted != requestedMute) throw new InvalidOperationException("Audio mute-state verification failed.");
                            ++muted;
                        } finally { if (session != null) Marshal.ReleaseComObject(session); }
                    }
                } finally {
                    if (sessions != null) Marshal.ReleaseComObject(sessions);
                    if (managerObject != null) Marshal.ReleaseComObject(managerObject);
                    if (device != null) Marshal.ReleaseComObject(device);
                }
            }
        } finally {
            if (devices != null) Marshal.ReleaseComObject(devices);
            Marshal.ReleaseComObject(enumerator);
        }
        return muted;
    }
}
'@
}
$muted = [Mw120SessionAudio]::SetMute([uint32[]]$gameIds, !$Unmute)
if (!$muted) { throw 'No audio session exists yet for the exact game process; rerun after audio initializes.' }
Write-Output "Verified game audio sessions: $muted; muted=$(!$Unmute)"
