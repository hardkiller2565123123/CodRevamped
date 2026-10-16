using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CodRevamped.IW8Tools;

// CodRevamped 1.20 deployment: native map support lives in our own MW2019 version.dll.
// The native runtime independently verifies target addresses before arming hooks.
internal static class Replay120MapLoader
{
    internal const string ExpectedReplayMd5 = "1C238FE327F2ECC3B0DB924C5B425439";
    internal const string GameExe = "game_dx12_ship_replay.exe";
    internal const string ClientName = "version.dll";
    private static readonly Regex IdRegex = new(@"^mp_[a-z0-9_]{1,12}$", RegexOptions.Compiled);
    internal static string[] ZoneNames(string id) =>
        [id + ".ff", "srv_" + id + ".ff", "eng_" + id + ".ff",
         "ww_" + id + ".ff", "techsets_" + id + ".ff", "map.json"];

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
    private static bool IsLink(string path) =>
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
    private static void NoLinkIfPresent(string path)
    {
        if (File.Exists(path) || Directory.Exists(path))
            Check(!IsLink(path), "Reparse points/links are not permitted: " + path);
    }
    private static void SafeChildren(string root, string path)
    {
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
        var fullPath = Path.GetFullPath(path);
        Check(fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase), "Deployment path escapes the game root.");
        NoLinkIfPresent(fullRoot);
        var relative = Path.GetRelativePath(fullRoot, fullPath);
        var current = fullRoot;
        foreach (var component in relative.Split(Path.DirectorySeparatorChar))
        {
            current = Path.Combine(current, component);
            NoLinkIfPresent(current);
        }
    }
    private static string Sha256(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    private static void CopyAndCheck(string from, string to)
    {
        Check(File.Exists(from) && !IsLink(from), "Unusable source file: " + from);
        File.Copy(from, to, false);
        Check(new FileInfo(from).Length == new FileInfo(to).Length &&
              Sha256(from) == Sha256(to), "Hash mismatch after copy: " + Path.GetFileName(from));
    }
    internal static string ValidateGame(string gameRoot)
    {
        Check(Directory.Exists(gameRoot), "Choose the directory containing Replay 1.20.");
        NoLinkIfPresent(gameRoot);
        var exe = Path.Combine(gameRoot, GameExe);
        Check(File.Exists(exe) && !IsLink(exe), "Replay game executable not found.");
        using var input = File.OpenRead(exe);
        var md5 = Convert.ToHexString(MD5.HashData(input)); // upstream build-identification only
        Check(md5.Equals(ExpectedReplayMd5, StringComparison.OrdinalIgnoreCase),
            $"Wrong Replay executable. MW120R targets 1.20.4.7623265 with MD5 {ExpectedReplayMd5}; selected MD5={md5}. No files were changed.");
        return md5;
    }
    // Marker emitted by the CodRevamped MW2019 native custom-map module.
    // Compatibility guard only; this is not a digital signature.
    internal const string LoaderMapRootContract = "CODREVAMPED_NATIVE_MAPS_V1";
    private static bool HasMapRootContract(string file)
    {
        // This is a compatibility marker, not an authentication mechanism.
        // Only accept a DLL matching the user-built, path-adjusted loader.
        var marker = Encoding.ASCII.GetBytes(LoaderMapRootContract);
        using var input = File.OpenRead(file);
        Check(input.Length < 128 * 1024 * 1024, "Client DLL exceeds compatibility-check budget.");
        var bytes = new byte[(int)input.Length];
        input.ReadExactly(bytes);
        return bytes.AsSpan().IndexOf(marker) >= 0;
    }
    internal static void RequireGameStopped()
    {
        Check(!Process.GetProcessesByName("game_dx12_ship_replay").Any(),
            "Close game_dx12_ship_replay.exe before installing or replacing maps.");
    }
    internal static void ValidatePackage(string packageDir, string id)
    {
        Check(IdRegex.IsMatch(id), "Map name must be lowercase mp_... and <=15 characters.");
        Check(Directory.Exists(packageDir) && !IsLink(packageDir), "Compiled package directory not found.");
        var names = ZoneNames(id);
        var actual = Directory.GetFileSystemEntries(packageDir);
        Check(actual.Length == names.Length && actual.All(x => names.Contains(Path.GetFileName(x), StringComparer.Ordinal)),
            "Loader package must contain exactly the five zones and map.json (nothing else).");
        foreach (var name in names[..5])
        {
            var file = Path.Combine(packageDir, name);
            Check(File.Exists(file) && !IsLink(file), "Missing required zone: " + name);
            using var input = File.OpenRead(file);
            Check(input.Length >= 0x8C, "Truncated native zone: " + name);
            var header = new byte[0xA0];
            input.ReadExactly(header.AsSpan(0, (int)Math.Min(input.Length, header.Length)));
            var magic = Encoding.ASCII.GetString(header.AsSpan(0, 8));
            var readU32 = (int offset) => System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(offset, 4));
            var readU64 = (int offset) => System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(offset, 8));
            var stored = magic == "IWffc100";
            Check((stored || magic == "IWffa100") && readU32(8) == 11 && readU32(12) == 4087,
                "Not a Replay 1.20 XFile: " + name);
            Check(header[17] == 0, "Encrypted zone is not supported: " + name);
            var resident = readU32(0x14);
            var xfile = readU64(0x20);
            ulong blockTotal = 0;
            for (var i = 0; i < 11; ++i) blockTotal += readU32(0x30 + i * 4);
            Check(xfile > 0 && blockTotal >= xfile && resident == input.Length - 0x88,
                "Invalid native zone size/stream descriptors: " + name);
            if (stored)
                Check(header[16] == 0 && resident == xfile + 4 &&
                      header[0x88] == 1 && header[0x89] == (byte)'I' &&
                      header[0x8A] == (byte)'W' && header[0x8B] == (byte)'C',
                    "Invalid Replay stored fastfile decoder marker: " + name);
            else
                Check(input.Length >= 0xA0 && header[16] == 1 &&
                      Encoding.ASCII.GetString(header.AsSpan(0x88, 8)) == "IWffs100",
                    "Invalid Replay signed fastfile descriptor: " + name);
        }
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(packageDir, "map.json")));
        Check(manifest.RootElement.GetProperty("id").GetString() == id,
            "map.json has an incorrect id.");
    }
    private static string NewBackupName() =>
        DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N")[..8];

    internal static string Deploy(string packageDir, string gameRoot, string id, string? clientSource)
    {
        ValidateGame(gameRoot);
        RequireGameStopped();
        ValidatePackage(packageDir, id);
        var currentClient = Path.Combine(gameRoot, ClientName);
        var shouldInstallClient = !string.IsNullOrWhiteSpace(clientSource);
        if (shouldInstallClient)
        {
            Check(File.Exists(clientSource) && !IsLink(clientSource), "Choose your compiled CodRevamped MW2019 version.dll.");
            Check(new FileInfo(clientSource).Length >= 64 * 1024,
                "The selected CodRevamped client DLL is unexpectedly small.");
            Check(Path.GetFileName(clientSource).Equals(ClientName, StringComparison.OrdinalIgnoreCase),
                "The client must be named version.dll.");
            Check(HasMapRootContract(clientSource),
                "Selected DLL lacks the CodRevamped integrated native-map marker. Rebuild MW2019/version.dll from this solution.");
            Check(!Path.GetFullPath(clientSource).Equals(Path.GetFullPath(currentClient), StringComparison.OrdinalIgnoreCase),
                "The client DLL is already in the game directory; leave its source field empty.");
        }
        else
        {
            Check(File.Exists(currentClient) && !IsLink(currentClient),
                "No CodRevamped version.dll installed. Build MW2019 in CodRevamped.sln or choose the built DLL.");
            Check(HasMapRootContract(currentClient),
                "Installed version.dll does not include CodRevamped native map support. Rebuild and deploy the MW2019 client.");
        }

        var folder = Path.Combine(gameRoot, "maps");
        var installed = Path.Combine(folder, id);
        var oldBackup = Path.Combine(gameRoot, ".codrevamped", "map-backups", id, NewBackupName());
        var clientBackup = Path.Combine(gameRoot, ".codrevamped", "client-backups", NewBackupName(), ClientName);
        var staged = Path.Combine(folder, "." + id + ".stage-" + NewBackupName());
        var stagedClient = Path.Combine(gameRoot, ".codrevamped-" + NewBackupName() + ".dll");
        foreach (var path in new[] { folder, installed, staged, oldBackup, clientBackup, stagedClient, currentClient })
            SafeChildren(gameRoot, path);
        Check(!File.Exists(Path.Combine(gameRoot, "zone", id + ".ff")) &&
              !File.Exists(Path.Combine(gameRoot, id + ".ff")),
            "Map id conflicts with a stock map; choose another id.");
        Check(!Path.GetFullPath(packageDir).Equals(Path.GetFullPath(installed), StringComparison.OrdinalIgnoreCase),
            "The build output cannot be the installed map folder.");

        Directory.CreateDirectory(folder);
        Directory.CreateDirectory(staged);
        var movedOld = false;
        var movedNew = false;
        var movedClient = false;
        var installedClient = false;
        try
        {
            foreach (var file in ZoneNames(id))
                CopyAndCheck(Path.Combine(packageDir, file), Path.Combine(staged, file));
            ValidatePackage(staged, id);
            if (shouldInstallClient) CopyAndCheck(clientSource!, stagedClient);
            RequireGameStopped();
            if (Directory.Exists(installed))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(oldBackup)!);
                Directory.Move(installed, oldBackup);
                movedOld = true;
            }
            Directory.Move(staged, installed);
            movedNew = true;
            if (shouldInstallClient)
            {
                if (File.Exists(currentClient))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(clientBackup)!);
                    File.Move(currentClient, clientBackup);
                    movedClient = true;
                }
                File.Move(stagedClient, currentClient);
                installedClient = true;
            }
            foreach (var name in ZoneNames(id))
                Check(Sha256(Path.Combine(packageDir, name)) == Sha256(Path.Combine(installed, name)),
                    "Final installed hash mismatch: " + name);
            return "Deployed verified native zones to " + installed + "\n" +
                   (shouldInstallClient ? "CodRevamped version.dll installed (SHA256 " + Sha256(currentClient) + ").\n" : "Existing CodRevamped version.dll retained.\n") +
                   (movedOld ? "Previous package backed up to " + oldBackup + "\n" : "") +
                   "Launch Replay with CodRevamped version.dll. Check [MAP120] startup diagnostics, then Multiplayer > Local Play > TDM.";
        }
        catch
        {
            // Restore previous installed data if the commit fails. Never delete backups.
            if (installedClient && File.Exists(currentClient)) File.Delete(currentClient);
            if (movedClient && File.Exists(clientBackup)) File.Move(clientBackup, currentClient);
            if (movedNew && Directory.Exists(installed))
            {
                var quarantine = Path.Combine(folder, "." + id + ".failed-" + NewBackupName());
                Directory.Move(installed, quarantine);
            }
            if (movedOld && Directory.Exists(oldBackup)) Directory.Move(oldBackup, installed);
            throw;
        }
        finally
        {
            if (Directory.Exists(staged)) Directory.Delete(staged, true);
            if (File.Exists(stagedClient)) File.Delete(stagedClient);
        }
    }
    internal static string RestorePreviousMap(string gameRoot, string id)
    {
        Check(IdRegex.IsMatch(id), "Invalid custom map id.");
        ValidateGame(gameRoot);
        RequireGameStopped();
        var target = Path.Combine(gameRoot, "maps", id);
        var saved = Path.Combine(gameRoot, ".codrevamped", "map-backups", id);
        SafeChildren(gameRoot, target);
        SafeChildren(gameRoot, saved);
        Check(Directory.Exists(saved) && !IsLink(saved), "No previous CodRevamped map backups found.");
        var backups = Directory.GetDirectories(saved).OrderByDescending(path => Path.GetFileName(path), StringComparer.Ordinal).ToArray();
        Check(backups.Length > 0, "No restorable custom map snapshots found.");
        var chosen = backups[0];
        ValidatePackage(chosen, id);
        var current = Path.Combine(gameRoot, ".codrevamped", "replaced-maps", id, NewBackupName());
        SafeChildren(gameRoot, current);
        var moved = false;
        if (Directory.Exists(target))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(current)!);
            Directory.Move(target, current);
            moved = true;
        }
        try { Directory.Move(chosen, target); }
        catch
        {
            if (moved && Directory.Exists(current)) Directory.Move(current, target);
            throw;
        }
        return "Restored previous custom map: " + target +
               (moved ? "\nThe replaced map was preserved at: " + current : "");
    }

}
