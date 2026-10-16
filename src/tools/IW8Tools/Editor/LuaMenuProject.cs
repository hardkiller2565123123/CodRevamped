using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CodRevamped.IW8Tools;

// Authoring format is independent of the game's private LUI ScriptFile serializer.
// Codegen emits readable LUI-source; never claims to emit compiled Havok Lua bytecode.
public sealed class LuaMenuProject
{
    public int Schema { get; set; } = 1;
    public string MenuId { get; set; } = "CRGunsmithPanel";
    public string DisplayName { get; set; } = "Custom Gunsmith Panel";
    public string Screen { get; set; } = "Gunsmith";
    public string ReferenceImage { get; set; } = ""; // project-relative only
    public List<LuaMenuWidget> Widgets { get; set; } = [];
    public static LuaMenuProject Starter(string screen) => new()
    {
        Screen = screen,
        MenuId = "CR" + (screen == "Gunsmith" ? "Gunsmith" : screen == "Loadouts" ? "Loadouts" : "MainMenu") + "Panel",
        DisplayName = "My " + screen + " Panel",
        Widgets = [
            new() { Id="cr_title", Kind="label", Text="CUSTOM " + screen.ToUpperInvariant(), X=95, Y=142, Width=480, Height=50, FontSize=30, Color="#F5F5F5" },
            new() { Id="cr_option", Kind="button", Text="CUSTOM OPTION", X=92, Y=238, Width=390, Height=58, FontSize=22, Color="#FFFFFF", Action="none" }
        ]
    };
}

public sealed class LuaMenuWidget
{
    public string Id { get; set; } = "cr_widget";
    public string Kind { get; set; } = "button"; // label | panel | button
    public string Text { get; set; } = "NEW OPTION";
    public double X { get; set; } = 110;
    public double Y { get; set; } = 250;
    public double Width { get; set; } = 310;
    public double Height { get; set; } = 54;
    public int FontSize { get; set; } = 22;
    public string Color { get; set; } = "#F3F3F3";
    public string Action { get; set; } = "none"; // none | open_menu | console_command
    public string ActionValue { get; set; } = "";
    public LuaMenuWidget Clone() => (LuaMenuWidget)MemberwiseClone();
}

public static class LuaMenuCompiler
{
    private static readonly Regex IdPattern = new("^[A-Za-z_][A-Za-z0-9_]{1,63}$", RegexOptions.Compiled);
    private static readonly Regex SafeCommand = new(@"^[A-Za-z0-9_ .+\-]{0,128}$", RegexOptions.Compiled);
    private static readonly HashSet<string> Kinds = ["label", "panel", "button"];
    private static readonly HashSet<string> Actions = ["none", "open_menu", "console_command"];
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
    private static string Num(double value) => value.ToString("0.###", CultureInfo.InvariantCulture);
    private static string Quote(string value)
    {
        var builder = new StringBuilder("\"");
        foreach (var ch in value)
        {
            if (ch == '\\') builder.Append("\\\\");
            else if (ch == '"') builder.Append("\\\"");
            else if (ch == '\n') builder.Append("\\n");
            else if (ch == '\r') builder.Append("\\r");
            else if (ch == '\t') builder.Append("\\t");
            else if (ch < 32) builder.AppendFormat(CultureInfo.InvariantCulture, "\\{0:000}", (int)ch);
            else builder.Append(ch);
        }
        return builder.Append('"').ToString();
    }
    public static void Validate(LuaMenuProject project)
    {
        if (project.Schema != 1) throw new InvalidDataException("Unsupported Lua menu project schema.");
        if (!IdPattern.IsMatch(project.MenuId)) throw new InvalidDataException("Menu ID must be a Lua-safe identifier, 2-64 characters.");
        if (project.DisplayName.Length > 160) throw new InvalidDataException("Menu title too long.");
        if (project.Widgets.Count > 256) throw new InvalidDataException("Maximum 256 controls per menu.");
        if (project.ReferenceImage == null || project.ReferenceImage.Length > 180 || project.ReferenceImage.Contains("..") ||
            Path.IsPathRooted(project.ReferenceImage) || project.ReferenceImage.Contains(':') || project.ReferenceImage.Contains('/') || project.ReferenceImage.Contains('\\'))
            throw new InvalidDataException("Reference image must be a local project-relative filename.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var widget in project.Widgets)
        {
            if (!IdPattern.IsMatch(widget.Id) || !ids.Add(widget.Id)) throw new InvalidDataException("Widget identifiers must be unique Lua-safe names: " + widget.Id);
            if (!Kinds.Contains(widget.Kind)) throw new InvalidDataException("Unknown widget type " + widget.Kind);
            if (!Actions.Contains(widget.Action)) throw new InvalidDataException("Unknown action " + widget.Action);
            if (!double.IsFinite(widget.X) || !double.IsFinite(widget.Y) || !double.IsFinite(widget.Width) || !double.IsFinite(widget.Height) ||
                widget.X < 0 || widget.Y < 0 || widget.Width < 1 || widget.Height < 1 ||
                widget.X + widget.Width > 1920.01 || widget.Y + widget.Height > 1080.01)
                throw new InvalidDataException("Control outside 1920x1080 design canvas: " + widget.Id);
            if (widget.FontSize is < 8 or > 96 || widget.Text.Length > 256) throw new InvalidDataException("Invalid text/font size: " + widget.Id);
            if (!Regex.IsMatch(widget.Color, "^#[0-9a-fA-F]{6}$")) throw new InvalidDataException("Use #RRGGBB for widget colors.");
            if (widget.Action == "open_menu" && !IdPattern.IsMatch(widget.ActionValue)) throw new InvalidDataException("Open-menu action requires a Lua-safe menu ID.");
            if (widget.Action == "console_command" && !SafeCommand.IsMatch(widget.ActionValue)) throw new InvalidDataException("Invalid or too-long console command.");
        }
    }
    // The output is a *proposed* IW LUI source module, not a verified 1.20 compiled chunk.
    public static string Generate(LuaMenuProject project)
    {
        Validate(project);
        var sb = new StringBuilder();
        sb.AppendLine("-- Generated by CodRevamped IW8Tools Lua Menu Builder");
        sb.AppendLine("-- Replay 1.20 LUI source candidate. Requires engine-side loading and live verification.");
        sb.AppendLine("-- Screen template: " + project.Screen.Replace("\n", " ").Replace("\r", " "));
        sb.AppendLine("LUI = LUI or {}");
        sb.AppendLine("LUI.createMenu = LUI.createMenu or {}");
        sb.AppendLine("LUI.createMenu[" + Quote(project.MenuId) + "] = function(controller)");
        sb.AppendLine("    local root = LUI.UIElement.new()");
        sb.AppendLine("    root.id = " + Quote(project.MenuId));
        sb.AppendLine("    root:registerAnimationState(\"default\", {leftAnchor=true,topAnchor=true,rightAnchor=false,bottomAnchor=false,left=0,top=0,right=1920,bottom=1080,alpha=1})");
        sb.AppendLine("    root:animateToState(\"default\", 0)");
        foreach (var widget in project.Widgets)
        {
            var name = "node_" + widget.Id;
            var text = widget.Kind != "panel";
            sb.AppendLine("    do");
            sb.AppendLine("        local " + name + " = LUI." + (text ? "UIText" : "UIElement") + ".new()");
            sb.AppendLine("        " + name + ".id = " + Quote(widget.Id));
            // IW Lua layouts use absolute bounds within the root design space.
            sb.AppendLine("        " + name + ":registerAnimationState(\"default\", {leftAnchor=true,topAnchor=true,rightAnchor=false,bottomAnchor=false,left=" + Num(widget.X) + ",top=" + Num(widget.Y) + ",right=" + Num(widget.X + widget.Width) + ",bottom=" + Num(widget.Y + widget.Height) + ",alpha=1})");
            sb.AppendLine("        " + name + ":animateToState(\"default\", 0)");
            if (text) sb.AppendLine("        " + name + ":setText(" + Quote(widget.Text) + ")");
            var r = Convert.ToByte(widget.Color.Substring(1,2),16) / 255.0;
            var g = Convert.ToByte(widget.Color.Substring(3,2),16) / 255.0;
            var b = Convert.ToByte(widget.Color.Substring(5,2),16) / 255.0;
            sb.AppendLine("        if " + name + ".setRGB then " + name + ":setRGB(" + Num(r) + "," + Num(g) + "," + Num(b) + ") end");
            if (text) sb.AppendLine("        if " + name + ".setFontSize then " + name + ":setFontSize(" + widget.FontSize + ") end");
            if (widget.Kind == "button")
            {
                sb.AppendLine("        -- Button focus/event dispatch is experimental until live Replay 1.20 verification.");
                sb.AppendLine("        if " + name + ".makeFocusable then " + name + ":makeFocusable() end");
                if (widget.Action == "open_menu")
                    sb.AppendLine("        " + name + ":registerEventHandler(\"button_action\", function(_, event) if LUI.FlowManager and LUI.FlowManager.RequestAddMenu then LUI.FlowManager.RequestAddMenu(nil, " + Quote(widget.ActionValue) + ", true, controller, false) end end)");
                else if (widget.Action == "console_command")
                    sb.AppendLine("        " + name + ":registerEventHandler(\"button_action\", function() if Engine and Engine.Exec then Engine.Exec(" + Quote(widget.ActionValue) + ") end end)");
            }
            sb.AppendLine("        root:addElement(" + name + ")");
            sb.AppendLine("    end");
        }
        sb.AppendLine("    return root");
        sb.AppendLine("end");
        sb.AppendLine("-- IW8 may use MenuBuilder registration rather than createMenu directly.");
        sb.AppendLine("if LUI.MenuBuilder and LUI.MenuBuilder.registerType then");
        sb.AppendLine("    LUI.MenuBuilder.registerType(" + Quote(project.MenuId) + ", function(...) return LUI.createMenu[" + Quote(project.MenuId) + "](...) end)");
        sb.AppendLine("end");
        sb.AppendLine("-- End of CodRevamped menu module.");
        return sb.ToString();
    }
    public static void SaveProject(string filename, LuaMenuProject project)
    {
        Validate(project);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(filename))!);
        File.WriteAllText(filename, JsonSerializer.Serialize(project, JsonOptions), new UTF8Encoding(false));
    }
    public static LuaMenuProject OpenProject(string filename)
    {
        var source = new FileInfo(filename);
        if (!source.Exists || source.Length > 1024 * 1024) throw new InvalidDataException("Menu project missing or too large.");
        var project = JsonSerializer.Deserialize<LuaMenuProject>(File.ReadAllText(filename), JsonOptions) ?? throw new InvalidDataException("Invalid project.");
        Validate(project); return project;
    }
    // Exact 1.20 PE identity. The client runtime checks the same tuple before installing hooks.
    public static void VerifyReplay120Executable(string filename)
    {
        if (!File.Exists(filename)) throw new InvalidDataException("Game executable does not exist.");
        using var stream = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = new BinaryReader(stream);
        if (stream.Length < 1024 || reader.ReadUInt16() != 0x5A4D)
            throw new InvalidDataException("Invalid Windows executable (DOS header).");
        stream.Position = 0x3C;
        var pe = reader.ReadInt32();
        if (pe < 0x40 || pe > stream.Length - 0x110)
            throw new InvalidDataException("Invalid PE offset.");
        stream.Position = pe;
        if (reader.ReadUInt32() != 0x00004550 || reader.ReadUInt16() != 0x8664)
            throw new InvalidDataException("Expected 64-bit PE executable.");
        stream.Position = pe + 8;
        var stamp = reader.ReadUInt32();
        stream.Position = pe + 24;
        var magic = reader.ReadUInt16();
        stream.Position = pe + 24 + 16;
        var entry = reader.ReadUInt32();
        stream.Position = pe + 24 + 56;
        var image = reader.ReadUInt32();
        if (magic != 0x20B || stamp != 0x5E9BAF80 || image != 0x1324B000 || entry != 0x021CDC10)
            throw new InvalidDataException("This executable is not the supported Replay 1.20 fingerprint. No Lua files staged.");
    }
    // Stage source atomically, without modifying unrelated game files. On failure
    // the previous authored menu is restored. The native module loads on restart.
    public static string Deploy(string gameRoot, LuaMenuProject project)
    {
        Validate(project);
        VerifyReplay120Executable(Path.Combine(gameRoot, "game_dx12_ship_replay.exe"));
        var root = Path.Combine(gameRoot, "lua");
        var id = project.MenuId;
        if (Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("The game's lua directory must not be a reparse point.");
        var installed = Path.Combine(root, id);
        if (Directory.Exists(installed) && (File.GetAttributes(installed) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("The installed Lua menu directory must not be a reparse point.");
        var temporary = Path.Combine(gameRoot, ".codrevamped", "staging", "lua-" + Guid.NewGuid().ToString("N"));
        var staged = Path.Combine(temporary, "lua", id);
        var backup = Path.Combine(gameRoot, ".codrevamped", "backups", "lua", id + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture));
        bool movedOld = false;
        try
        {
            Build(temporary, project);
            Directory.CreateDirectory(root);
            if (Directory.Exists(installed))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(backup)!);
                Directory.Move(installed, backup);
                movedOld = true;
            }
            Directory.Move(staged, installed);
        }
        catch
        {
            if (movedOld && !Directory.Exists(installed) && Directory.Exists(backup))
                Directory.Move(backup, installed);
            throw;
        }
        finally
        {
            if (Directory.Exists(temporary)) Directory.Delete(temporary, true);
        }
        return installed;
    }
    public static string Build(string outputRoot, LuaMenuProject project)
    {
        Validate(project);
        // Build produces source and metadata, not an engine VM bytecode file.
        var directory = Path.Combine(outputRoot, "lua", project.MenuId);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, project.MenuId + ".lua"), Generate(project), new UTF8Encoding(false));
        SaveProject(Path.Combine(directory, "menu.project.json"), project);
        var manifest = new { schema=1, target="MW2019-Replay-1.20", id=project.MenuId,
            screen=project.Screen, format="lui-source", runtime="requires-verified-lui-loader", widgets=project.Widgets.Count };
        File.WriteAllText(Path.Combine(directory, "menu.build.json"), JsonSerializer.Serialize(manifest, JsonOptions), new UTF8Encoding(false));
        return directory;
    }
}
