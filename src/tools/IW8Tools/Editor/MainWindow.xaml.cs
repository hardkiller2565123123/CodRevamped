using Microsoft.Win32;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;
using System.Windows.Input;
using System.Text.Json.Nodes;

namespace CodRevamped.IW8Tools;

public partial class MainWindow : Window
{
    private sealed record Block(string Name, double X, double Y, double Z,
                                double Width, double Length, double Height, double Yaw=0,
                                string Shape="box", double UVScale=128);
    private sealed record Spawn(string Type, double X, double Y, double Z, double Yaw);
    private readonly List<Spawn> _spawns = [];
    private readonly List<Block> _blocks = [];
    private readonly Stack<List<Block>> _undo = new();
    private readonly Stack<List<Block>> _redo = new();
    private string? _loadedWeaponId;
    private readonly PerspectiveCamera _camera = new(new Point3D(24, -32, 25),
                          new Vector3D(-24, 32, -18), new Vector3D(0, 0, 1), 52);
    private readonly Model3DGroup _scene = new();
    private ImageSource? _previewTexture;
    private Point3D _cameraTarget = new(0,0,0);
    private bool _orbiting;
    private Point _lastMouse;
    private const string Exe = "game_dx12_ship_replay.exe";
    private static readonly Regex MapPattern = new(@"^mp_[a-z0-9_]{1,12}$", RegexOptions.Compiled);
    private static readonly Regex AssetPattern = new(@"^[a-z0-9_]{1,56}$", RegexOptions.Compiled);
    private static readonly string[] Parts = ["{0}.ff", "srv_{0}.ff", "eng_{0}.ff",
                                               "ww_{0}.ff", "techsets_{0}.ff"];

    public MainWindow()
    {
        InitializeComponent();
        NativeToolsPath.Text = Path.Combine(AppContext.BaseDirectory, "IW8Tools.Native.exe");
        SceneView.Camera = _camera;
        SceneView.Children.Add(new ModelVisual3D { Content = _scene });
        _scene.Children.Add(new AmbientLight(Color.FromRgb(88, 105, 124)));
        _scene.Children.Add(new DirectionalLight(Colors.White, new Vector3D(-0.6, 1, -1)));
        ConfigureRadiantViews();
        Redraw();
        Log("IW8 Tools ready. Choose a workspace or drag an asset into the window.");
    }

    // Three native editor viewports share authored brush meshes with the camera and exporter.
    // Changes are committed once on mouse-up, so each drag is a single undo operation.
    private Radiant2DViewport[] OrthographicViews => [TopView, FrontView, SideView];

    private void ConfigureRadiantViews()
    {
        foreach (var view in OrthographicViews)
        {
            view.BrushSelected = index =>
            {
                if (index < 0 || index >= _blocks.Count) return;
                Objects.SelectedIndex = index;
                Objects.ScrollIntoView(Objects.SelectedItem);
            };
            view.BrushMoved = MoveBrushFromRadiant;
            view.CreateBox = CreateBrushAt;
            view.CreateSpawn = CreateSpawnAt;
            view.CursorChanged = coordinates => MapEditorCoordinates.Text = coordinates;
        }
        UpdateRadiantGrid();
    }

    private void UpdateRadiantGrid()
    {
        if (TopView == null || FrontView == null || SideView == null) return;
        if (!double.TryParse(GridStep?.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var step)
            || !double.IsFinite(step) || step <= 0 || step > 4096) return;
        foreach (var view in OrthographicViews) view.SetGrid(step);
    }

    private void GridStep_TextChanged(object sender, TextChangedEventArgs e) => UpdateRadiantGrid();

    private void UpdateRadiantViews()
    {
        if (TopView == null || FrontView == null || SideView == null) return;
        var geometry = _blocks.Select(b =>
        {
            var mesh = Shape(b);
            return new Radiant2DViewport.BrushGeometry(b.Name, b.Shape, mesh.Points, mesh.Faces);
        }).ToArray();
        var entities = _spawns.Select(s =>
            new Radiant2DViewport.EntityMarker(s.Type, new Point3D(s.X, s.Y, s.Z))).ToArray();
        foreach (var view in OrthographicViews) view.SetScene(geometry, entities, Objects.SelectedIndex);
    }

    private void MoveBrushFromRadiant(int index, Vector3D move) => Handle(() =>
    {
        ProjectRoot();
        Require(index >= 0 && index < _blocks.Count, "Select a brush to move.");
        var original = _blocks[index];
        var shifted = original with
        {
            X = original.X + move.X, Y = original.Y + move.Y, Z = original.Z + move.Z
        };
        Require(Corners(shifted).All(p => Math.Abs(p.X) < 99999 &&
            Math.Abs(p.Y) < 99999 && Math.Abs(p.Z) < 99999), "Brush exceeds world bounds.");
        RememberEdit();
        _blocks[index] = shifted;
        RefreshScene(index);
        SaveScene();
    });

    private void CreateBrushAt(Point3D position) => Handle(() =>
    {
        ProjectRoot();
        Require(_blocks.Count < 600, "Brush limit reached.");
        var grid = double.TryParse(GridStep.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var g)
                   && double.IsFinite(g) && g > 0 ? Math.Clamp(g, 1, 4096) : 32;
        double snap(double x) => Math.Round(x / grid, MidpointRounding.AwayFromZero) * grid;
        RememberEdit();
        _blocks.Add(new Block($"Brush{_blocks.Count}", snap(position.X), snap(position.Y),
            snap(position.Z), grid * 4, grid * 4, grid * 4));
        RefreshScene(_blocks.Count - 1);
        SaveScene();
    });

    private void CreateSpawnAt(Point3D position) => Handle(() =>
    {
        ProjectRoot();
        Require(_spawns.Count < 128, "Spawn point limit reached.");
        var kind = (SpawnType.SelectedItem as ComboBoxItem)?.Tag as string ?? "mp_tdm_spawn";
        Require(ValidSpawnTypes.Contains(kind), "Select a supported spawn type first.");
        _spawns.Add(new Spawn(kind, position.X, position.Y, position.Z, 0));
        RefreshSpawns(_spawns.Count - 1);
        SaveScene();
    });

    private void MapEditor_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if ((Keyboard.Modifiers & ModifierKeys.Control) != 0)
        {
            switch (e.Key)
            {
                case Key.S: SaveScene_Click(sender, e); e.Handled = true; return;
                case Key.Z: Undo_Click(sender, e); e.Handled = true; return;
                case Key.Y: Redo_Click(sender, e); e.Handled = true; return;
                case Key.D: Duplicate_Click(sender, e); e.Handled = true; return;
            }
        }
        // Typing in the property inspector must not trigger editor shortcuts.
        if (Keyboard.FocusedElement is TextBox or ComboBox) return;
        if (e.Key == Key.F) { FrameScene_Click(sender, e); e.Handled = true; }
        else if (e.Key == Key.Delete) { Remove_Click(sender, e); e.Handled = true; }
    }

    private sealed record TextureEntry(string Name, string Descriptor, BitmapSource Preview);

    private void TextureTab_Loaded(object sender, RoutedEventArgs e) => ReloadImportedTextures();
    private void RefreshTextures_Click(object sender, RoutedEventArgs e) => ReloadImportedTextures();

    private void ReloadImportedTextures()
    {
        if (TextureAssets == null || ProjectFolder == null) return;
        TextureAssets.Items.Clear();
        var root = ProjectFolder.Text;
        if (!Directory.Exists(root)) return;
        var directory = Path.Combine(root, "source", "images");
        if (!Directory.Exists(directory)) return;
        foreach (var descriptor in Directory.EnumerateFiles(directory, "*.texture.json").Take(128))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(descriptor));
                var width = doc.RootElement.GetProperty("width").GetInt32();
                var height = doc.RootElement.GetProperty("height").GetInt32();
                if (width < 1 || height < 1 || width > 8192 || height > 8192) continue;
                var source = Path.ChangeExtension(Path.ChangeExtension(descriptor, null), ".rgba");
                if (!File.Exists(source) || new FileInfo(source).Length != (long)width * height * 4) continue;
                const int limit = 100;
                var w = Math.Min(limit, width); var h = Math.Min(limit, height);
                var pixels = new byte[checked(w * h * 4)];
                var scan = new byte[checked(width * 4)];
                using (var stream = File.OpenRead(source))
                {
                    for (var y = 0; y < h; ++y)
                    {
                        var srcY = (int)((long)y * height / h);
                        stream.Position = (long)srcY * width * 4;
                        stream.ReadExactly(scan);
                        for (var x = 0; x < w; ++x)
                            Buffer.BlockCopy(scan, (int)((long)x * width / w) * 4,
                                pixels, (y * w + x) * 4, 4);
                    }
                }
                // WPF's broadly supported BGRA32 preview format; the .rgba source remains untouched.
                for (var i = 0; i < pixels.Length; i += 4)
                    (pixels[i], pixels[i + 2]) = (pixels[i + 2], pixels[i]);
                var bitmap = BitmapSource.Create(w, h, 96, 96, PixelFormats.Bgra32, null, pixels, w * 4);
                bitmap.Freeze();
                var name = Path.GetFileName(source);
                TextureAssets.Items.Add(new TextureEntry(name, descriptor, bitmap));
            }
            catch (Exception ex) { Log("Texture preview skipped: " + Path.GetFileName(descriptor) + " (" + ex.Message + ")"); }
        }
    }

    private void TextureAssets_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (TextureSelection == null) return;
        TextureSelection.Text = TextureAssets.SelectedItem is TextureEntry t
            ? t.Name + " (editor preview; engine material still requires compilation)"
            : "Choose an imported source texture";
        _previewTexture = TextureAssets.SelectedItem is TextureEntry preview ? preview.Preview : null;
        if (_scene.Children.Count >= 2 + _blocks.Count) UpdateSelectionHighlight();
    }

    private void ApplySelectedTexture_Click(object sender, RoutedEventArgs e) => Handle(() =>
    {
        if (TextureAssets.SelectedItem is not TextureEntry t)
            throw new InvalidOperationException("Select an imported texture in the browser.");
        ApplyTextureDescriptor(t.Descriptor);
    });

    private void OpenLuaWorkbench_Click(object sender, RoutedEventArgs e)
    {
        var window = new LuaMenuWorkbench { Owner = this };
        window.Show();
    }

    private void Log(string message)
    {
        Dispatcher.Invoke(() => {
            Output.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
            Output.ScrollToEnd();
        });
    }
    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
    private void Handle(Action task)
    {
        try { task(); }
        catch (Exception ex) { Log($"ERROR: {ex.Message}"); MessageBox.Show(ex.Message, "IW8 Tools", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }
    private static string ChooseFolder(string? initial = null)
    {
        var picker = new OpenFolderDialog { Title = "Choose folder" };
        if (Directory.Exists(initial)) picker.InitialDirectory = initial;
        return picker.ShowDialog() == true ? picker.FolderName : string.Empty;
    }
    private static string RequireMapId(string map)
    {
        Require(MapPattern.IsMatch(map), "Map ID must be lowercase mp_... (maximum 15 characters).");
        return map;
    }
    private string ProjectRoot()
    {
        var p = ProjectFolder.Text;
        Require(Directory.Exists(p), "Create or open a map project first.");
        return p;
    }
    private void NewMap_Click(object sender, RoutedEventArgs e) => Handle(() =>
    {
        var id = RequireMapId(MapId.Text.Trim());
        var parent = ChooseFolder(); if (parent.Length == 0) return;
        var root = Path.Combine(parent, id);
        Require(!Directory.Exists(root), "Project directory exists. Open it instead of overwriting it.");
        Directory.CreateDirectory(Path.Combine(root, "source", "images"));
        Directory.CreateDirectory(Path.Combine(root, "source", "weapons"));
        Directory.CreateDirectory(Path.Combine(root, "dump", "maps", "mp"));
        Directory.CreateDirectory(Path.Combine(root, "maps", id));
        MapTitle.Text=id;
        MapDescription.Text="CodRevamped authored test map";
        File.WriteAllText(Path.Combine(root,"map.json"), JsonSerializer.Serialize(new {
            id,title=MapTitle.Text,description=MapDescription.Text
        },new JsonSerializerOptions{WriteIndented=true}));
        File.WriteAllText(Path.Combine(root, "iw8tools.project.json"), JsonSerializer.Serialize(new {
            schema = 1, target = "Replay-1.20", id, nativeFastfilesBuilt = false,
            notes = "Source editor project. Requires verified native compiler and collision data."
        }, new JsonSerializerOptions { WriteIndented = true }));
        ResetSpawns();
        WriteTdmSpawns(root, id);
        _previewTexture=null;_loadedWeaponId=null;_undo.Clear();_redo.Clear();_blocks.Clear();_blocks.Add(new Block("TestFloor", 0, 0, -16, 1024, 1024, 32));
        ProjectFolder.Text = root;
        DumpFolder.Text = Path.Combine(root, "dump");
        PackageFolder.Text = Path.Combine(root, "maps", id);
        SaveScene();RefreshScene();FrameScene_Click(sender,e);ReloadImportedTextures();
        Log($"Created source map {id}. No fake .ff or .havok files created.");
    });
    private void OpenMap_Click(object sender, RoutedEventArgs e) => Handle(() =>
    {
        var root = ChooseFolder();if(root.Length==0)return;
        var manifest = Path.Combine(root, "iw8tools.project.json");
        Require(File.Exists(manifest), "Not an IW8 Tools source project (iw8tools.project.json missing).");
        using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
        var id = RequireMapId(doc.RootElement.GetProperty("id").GetString() ?? "");
        MapId.Text=id;ProjectFolder.Text=root;DumpFolder.Text=Path.Combine(root,"dump");
        var metadataFile=Path.Combine(root,"map.json");
        if(File.Exists(metadataFile))
        {
            using var metadata=JsonDocument.Parse(File.ReadAllText(metadataFile));
            var m=metadata.RootElement;
            MapTitle.Text=m.TryGetProperty("title",out var t)?t.GetString()??id:id;
            MapDescription.Text=m.TryGetProperty("description",out var d)?d.GetString()??"":"";
        }
        var options=Path.Combine(root,"source","settings.json");
        if(File.Exists(options))
        {
            using var settings=JsonDocument.Parse(File.ReadAllText(options));
            var sun=settings.RootElement;
            SunIntensity.Text=sun.GetProperty("sunIntensity").GetDouble().ToString("R",CultureInfo.InvariantCulture);
            var vec=sun.GetProperty("sunDirection").EnumerateArray().Select(v=>v.GetDouble()).ToArray();
            if(vec.Length==3)
            {
                SunX.Text=vec[0].ToString("R",CultureInfo.InvariantCulture);
                SunY.Text=vec[1].ToString("R",CultureInfo.InvariantCulture);
                SunZ.Text=vec[2].ToString("R",CultureInfo.InvariantCulture);
            }
        }
        PackageFolder.Text=Path.Combine(root,"maps",id);
        var scene=Path.Combine(root,"source","scene.json");
        _previewTexture=null;_loadedWeaponId=null;_undo.Clear();_redo.Clear();_blocks.Clear();
        if(File.Exists(scene))_blocks.AddRange(JsonSerializer.Deserialize<List<Block>>(File.ReadAllText(scene)) ?? []);
        var spawnPath=Path.Combine(root,"source","spawns.json");
        _spawns.Clear();
        if(File.Exists(spawnPath)) _spawns.AddRange(JsonSerializer.Deserialize<List<Spawn>>(File.ReadAllText(spawnPath)) ?? []);
        else ResetSpawns();
        RefreshSpawns();RefreshScene();FrameScene_Click(sender,e);ReloadImportedTextures();Log($"Opened {id}, blocks={_blocks.Count}");
    });
    // Compiler numeric string keys come from Replay 1.20's verified entity
    // format. Do not use stock CoD4 key-value entity text with build-map.
    private static readonly HashSet<string> ValidSpawnTypes = [
        "info_player_start", "mp_tdm_spawn", "mp_tdm_spawn_allies_start", "mp_tdm_spawn_axis_start"];
    private void ResetSpawns()
    {
        _spawns.Clear();
        _spawns.AddRange([
            new("info_player_start",0,0,96,0),
            new("mp_tdm_spawn",0,160,96,0),
            new("mp_tdm_spawn_allies_start",-192,0,96,0),
            new("mp_tdm_spawn_axis_start",192,0,96,180)
        ]);
        RefreshSpawns();
    }
    private void RefreshSpawns(int selected=-1)
    {
        Spawns.Items.Clear();
        foreach (var item in _spawns)
            Spawns.Items.Add($"{item.Type} | {item.X:0} {item.Y:0} {item.Z:0}");
        if (selected>=0 && selected<_spawns.Count) Spawns.SelectedIndex=selected;
        UpdateRadiantViews();
    }
    private void Spawns_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var i=Spawns.SelectedIndex;if(i<0 || i>=_spawns.Count)return;
        var sp=_spawns[i];
        SpawnType.SelectedItem=SpawnType.Items.Cast<ComboBoxItem>().FirstOrDefault(it=>
            (string?)it.Tag==sp.Type);
        SpawnX.Text=sp.X.ToString("R",CultureInfo.InvariantCulture);
        SpawnY.Text=sp.Y.ToString("R",CultureInfo.InvariantCulture);
        SpawnZ.Text=sp.Z.ToString("R",CultureInfo.InvariantCulture);
        SpawnYaw.Text=sp.Yaw.ToString("R",CultureInfo.InvariantCulture);
    }
    private Spawn ReadSpawn()
    {
        var kind=(SpawnType.SelectedItem as ComboBoxItem)?.Tag as string ?? "mp_tdm_spawn";
        Require(ValidSpawnTypes.Contains(kind),"Unknown spawn type.");
        var yaw=ParseCoordinate(SpawnYaw.Text,"Spawn yaw");
        Require(yaw>=-360 && yaw<=360,"Spawn yaw must be within ±360 degrees.");
        return new(kind,ParseCoordinate(SpawnX.Text,"Spawn X"),
            ParseCoordinate(SpawnY.Text,"Spawn Y"),ParseCoordinate(SpawnZ.Text,"Spawn Z"),yaw);
    }
    private void AddSpawn_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        Require(_spawns.Count<128,"128 spawn-point limit reached.");
        _spawns.Add(ReadSpawn());RefreshSpawns(_spawns.Count-1);SaveScene();
    });
    private void ApplySpawn_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        var index=Spawns.SelectedIndex;Require(index>=0,"Select a spawn.");
        _spawns[index]=ReadSpawn();RefreshSpawns(index);SaveScene();
    });
    private void RemoveSpawn_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        var index=Spawns.SelectedIndex;Require(index>=0,"Select a spawn.");
        _spawns.RemoveAt(index);RefreshSpawns();SaveScene();
    });
    private void ResetSpawns_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        ResetSpawns();SaveScene();
    });
    private static string SpFmt(double n)=>n.ToString("0.######",CultureInfo.InvariantCulture);
    private void WriteTdmSpawns(string root, string id)
    {
        Require(_spawns.Count<=128,"Spawn limit exceeded.");
        foreach(var required in ValidSpawnTypes)
            Require(_spawns.Any(p=>p.Type==required),"Required TDM spawn missing: "+required);
        var ents=new StringBuilder("{ 212 \"worldspawn\" }\n");
        foreach(var sp in _spawns)
        {
            Require(ValidSpawnTypes.Contains(sp.Type) &&
                new[]{sp.X,sp.Y,sp.Z,sp.Yaw}.All(double.IsFinite),"Invalid spawn fields.");
            ents.Append("{ 212 \""+sp.Type+"\" 709 \""+
                SpFmt(sp.X)+" "+SpFmt(sp.Y)+" "+SpFmt(sp.Z)+
                "\" 80 \"0 "+SpFmt(sp.Yaw)+" 0\" }\n");
        }
        // Stock Replay requires at least one non-player entity in the initial
        // snapshot when all static props were baked into the world geometry.
        ents.Append("{ 212 \"script_model\" 709 \"0 0 16\" 80 \"0 0 0\" }\n");
        File.WriteAllText(Path.Combine(root,"dump",id+"_iw8_ents.txt"),ents.ToString(),new UTF8Encoding(false));
    }
    private void CreateTestArena_Click(object sender, RoutedEventArgs e) => Handle(() =>
    {
        var root = ProjectRoot();
        if (_blocks.Count > 0 && MessageBox.Show(
            "Replace the current blockout with a 1024-unit enclosed test arena? Undo is available.",
            "Create TDM test arena", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        RememberEdit();
        _blocks.Clear();
        _blocks.AddRange([
            new Block("ArenaFloor", 0, 0, -16, 1024, 1024, 32),
            new Block("ArenaNorth", 0, 496, 144, 1024, 32, 288),
            new Block("ArenaSouth", 0, -496, 144, 1024, 32, 288),
            new Block("ArenaEast", 496, 0, 144, 32, 1024, 288),
            new Block("ArenaWest", -496, 0, 144, 32, 1024, 288),
            new Block("CoverLeft", -128, 0, 40, 72, 72, 80),
            new Block("CoverRight", 128, 0, 40, 72, 72, 80)
        ]);
        ResetSpawns();
        WriteTdmSpawns(root, RequireMapId(MapId.Text.Trim()));
        RefreshScene();SaveScene();FrameScene_Click(sender,e);
        Log("Test arena + numeric TDM spawn entities generated. Export native graybox before building.");
    });
    private void AttachMaterial_Click(object sender, RoutedEventArgs e) => Handle(() =>
    {
        var id = RequireMapId(MapId.Text.Trim());
        var root = ProjectRoot();
        var source = ChooseFolder(); if (source.Length == 0) return;
        var materials = Directory.GetFiles(source, "*.d3dbsp.material.json", SearchOption.TopDirectoryOnly);
        var techsets = Directory.GetFiles(source, "*.d3dbsp.techset.json", SearchOption.TopDirectoryOnly);
        Require(materials.Length == 1 && techsets.Length == 1,
            "Choose a prepared dump maps/mp directory with exactly one material JSON and techset JSON.");
        var material = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(materials[0]))?.AsObject()
            ?? throw new InvalidOperationException("Invalid material JSON.");
        var techset = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(techsets[0]))?.AsObject()
            ?? throw new InvalidOperationException("Invalid techset JSON.");
        Require(techset["name"] != null && techset["techniques"] is System.Text.Json.Nodes.JsonArray
            && techset["shaders"] is System.Text.Json.Nodes.JsonObject,
            "A real populated Replay techset is required; a mock shader is not sufficient.");
        Require(material["techset"]?.GetValue<string>() == techset["name"]?.GetValue<string>(),
            "The material must reference the selected techset's name.");
        var directory=Path.Combine(root,"dump","maps","mp");Directory.CreateDirectory(directory);
        var materialTarget=$"{id}.d3dbsp.material.json";
        var techsetTarget=$"{id}.d3dbsp.techset.json";
        material["techsetDefinition"]=techsetTarget;
        // Keep native shader identifiers and bytecode owned by this template.
        // Do not copy any stock shader data into public project releases.
        foreach(var image in Directory.GetFiles(source, "*.rgba"))
        {
            var target=Path.Combine(directory,Path.GetFileName(image));
            if(!Path.GetFullPath(image).Equals(Path.GetFullPath(target),StringComparison.OrdinalIgnoreCase))
                File.Copy(image,target,true);
        }
        File.WriteAllText(Path.Combine(directory,materialTarget),material.ToJsonString(new JsonSerializerOptions{WriteIndented=true}));
        File.WriteAllText(Path.Combine(directory,techsetTarget),techset.ToJsonString(new JsonSerializerOptions{WriteIndented=true}));
        Log("Attached authored 1.20 material and real technique/shader definitions. Re-export your graybox now.");
    });

    private void AddFloor_Click(object sender, RoutedEventArgs e) => AddBlock("Floor", 24,24,1,-0.5);
    private void AddRamp_Click(object sender,RoutedEventArgs e)=>AddSpecial("Ramp","ramp",192,256,128);
    private void AddCylinder_Click(object sender,RoutedEventArgs e)=>AddSpecial("Cylinder","cylinder",128,128,128);
    private void AddStairs_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        ProjectRoot();Require(_blocks.Count<=590,"Not enough room for a flight of stairs.");
        RememberEdit();
        int batch=_blocks.Count;
        // Eight independent convex solid steps for native collision.
        for(int i=0;i<8;i++) _blocks.Add(new Block($"Stair{batch}_{i}",
            0,i*32-112,(i+1)*12,192,32,(i+1)*24));
        RefreshScene(_blocks.Count-1);SaveScene();
    });
    private void AddSpecial(string name,string shape,double w,double l,double h)=>Handle(()=>{
        ProjectRoot();Require(_blocks.Count<600,"Maximum of 600 solid brushes reached.");
        RememberEdit();_blocks.Add(new Block(name+_blocks.Count,0,0,h/2,w,l,h,0,shape));
        RefreshScene(_blocks.Count-1);SaveScene();
    });

    private void AddBox_Click(object sender, RoutedEventArgs e) => AddBlock("Block", 4,4,4,2);
    private void AddBlock(string kind,double x,double y,double z,double zOffset) => Handle(() =>
    {
        ProjectRoot();
        Require(_blocks.Count<600,"Maximum of 600 convex brushes reached.");
        var n=_blocks.Count(b=>b.Name.StartsWith(kind,StringComparison.Ordinal));
        RememberEdit();
        _blocks.Add(new Block(kind+n,n%5*5-10,(n/5)*5-10,zOffset,x,y,z));
        RefreshScene(_blocks.Count-1);SaveScene();
    });
    private void Remove_Click(object sender, RoutedEventArgs e) => Handle(() =>
    {
        var index=Objects.SelectedIndex;if(index<0)return;
        RememberEdit();_blocks.RemoveAt(index);RefreshScene(Math.Min(index,_blocks.Count-1));SaveScene();
    });
    private void SaveScene_Click(object sender, RoutedEventArgs e) => Handle(() => {SaveScene();Log("Scene saved and OBJ exported.");});

    private static ReplayBrushGeometry.Mesh Shape(Block b)=> ReplayBrushGeometry.Build(
        b.Shape,b.X,b.Y,b.Z,b.Width,b.Length,b.Height,b.Yaw);
    private static Point3D[] Corners(Block b)=>Shape(b).Points;
    private GeometryModel3D BlockModel(Block b,bool selected=false)
    {
        var mesh=new MeshGeometry3D();var source=Shape(b);
        foreach(var face in source.Faces)
        {
            var start=mesh.Positions.Count;
            // Editor-only UV projection; the native export uses authored UVScale.
            var pts=face.Select(i=>source.Points[i]).ToArray();
            var normal=ReplayBrushGeometry.Normal(source.Points,face);
            var mode=Math.Abs(normal.Z)>=Math.Max(Math.Abs(normal.X),Math.Abs(normal.Y))?0:
                Math.Abs(normal.Y)>=Math.Abs(normal.X)?1:2;
            double U(Point3D p)=>mode==2?p.Y:p.X;
            double V(Point3D p)=>mode==0?p.Y:p.Z;
            var minU=pts.Min(U);var maxU=pts.Max(U);
            var minV=pts.Min(V);var maxV=pts.Max(V);
            foreach(var pt in pts)
            {
                mesh.Positions.Add(pt);
                mesh.TextureCoordinates.Add(new Point((U(pt)-minU)/Math.Max(1,maxU-minU),
                    1-(V(pt)-minV)/Math.Max(1,maxV-minV)));
            }
            for(int i=1;i<face.Length-1;i++)
            {
                mesh.TriangleIndices.Add(start);mesh.TriangleIndices.Add(start+i);
                mesh.TriangleIndices.Add(start+i+1);
            }
        }
        var brush=new SolidColorBrush(selected?Color.FromRgb(236,184,64):
            (b.Name.Contains("Floor",StringComparison.OrdinalIgnoreCase)
            ? Color.FromRgb(79,111,129):
            b.Shape=="ramp" ? Color.FromRgb(104,171,128) :
            b.Shape=="cylinder" ? Color.FromRgb(165,132,204):Color.FromRgb(62,163,196)));
        Material material = !selected && _previewTexture != null
            ? new DiffuseMaterial(new ImageBrush(_previewTexture))
            : new DiffuseMaterial(brush);
        return new GeometryModel3D(mesh,material) { BackMaterial=material };
    }
    private void RefreshScene(int selected=-1)
    {
        while(_scene.Children.Count>2)_scene.Children.RemoveAt(2);
        Objects.Items.Clear();
        foreach(var b in _blocks){_scene.Children.Add(BlockModel(b));Objects.Items.Add($"{b.Name}  {b.Width}×{b.Length}×{b.Height}");}
        if(selected>=0 && selected<_blocks.Count)Objects.SelectedIndex=selected;
        UpdateSelectionHighlight();
        UpdateRadiantViews();
    }
    private void UpdateSelectionHighlight()
    {
        var selected=Objects.SelectedIndex;
        for(int i=0;i<_blocks.Count;++i)_scene.Children[i+2]=BlockModel(_blocks[i],i==selected);
        if (TopView != null && FrontView != null && SideView != null)
            foreach (var view in OrthographicViews) view.SetSelected(selected);
    }
    private void RememberEdit()
    {
        _undo.Push([.._blocks]);
        if(_undo.Count>64){var saved=_undo.Take(64).Reverse().ToArray();_undo.Clear();foreach(var v in saved)_undo.Push(v);}
        _redo.Clear();
    }
    private static double ParseCoordinate(string value,string label,bool dimension=false)
    {
        Require(double.TryParse(value,NumberStyles.Float,CultureInfo.InvariantCulture,out var n)
            && double.IsFinite(n) && Math.Abs(n)<=99999,$"{label} must be a finite number within ±99999; use a dot for decimals.");
        if(dimension)Require(n>=0.125 && n<=100000,$"{label} must be at least 0.125 and no more than 100000.");
        return n;
    }
    private void Objects_SelectionChanged(object sender,SelectionChangedEventArgs e)
    {
        var i=Objects.SelectedIndex;if(i<0 || i>=_blocks.Count)return;
        var b=_blocks[i];
        EditX.Text=b.X.ToString("R",CultureInfo.InvariantCulture);
        EditY.Text=b.Y.ToString("R",CultureInfo.InvariantCulture);
        EditZ.Text=b.Z.ToString("R",CultureInfo.InvariantCulture);
        EditWidth.Text=b.Width.ToString("R",CultureInfo.InvariantCulture);
        EditLength.Text=b.Length.ToString("R",CultureInfo.InvariantCulture);
        EditHeight.Text=b.Height.ToString("R",CultureInfo.InvariantCulture);
        EditYaw.Text=b.Yaw.ToString("R",CultureInfo.InvariantCulture);
        EditUVScale.Text=b.UVScale.ToString("R",CultureInfo.InvariantCulture);
        UpdateSelectionHighlight();
    }
    private void ApplyTransform_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        ProjectRoot();var i=Objects.SelectedIndex;Require(i>=0 && i<_blocks.Count,"Choose an object first.");
        var previous=_blocks[i];
        var next=previous with {
            X=ParseCoordinate(EditX.Text,"X"),Y=ParseCoordinate(EditY.Text,"Y"),Z=ParseCoordinate(EditZ.Text,"Z"),
            Width=ParseCoordinate(EditWidth.Text,"Width",true),
            Length=ParseCoordinate(EditLength.Text,"Length",true),
            Height=ParseCoordinate(EditHeight.Text,"Height",true),
            Yaw=ParseCoordinate(EditYaw.Text,"Yaw"),
            UVScale=ParseCoordinate(EditUVScale.Text,"UV tile size",true)
        };
        Require(next.Yaw is >=-360 and <=360,"Yaw must be within -360 to 360 degrees.");
        Require(next.UVScale<=8192,"UV tile size must be <=8192.");
        foreach(var pt in Corners(next))Require(Math.Abs(pt.X)<99999 && Math.Abs(pt.Y)<99999 && Math.Abs(pt.Z)<99999,
            "Transformed geometry exceeds the native source bounds.");
        if(next==previous)return;
        RememberEdit();_blocks[i]=next;RefreshScene(i);SaveScene();Log("Object transform saved.");
    });
    private void SnapSelected_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        ProjectRoot();var i=Objects.SelectedIndex;
        Require(i>=0 && i<_blocks.Count,"Select a solid to snap to the grid.");
        var step=ParseCoordinate(GridStep.Text,"Grid size",true);
        Require(step<=4096,"Grid size must be <=4096 units.");
        double Snap(double value)=>Math.Round(value/step,MidpointRounding.AwayFromZero)*step;
        var current=_blocks[i];
        var snapped=current with {X=Snap(current.X),Y=Snap(current.Y),Z=Snap(current.Z),
            Width=Math.Max(step,Snap(current.Width)),
            Length=Math.Max(step,Snap(current.Length)),Height=Math.Max(step,Snap(current.Height))};
        Require(Corners(snapped).All(v=>Math.Abs(v.X)<99999 && Math.Abs(v.Y)<99999 && Math.Abs(v.Z)<99999),
            "Snapped geometry exceeds the native world-coordinate range.");
        RememberEdit();_blocks[i]=snapped;RefreshScene(i);SaveScene();
    });
    private void Rotate90_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        ProjectRoot();var i=Objects.SelectedIndex;Require(i>=0,"Select a solid first.");
        var b=_blocks[i];RememberEdit();_blocks[i]=b with{Yaw=(b.Yaw+90)%360};
        RefreshScene(i);SaveScene();
    });

    private void Duplicate_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        ProjectRoot();var i=Objects.SelectedIndex;Require(i>=0 && i<_blocks.Count,"Choose an object first.");
        Require(_blocks.Count<600,"Maximum of 600 blockout shapes reached.");
        var b=_blocks[i];RememberEdit();_blocks.Add(b with{Name=b.Name+"_copy",X=b.X+2,Y=b.Y+2});
        RefreshScene(_blocks.Count-1);SaveScene();
    });
    private void Undo_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        if(_undo.Count==0)return;
        _redo.Push([.._blocks]);_blocks.Clear();_blocks.AddRange(_undo.Pop());RefreshScene();SaveScene();
    });
    private void Redo_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        if(_redo.Count==0)return;
        _undo.Push([.._blocks]);_blocks.Clear();_blocks.AddRange(_redo.Pop());RefreshScene();SaveScene();
    });
    private void FrameScene_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        if(_blocks.Count==0)return;
        var p=_blocks.SelectMany(Corners).ToArray();
        var x=(p.Min(t=>t.X)+p.Max(t=>t.X))/2;
        var y=(p.Min(t=>t.Y)+p.Max(t=>t.Y))/2;
        var z=(p.Min(t=>t.Z)+p.Max(t=>t.Z))/2;
        var radius=Math.Max(10,Math.Max(p.Max(t=>t.X)-p.Min(t=>t.X),
                               Math.Max(p.Max(t=>t.Y)-p.Min(t=>t.Y),p.Max(t=>t.Z)-p.Min(t=>t.Z))));
        _cameraTarget=new Point3D(x,y,z);
        _camera.Position=new Point3D(x+radius,y-radius*1.5,z+radius);
        _camera.LookDirection=new Vector3D(x-_camera.Position.X,y-_camera.Position.Y,z-_camera.Position.Z);
        foreach (var view in OrthographicViews) view.FrameAll();
    });
    private void SceneView_MouseWheel(object sender,MouseWheelEventArgs e)
    {
        var direction=_camera.Position-_cameraTarget;
        var current=direction.Length;
        if(current<.01)return;
        var next=Math.Clamp(current*Math.Pow(.85,e.Delta/120.0),16,100000);
        _camera.Position=_cameraTarget+direction*(next/current);
        _camera.LookDirection=_cameraTarget-_camera.Position;
        e.Handled=true;
    }
    private void SceneView_MouseDown(object sender,MouseButtonEventArgs e)
    {
        if(e.ChangedButton==MouseButton.Middle)
        {
            _orbiting=true;_lastMouse=e.GetPosition(SceneView);
            SceneView.CaptureMouse();e.Handled=true;return;
        }
        if(e.ChangedButton!=MouseButton.Left)return;
        var hit=VisualTreeHelper.HitTest(SceneView,e.GetPosition(SceneView)) as RayMeshGeometry3DHitTestResult;
        if(hit==null)return;
        for(int i=0;i<_blocks.Count;i++)
            if(ReferenceEquals(_scene.Children[i+2],hit.ModelHit))
            {
                Objects.SelectedIndex=i;Objects.ScrollIntoView(Objects.SelectedItem);
                e.Handled=true;break;
            }
    }
    private void SceneView_MouseUp(object sender,MouseButtonEventArgs e)
    {
        if(e.ChangedButton!=MouseButton.Middle)return;
        _orbiting=false;SceneView.ReleaseMouseCapture();e.Handled=true;
    }
    private void SceneView_MouseMove(object sender,MouseEventArgs e)
    {
        if(!_orbiting)return;
        if(e.MiddleButton!=MouseButtonState.Pressed){_orbiting=false;SceneView.ReleaseMouseCapture();return;}
        var mouse=e.GetPosition(SceneView);var dx=mouse.X-_lastMouse.X;var dy=mouse.Y-_lastMouse.Y;
        _lastMouse=mouse;
        var v=_camera.Position-_cameraTarget;var r=v.Length;if(r<=0)return;
        var az=Math.Atan2(v.Y,v.X)-dx*.009;
        var polar=Math.Clamp(Math.Acos(Math.Clamp(v.Z/r,-1,1))+dy*.009,.08,Math.PI-.08);
        _camera.Position=_cameraTarget+new Vector3D(
            r*Math.Sin(polar)*Math.Cos(az),r*Math.Sin(polar)*Math.Sin(az),r*Math.Cos(polar));
        _camera.LookDirection=_cameraTarget-_camera.Position;
        e.Handled=true;
    }

    private void Redraw()=>RefreshScene();
    private void SaveScene()
    {
        var root=ProjectRoot();var dir=Path.Combine(root,"source");Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir,"scene.json"),JsonSerializer.Serialize(_blocks,new JsonSerializerOptions{WriteIndented=true}));
        File.WriteAllText(Path.Combine(dir,"spawns.json"),JsonSerializer.Serialize(_spawns,new JsonSerializerOptions{WriteIndented=true}));
        var title=MapTitle.Text.Trim();var description=MapDescription.Text.Trim();
        Require(title.Length is >0 and <=64 && !title.Contains('\n') && !title.Contains('\r'),
            "Map title must be 1..64 characters on one line.");
        Require(description.Length<=256,"Map description must be 256 characters or fewer.");
        File.WriteAllText(Path.Combine(root,"map.json"),JsonSerializer.Serialize(new {
            id=RequireMapId(MapId.Text.Trim()),title,description
        },new JsonSerializerOptions{WriteIndented=true}));
        // The native map compiler understands these two optional authored inputs.
        // Surface material/techset and collision data must come from verified sources.
        var mapId=RequireMapId(MapId.Text.Trim());
        var mapDir=Path.Combine(root,"dump","maps","mp");
        Directory.CreateDirectory(mapDir);
        var lighting=Path.Combine(mapDir,$"{mapId}.d3dbsp.lighting.json");
        if(!File.Exists(lighting))File.WriteAllText(lighting,JsonSerializer.Serialize(new {
            schema=1,intensity=1.0,color=new[]{1.0,1.0,1.0},
            direction=new[]{0.0,0.0,-1.0},up=new[]{0.0,1.0,0.0}
        },new JsonSerializerOptions{WriteIndented=true}));
        if(_blocks.Count>0){
            var points=_blocks.SelectMany(Corners).ToList();
            var bounds=Path.Combine(mapDir,$"{mapId}.d3dbsp.bounds.json");
            var nativeExport=Path.Combine(mapDir,$"{mapId}.graybox.provenance.json");
            if(!File.Exists(nativeExport))File.WriteAllText(bounds,JsonSerializer.Serialize(new {
                schema=1,min=new[]{points.Min(p=>p.X),points.Min(p=>p.Y),points.Min(p=>p.Z)},
                max=new[]{points.Max(p=>p.X),points.Max(p=>p.Y),points.Max(p=>p.Z)}
            },new JsonSerializerOptions{WriteIndented=true}));
        }
        using var sw=new StreamWriter(Path.Combine(dir,"blockout.obj"),false,new UTF8Encoding(false));
        sw.WriteLine("# IW8 Tools authored geometry source, NOT a native IW8 GfxWorld");
        int baseVertex=1;
        foreach(var block in _blocks){
            sw.WriteLine($"o {block.Name}");
            foreach(var p in Corners(block)) sw.WriteLine(string.Format(CultureInfo.InvariantCulture,"v {0:R} {1:R} {2:R}",p.X,p.Y,p.Z));
            foreach(var face in Shape(block).Faces)
                sw.WriteLine("f "+string.Join(" ",face.Select(index=>(baseVertex+index).ToString(CultureInfo.InvariantCulture))));
            baseVertex+=Corners(block).Length;
        }
    }

    private void WriteLighting(string root,string id)
    {
        var intensity=ParseCoordinate(SunIntensity.Text,"Sun intensity");
        Require(intensity>0 && intensity<=100,"Sun intensity must be >0 and <=100.");
        var direction=new Vector3D(ParseCoordinate(SunX.Text,"Sun direction X"),
            ParseCoordinate(SunY.Text,"Sun direction Y"),ParseCoordinate(SunZ.Text,"Sun direction Z"));
        Require(direction.LengthSquared>.0001,"Sun direction cannot be zero.");
        direction.Normalize();
        var up=Vector3D.CrossProduct(direction,new Vector3D(1,0,0));
        if(up.LengthSquared<.01)up=Vector3D.CrossProduct(direction,new Vector3D(0,1,0));
        up.Normalize();
        var directory=Path.Combine(root,"dump","maps","mp");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory,$"{id}.d3dbsp.lighting.json"),
            JsonSerializer.Serialize(new{schema=1,intensity,color=new[]{1.0,1.0,1.0},
                direction=new[]{direction.X,direction.Y,direction.Z},
                up=new[]{up.X,up.Y,up.Z}},new JsonSerializerOptions{WriteIndented=true}));
        File.WriteAllText(Path.Combine(root,"source","settings.json"),
            JsonSerializer.Serialize(new{sunIntensity=intensity,sunDirection=new[]{direction.X,direction.Y,direction.Z}},
                new JsonSerializerOptions{WriteIndented=true}));
    }
    private void SaveLighting_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        WriteLighting(ProjectRoot(),RequireMapId(MapId.Text.Trim()));
        Log("Authored sunlight settings saved for the next native build.");
    });

    // This is the actual MWCOLL02 hull layout accepted by the Replay native Havok
    // baker: magic[8], uint32 hullCount, repeated (uint32 vertexCount, float xyz[]).
    // Each authored cuboid is convex. No game-owned collision bytes are redistributed.
    private void ExportGraybox_Click(object sender,RoutedEventArgs e) => Handle(ExportGraybox);
    private void ExportGraybox()
    {
        var id=RequireMapId(MapId.Text.Trim());
        var root=ProjectRoot();
        Require(_blocks.Count>0 && _blocks.Count<=600,"Native graybox requires 1..600 box primitives.");
        // Save before exporting native render/collision data. Saving afterward
        // used to replace the 64-unit native collision margins with tight bounds.
        SaveScene();
        var mapDir=Path.Combine(root,"dump","maps","mp");
        Directory.CreateDirectory(mapDir);
        WriteTdmSpawns(root,id);
        WriteLighting(root,id);
        var points=_blocks.SelectMany(Corners).ToArray();
        foreach(var b in _blocks)
        {
            Require(double.IsFinite(b.UVScale) && b.UVScale>=.125 && b.UVScale<=8192,
                "Brush UV tile size invalid; select each legacy brush and apply a tile size of 128.");
            Require(double.IsFinite(b.X) && double.IsFinite(b.Y) && double.IsFinite(b.Z) &&
                double.IsFinite(b.Width) && double.IsFinite(b.Length) && double.IsFinite(b.Height) &&
                b.Width>=0.125 && b.Length>=0.125 && b.Height>=0.125,
                "All box coordinates and dimensions must be finite and nonzero.");
        }
        Require(points.All(v=>Math.Abs(v.X)<99999 && Math.Abs(v.Y)<99999 && Math.Abs(v.Z)<99999),
            "Map geometry is outside native world coordinate bounds.");
        double[] lo=[points.Min(v=>v.X)-64,points.Min(v=>v.Y)-64,points.Min(v=>v.Z)-64];
        double[] hi=[points.Max(v=>v.X)+64,points.Max(v=>v.Y)+64,points.Max(v=>v.Z)+64];
        var bounds=new[]{lo,hi};
        using(var writer=new BinaryWriter(File.Create(Path.Combine(mapDir,$"{id}.collision.native"))))
        {
            writer.Write(Encoding.ASCII.GetBytes("MWCOLL02"));
            writer.Write((uint)_blocks.Count);
            foreach(var b in _blocks)
            {
                writer.Write((uint)Corners(b).Length);
                foreach(var point in Corners(b))
                {
                    writer.Write((float)point.X);writer.Write((float)point.Y);writer.Write((float)point.Z);
                }
            }
        }
        var surfaces=new List<object>();
        foreach(var b in _blocks)
        {
            var mesh=Shape(b);
            foreach(var face in mesh.Faces)
            {
                var normal=ReplayBrushGeometry.Normal(mesh.Points,face);
                var origin=mesh.Points[face[0]];
                var tangent=mesh.Points[face[1]]-origin;
                tangent.Normalize();
                var binormal=Vector3D.CrossProduct(normal,tangent);
                binormal.Normalize();
                var packed=ReplayBrushGeometry.PackNormal(normal,tangent);
                var vertices=face.Select(i=>{
                    var delta=mesh.Points[i]-origin;
                    return new {
                        position=new[]{mesh.Points[i].X,mesh.Points[i].Y,mesh.Points[i].Z},
                        uv=new[]{Vector3D.DotProduct(delta,tangent)/b.UVScale,
                                 Vector3D.DotProduct(delta,binormal)/b.UVScale},
                        normal=packed,color=new[]{255,255,255,255}
                    };
                }).ToArray();
                var indices=new List<int>();
                for(int i=1;i<face.Length-1;i++)indices.AddRange([0,i,i+1]);
                surfaces.Add(new {materialIndex=0,opaque=true,vertices,indices});
            }
        }
        // Reflector definitions meet the native resident RGBA8 source shape.
        // These neutral placeholders are not authored lighting or cubemap captures.
        var cubeFile=$"{id}_reflection_cube.rgba";
        var arrayFile=$"{id}_reflection_array.rgba";
        const int side=16;
        var pixel=new byte[side*side*4];
        for(int i=0;i<pixel.Length;i+=4){pixel[i]=84;pixel[i+1]=88;pixel[i+2]=92;pixel[i+3]=255;}
        using(var f=File.Create(Path.Combine(mapDir,cubeFile)))
            for(int i=0;i<6;++i) f.Write(pixel);
        File.WriteAllBytes(Path.Combine(mapDir,arrayFile),pixel);
        var center=new[]{(lo[0]+hi[0])/2,(lo[1]+hi[1])/2,(lo[2]+hi[2])/2};
        var cubemap=new{name=$"mw120r/{id}_cube",width=side,height=side,flags=0x8001,rgba8=cubeFile};
        var array=new{name=$"mw120r/{id}_array",width=side,height=side,flags=0x20000,numElements=1,rgba8=arrayFile};
        var render=new {
            schema=1,material=$"w/mw120r_{id}",
            materialDefinition=$"{id}.d3dbsp.material.json",surfaces,
            dpvs=new{
                planes=new[]{new{normal=new[]{0.0,0.0,1.0},dist=0.0,type=2}},
                nodes=new[]{0},
                cells=new[]{new{bounds,portals=Array.Empty<object>(),trees=new[]{new{
                    bounds,surfaces=Enumerable.Range(0,surfaces.Count).ToArray(),models=Array.Empty<int>()
                }}}}
            },
            reflectionProbes=new[]{new{origin=center,volume=bounds,image=cubemap,
                sh=Enumerable.Range(0,4).Select(_=>new double[9]).ToArray()}},
            reflectionProbeArrayImage=array
        };
        var opts=new JsonSerializerOptions{WriteIndented=true};
        File.WriteAllText(Path.Combine(mapDir,$"{id}.d3dbsp.render.json"),JsonSerializer.Serialize(render,opts));
        File.WriteAllText(Path.Combine(mapDir,$"{id}.d3dbsp.bounds.json"),
            JsonSerializer.Serialize(new{schema=1,min=lo,max=hi},opts));
        CollisionPath.Text=Path.Combine(mapDir,$"{id}.collision.native");
        DumpFolder.Text=Path.Combine(root,"dump");
        var scenePath=Path.Combine(root,"source","scene.json");
        var sourceHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(scenePath)));
        File.WriteAllText(Path.Combine(mapDir,$"{id}.graybox.provenance.json"),
            JsonSerializer.Serialize(new{schema=1,id,sceneSha256=sourceHash},opts));
        File.WriteAllText(Path.Combine(root,"source","geometry-report.json"),
            JsonSerializer.Serialize(new{schema=1,id,brushes=_blocks.Count,
                types=_blocks.GroupBy(b=>b.Shape).ToDictionary(g=>g.Key,g=>g.Count()),
                renderSurfaces=surfaces.Count,vertices=_blocks.Sum(b=>Shape(b).Faces.Sum(f=>f.Length)),
                collision="MWCOLL02",spawns=_spawns.Count,
                target="Replay-1.20",nativeCompiled=false},opts));
        Log($"GRAYBOX SOURCE {id}: {_blocks.Count} convex hulls, {surfaces.Count} faces, {_spawns.Count} spawns; tangent frames packed for IW8.");
        Log("COMPILER EXPERIMENT: native collision baked by ZoneTool; source shader/material definitions must be prepared separately.");
    }

    private static void RequireFreshSource(string dump,string root,string id)
    {
        var marker=Path.Combine(dump,"maps","mp",$"{id}.graybox.provenance.json");
        if(!File.Exists(marker))return; // A manually prepared native dump needn't originate from IW8 Tools.
        using var doc=JsonDocument.Parse(File.ReadAllText(marker));
        Require(doc.RootElement.GetProperty("id").GetString()==id,
            "Graybox provenance ID differs from the map ID.");
        var actual=Convert.ToHexString(SHA256.HashData(
            File.ReadAllBytes(Path.Combine(root,"source","scene.json"))));
        Require(string.Equals(actual,doc.RootElement.GetProperty("sceneSha256").GetString(),
            StringComparison.OrdinalIgnoreCase),
            "Graybox geometry changed after last export. Click Export native-source graybox + collision again.");
    }

    private static string[] ZoneNames(string id) => Parts.Select(x=>string.Format(CultureInfo.InvariantCulture,x,id)).ToArray();
    private void PreflightMap_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        var id=RequireMapId(MapId.Text.Trim());var root=ProjectRoot();
        Require(_blocks.Count is >0 and <=600,"Create 1..600 valid brush objects.");
        Require(_spawns.Count<=128,"Spawn limit is 128.");
        foreach(var entry in ValidSpawnTypes)
            Require(_spawns.Any(p=>p.Type==entry),"Required TDM spawn is missing: "+entry);
        var mapDir=Path.Combine(root,"dump","maps","mp");
        var render=Path.Combine(mapDir,$"{id}.d3dbsp.render.json");
        Require(File.Exists(render),"Export native-source geometry first.");
        RequireFreshSource(Path.Combine(root,"dump"),root,id);
        var material=Path.Combine(mapDir,$"{id}.d3dbsp.material.json");
        var techset=Path.Combine(mapDir,$"{id}.d3dbsp.techset.json");
        Require(File.Exists(material)&&File.Exists(techset),"Attach a populated native material/techset template.");
        using var mr=JsonDocument.Parse(File.ReadAllText(material));
        using var ts=JsonDocument.Parse(File.ReadAllText(techset));
        Require(mr.RootElement.GetProperty("textures").GetArrayLength()>0,"Material has no texture slots.");
        Require(ts.RootElement.GetProperty("shaders").EnumerateObject().Any(),"Native techset has no shader assets.");
        var collision=Path.Combine(mapDir,$"{id}.collision.native");
        var havok=Path.Combine(mapDir,$"{id}.d3dbsp.havok");
        Require(File.Exists(collision)||File.Exists(havok),"Export collision or attach valid TAG0 Havok input.");
        Log($"PREFLIGHT {id}: {_blocks.Count} solid brushes, {_spawns.Count} spawn points, native render/techset/collision source present.");
        Log("Preflight checks only source structure, not engine acceptance, shader compatibility, or live gameplay.");
    });

    private void ValidateSource_Click(object sender, RoutedEventArgs e) => Handle(() =>
    {
        var id=RequireMapId(MapId.Text.Trim());var dir=DumpFolder.Text;
        Require(Directory.Exists(dir),"Prepared dump directory missing.");
        RequireFreshSource(dir,ProjectRoot(),id);
        var mapDir=Path.Combine(dir,"maps","mp");
        Require(_spawns.Count>0,"Add spawn points before compiling.");
        foreach(var required in ValidSpawnTypes)Require(_spawns.Any(s=>s.Type==required),"Missing "+required);
        foreach(var ext in new[]{"render.json","lighting.json","havok"}) {
            var target=Path.Combine(mapDir,$"{id}.d3dbsp.{ext}");
            Log($"SOURCE {(File.Exists(target)?"FOUND":"MISSING")} {Path.GetFileName(target)}");
        }
        Require(File.Exists(Path.Combine(mapDir,$"{id}.d3dbsp.render.json")),
            "Native render.json missing. Blockout OBJ is not a substitute; prepare GfxWorld inputs first.");
        Log("Source basic structure checked. Compiler performs full asset validation.");
    });
    private static void ValidateNativePackage(string folder,string id)
    {
        Require(Directory.Exists(folder),"Output package not found.");
        foreach(var file in ZoneNames(id)) {
            var full=Path.Combine(folder,file);
            Require(File.Exists(full), $"Required companion fastfile missing: {file}");
            using var fs=File.OpenRead(full);var magic=new byte[16];
            Require(fs.Read(magic)==16,"Truncated fastfile: "+file);
            var known=Encoding.ASCII.GetString(magic,0,8);
            Require(known=="IWffc100"||known=="IWffa100", "Not an IW8 header: "+file);
            Require(BitConverter.ToUInt32(magic,8)==11 && BitConverter.ToUInt32(magic,12)==4087,
              "Incompatible 1.20 XFile/header version in: "+file);
        }
        var mapPath=Path.Combine(folder,"map.json");Require(File.Exists(mapPath),"map.json missing.");
        using var doc=JsonDocument.Parse(File.ReadAllText(mapPath));
        Require(doc.RootElement.GetProperty("id").GetString()==id,"map.json ID doesn't match map ID.");
        var allowed=ZoneNames(id).Append("map.json").ToHashSet(StringComparer.OrdinalIgnoreCase);
        Require(Directory.GetFiles(folder).All(p=>allowed.Contains(Path.GetFileName(p))),
          "Output contains unrelated files. Only five native fastfiles and map.json are supported.");
    }
    private void ValidatePackage_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        ValidateNativePackage(PackageFolder.Text,RequireMapId(MapId.Text.Trim()));Log("Package header/layout VALIDATED; live game compatibility not verified.");
    });

    private async Task RunProgramAsync(string exe, params string[] args)
    {
        Require(File.Exists(exe),"Tool executable missing: "+exe);
        var info=new ProcessStartInfo(exe){UseShellExecute=false,RedirectStandardOutput=true,
            RedirectStandardError=true,CreateNoWindow=true,WorkingDirectory=Path.GetDirectoryName(exe)!};
        foreach(var arg in args)info.ArgumentList.Add(arg);
        using var process=new Process{StartInfo=info};Require(process.Start(),"Could not start external tool.");
        var outputTask=process.StandardOutput.ReadToEndAsync();
        var errorTask=process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        Log(await outputTask);var err=await errorTask;if(err.Length>0)Log(err);
        Require(process.ExitCode==0,$"External tool failed with exit code {process.ExitCode}.");
    }
    private void SyncPackageMetadata(string id,string directory)
    {
        var output=Path.Combine(directory,"map.json");
        Require(File.Exists(output),"ZoneTool did not write native map.json.");
        var material=JsonNode.Parse(File.ReadAllText(output))?.AsObject()
            ?? throw new InvalidOperationException("ZoneTool map.json is invalid.");
        material["id"]=id;
        var title=MapTitle.Text.Trim();
        Require(title.Length is >0 and <=64,"Map title length invalid.");
        material["title"]=title;
        material["name"]=title;
        material["description"]=MapDescription.Text.Trim();
        File.WriteAllText(output,material.ToJsonString(new JsonSerializerOptions{WriteIndented=true}));
    }

    private async Task BuildNativeMapAsync()
    {
            var id=RequireMapId(MapId.Text.Trim());var dump=DumpFolder.Text;
            Require(Directory.Exists(dump),"Prepared dump directory missing.");
            RequireFreshSource(dump,ProjectRoot(),id);
            WriteTdmSpawns(ProjectRoot(),id);
            var mapDir=Path.Combine(dump,"maps","mp");
            Require(File.Exists(Path.Combine(mapDir,$"{id}.d3dbsp.material.json")) &&
                    File.Exists(Path.Combine(mapDir,$"{id}.d3dbsp.techset.json")),
                "First attach an authored material + valid Replay shader/techset template.");
            Directory.CreateDirectory(PackageFolder.Text);
            Log("Compiling with separately built IW8 ZoneTool...");
            Require(File.Exists(ZoneToolPath.Text),"Choose a built iw8-zonetool.exe first.");
            var args=new List<string>{"build-map",dump,id,"-o",PackageFolder.Text};
            var havok=Path.Combine(dump,"maps","mp",$"{id}.d3dbsp.havok");
            if(!File.Exists(havok)) {
                Require(Exact120(GameFolder.Text),"Collision baking requires the exact Replay 1.20 game executable.");
                var collision=string.IsNullOrWhiteSpace(CollisionPath.Text)
                    ? Path.Combine(dump,"maps","mp",$"{id}.collision.native") : CollisionPath.Text;
                Require(File.Exists(collision),"Supply a compatible MWCOLL02..12 collision input, export the graybox, or provide a native TAG0 .havok dump.");
                args.AddRange(["--replay",Path.Combine(GameFolder.Text,Exe),"--collision",collision]);
                if(!string.IsNullOrWhiteSpace(FootstepsPath.Text)){
                    Require(File.Exists(FootstepsPath.Text),"Footsteps source not found.");
                    args.AddRange(["--footsteps",FootstepsPath.Text]);
                }
            }
            await RunProgramAsync(ZoneToolPath.Text,args.ToArray());
            SyncPackageMetadata(id,PackageFolder.Text);
            await RunProgramAsync(ZoneToolPath.Text,"validate-output",PackageFolder.Text,id);
            ValidateNativePackage(PackageFolder.Text,id);
            Log("Native package built and header-checked. Live engine acceptance is still unverified.");
    }
    private async void Build_Click(object sender,RoutedEventArgs e)
    {
        try { await BuildNativeMapAsync(); }
        catch(Exception ex){Log("BUILD FAILED: "+ex.Message);MessageBox.Show(ex.Message,"IW8 Tools");}
    }
    private async void BuildAndDeploy_Click(object sender,RoutedEventArgs e)
    {
        try
        {
            Require(Directory.Exists(ProjectFolder.Text),"Create or open a map project first.");
            ExportGraybox();
            await BuildNativeMapAsync();
            await DeployForReplayAsync();
        }
        catch(Exception ex){Log("END-TO-END TEST FAILED: "+ex.Message);MessageBox.Show(ex.Message,"IW8 Tools");}
    }
    private void BrowseClientDll_Click(object sender,RoutedEventArgs e)
    {
        var picker=new OpenFileDialog{Title="Your CodRevamped MW2019 version.dll",
            Filter="CodRevamped client|version.dll|DLL files|*.dll"};
        if(picker.ShowDialog()==true)ClientDllPath.Text=picker.FileName;
    }
    private async Task DeployForReplayAsync()
    {
        var id=RequireMapId(MapId.Text.Trim());
        var dll=ClientDllPath.Text.Trim();
        var game=GameFolder.Text.Trim();
        // SHA/MD5 and native package checks happen again immediately before staging.
        Replay120MapLoader.ValidateGame(game);
        Replay120MapLoader.RequireGameStopped();
        Replay120MapLoader.ValidatePackage(PackageFolder.Text,id);
        var chosenDll=string.IsNullOrWhiteSpace(dll)?null:dll;
        var message="Deploy "+id+" to Replay 1.20\n\n"+
            Path.Combine(game,"maps",id)+"\n"+
            (chosenDll!=null?"Also install/replace CodRevamped version.dll (existing client backed up).":
                             "Keep existing CodRevamped version.dll.")+"\n\n"+
            "Uses the native custom-map runtime integrated into CodRevamped version.dll. " +
            "Use an isolated Replay installation. Continue?";
        Require(MessageBox.Show(message,"Deploy for in-game test",MessageBoxButton.YesNo,MessageBoxImage.Warning)
            ==MessageBoxResult.Yes,"Deployment cancelled.");
        var report=await Task.Run(()=>Replay120MapLoader.Deploy(PackageFolder.Text,game,id,chosenDll));
        Log(report);
    }
    private async void DeployReplay_Click(object sender,RoutedEventArgs e)
    {
        try{await DeployForReplayAsync();}
        catch(Exception ex){Log("NATIVE DEPLOY FAILED: "+ex.Message);MessageBox.Show(ex.Message,"IW8 Tools");}
    }
    private async void RestoreReplay_Click(object sender,RoutedEventArgs e)
    {
        try
        {
            var id=RequireMapId(MapId.Text.Trim());
            var root=GameFolder.Text.Trim();
            var msg="Restore the previous native package for "+id+"? The current package will be preserved separately.";
            if(MessageBox.Show(msg,"Restore 1.20 custom map",MessageBoxButton.YesNo,MessageBoxImage.Question)!=MessageBoxResult.Yes)return;
            var result=await Task.Run(()=>Replay120MapLoader.RestorePreviousMap(root,id));
            Log(result);
        }
        catch(Exception ex){Log("RESTORE FAILED: "+ex.Message);MessageBox.Show(ex.Message,"IW8 Tools");}
    }
    private void BrowseZoneTool_Click(object sender,RoutedEventArgs e){
        var picker=new OpenFileDialog{Title="Choose iw8-zonetool.exe",Filter="Executable|*.exe"};
        if(picker.ShowDialog()==true)ZoneToolPath.Text=picker.FileName;
    }
    private void BrowseGame_Click(object sender,RoutedEventArgs e){var root=ChooseFolder();if(root.Length>0)GameFolder.Text=root;}
    private static bool Exact120(string root)
    {
        var exe=Path.Combine(root,Exe);if(!File.Exists(exe))return false;
        using var file=File.OpenRead(exe);using var br=new BinaryReader(file);
        if(file.Length<512||br.ReadUInt16()!=0x5A4D)return false;
        file.Position=0x3c;var peOffset=br.ReadUInt32();
        if(peOffset>file.Length-100)return false;
        file.Position=peOffset;if(br.ReadUInt32()!=0x00004550)return false;
        var machine=br.ReadUInt16();br.ReadUInt16();var stamp=br.ReadUInt32();
        file.Position=peOffset+0x28;var entry=br.ReadUInt32();
        file.Position=peOffset+0x50;var image=br.ReadUInt32();
        return machine==0x8664 && stamp==0x5E9BAF80 && image==0x1324B000 && entry==0x021CDC10;
    }
    private async void Stage_Click(object sender,RoutedEventArgs e)
    {
        try{
            var id=RequireMapId(MapId.Text.Trim());
            Require(Exact120(GameFolder.Text),"Replay 1.20 game executable fingerprint mismatch.");
            Require(!Process.GetProcessesByName("game_dx12_ship_replay").Any(),"Close the game before staging.");
            Require(File.Exists(NativeToolsPath.Text),"Choose IW8Tools.Native.exe; build it from this solution first.");
            ValidateNativePackage(PackageFolder.Text,id);
            await RunProgramAsync(NativeToolsPath.Text,"map","stage",PackageFolder.Text,GameFolder.Text,id);
            await RunProgramAsync(NativeToolsPath.Text,"map","verify",PackageFolder.Text,GameFolder.Text,id);
            Log("Staging and byte-for-byte verification complete. Native map registration is still needed to enter the map.");
        }catch(Exception ex){Log("STAGE FAILED: "+ex.Message);MessageBox.Show(ex.Message,"IW8 Tools");}
    }
    private async void VerifyStage_Click(object sender,RoutedEventArgs e)
    {
        try {
            var id=RequireMapId(MapId.Text.Trim());
            Require(File.Exists(NativeToolsPath.Text),"Choose IW8Tools.Native.exe first.");
            await RunProgramAsync(NativeToolsPath.Text,"map","verify",PackageFolder.Text,GameFolder.Text,id);
            Log("Staged fastfiles match source package. This does not test live native registration.");
        }catch(Exception ex){Log("VERIFY FAILED: "+ex.Message);MessageBox.Show(ex.Message,"IW8 Tools");}
    }
    private async void Restore_Click(object sender,RoutedEventArgs e)
    {
        try{
            var id=RequireMapId(MapId.Text.Trim());
            Require(Exact120(GameFolder.Text),"Replay 1.20 executable fingerprint mismatch.");
            Require(!Process.GetProcessesByName("game_dx12_ship_replay").Any(),"Close the game before rollback.");
            await RunProgramAsync(NativeToolsPath.Text,"map","restore",GameFolder.Text,id);
            Log("Latest map backup restored.");
        }catch(Exception ex){Log("RESTORE FAILED: "+ex.Message);MessageBox.Show(ex.Message,"IW8 Tools");}
    }
    private static string? BrowseExe(string name)
    {
        var picker=new OpenFileDialog{Title="Choose "+name,Filter="Windows executable|*.exe"};
        return picker.ShowDialog()==true?picker.FileName:null;
    }
    private void BrowseNativeTools_Click(object sender,RoutedEventArgs e) {var p=BrowseExe("IW8Tools.Native.exe");if(p!=null)NativeToolsPath.Text=p;}
    private void BrowseUnlinker_Click(object sender,RoutedEventArgs e) {var p=BrowseExe("Unlinker.exe");if(p!=null)UnlinkerPath.Text=p;}
    private void BrowseIW3_Click(object sender,RoutedEventArgs e)
    {
        var picker=new OpenFileDialog{Title="Choose compiled IW3 multiplayer fastfile",Filter="Call of Duty fastfiles|*.ff"};
        if(picker.ShowDialog()==true)IW3Fastfile.Text=picker.FileName;
    }
    private async void ConvertIW3_Click(object sender,RoutedEventArgs e)
    {
        try{
            var id=RequireMapId(MapId.Text.Trim());
            Require(File.Exists(IW3Fastfile.Text),"Choose a real compiled CoD4/IW3 multiplayer fastfile.");
            Require(File.Exists(UnlinkerPath.Text),"Choose the matching OpenAssetTools Unlinker.exe.");
            Require(File.Exists(ZoneToolPath.Text),"Choose the built IW8 ZoneTool.");
            Require(Exact120(GameFolder.Text),"The supported Replay 1.20 game executable is required for collision baking.");
            Require(!string.IsNullOrWhiteSpace(PackageFolder.Text),"Choose a package output directory.");
            Directory.CreateDirectory(PackageFolder.Text);
            Log("Converting compiled IW3 map using the native ZoneTool, Unlinker and Replay collision baker...");
            await RunProgramAsync(ZoneToolPath.Text,"build-iw3",IW3Fastfile.Text,id,
                "-o",PackageFolder.Text,"--replay",Path.Combine(GameFolder.Text,Exe),
                "--unlinker",UnlinkerPath.Text,"--search-path",Path.GetDirectoryName(IW3Fastfile.Text)!);
            await RunProgramAsync(ZoneToolPath.Text,"validate-output",PackageFolder.Text,id);
            ValidateNativePackage(PackageFolder.Text,id);
            Log("Native package compilation completed. Staging and live engine acceptance are separate checks.");
        }catch(Exception ex){Log("IW3 CONVERSION FAILED: "+ex.Message);MessageBox.Show(ex.Message,"IW8 Tools");}
    }
    private void Texture_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        var root=ProjectRoot();var pick=new OpenFileDialog{Filter="Images|*.png;*.bmp;*.jpg;*.jpeg;*.tga;*.dds|All files|*.*"};
        if(pick.ShowDialog()!=true)return;
        using var file=File.OpenRead(pick.FileName);
        BitmapDecoder decoder=BitmapDecoder.Create(file,BitmapCreateOptions.PreservePixelFormat,BitmapCacheOption.OnLoad);
        var frame=decoder.Frames[0];
        Require(frame.PixelWidth>0&&frame.PixelHeight>0&&frame.PixelWidth<=8192&&frame.PixelHeight<=8192,"Unsupported texture dimensions.");
        var source=new FormatConvertedBitmap(frame,PixelFormats.Bgra32,null,0);
        var stride=checked(frame.PixelWidth*4);var pixels=new byte[checked(stride*frame.PixelHeight)];
        source.CopyPixels(pixels,stride,0);
        for(var i=0;i<pixels.Length;i+=4)(pixels[i],pixels[i+2])=(pixels[i+2],pixels[i]);
        var dir=Path.Combine(root,"source","images");Directory.CreateDirectory(dir);
        var name=Path.GetFileNameWithoutExtension(pick.FileName);
        name=Regex.Replace(name.ToLowerInvariant(),"[^a-z0-9_]","_");
        Require(AssetPattern.IsMatch(name),"Invalid texture identifier.");
        var dest=Path.Combine(dir,name+".rgba");File.WriteAllBytes(dest,pixels);
        File.WriteAllText(Path.Combine(dir,name+".texture.json"),JsonSerializer.Serialize(new {
           source=Path.GetFileName(pick.FileName),format="RGBA8",width=frame.PixelWidth,height=frame.PixelHeight,
           byteCount=pixels.Length, note="Source texture bytes, not an IW8 GfxImage or compiled IWI."
        },new JsonSerializerOptions{WriteIndented=true}));
        ReloadImportedTextures();
        Log($"GFX source exported: {name}.rgba ({frame.PixelWidth}x{frame.PixelHeight})");
    });
    private void UseTextureForMap_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        var root=ProjectRoot();
        var descriptorPicker=new OpenFileDialog{
            Title="Choose a texture imported through IW8Tools",
            Filter="IW8Tools texture descriptors|*.texture.json",
            InitialDirectory=Path.Combine(root,"source","images")};
        if(descriptorPicker.ShowDialog()==true) ApplyTextureDescriptor(descriptorPicker.FileName);
    });

    private void ApplyTextureDescriptor(string descriptorPath)
    {
        var root=ProjectRoot();var id=RequireMapId(MapId.Text.Trim());
        using var document=JsonDocument.Parse(File.ReadAllText(descriptorPath));
        var data=document.RootElement;
        var width=data.GetProperty("width").GetInt32();
        var height=data.GetProperty("height").GetInt32();
        Require(width is >0 and <=4096 && height is >0 and <=4096,
            "Native image requires dimensions 1..4096. Import a smaller image.");
        var rgbaSource=Path.ChangeExtension(descriptorPath,null); // removes .json
        rgbaSource=Path.ChangeExtension(rgbaSource,".rgba"); // remove .texture
        Require(File.Exists(rgbaSource),"Matching .rgba data missing: "+rgbaSource);
        Require(new FileInfo(rgbaSource).Length==(long)width*height*4,
            "RGBA source has the wrong dimensions/length.");
        var dir=Path.Combine(root,"dump","maps","mp");
        var materialFile=Path.Combine(dir,$"{id}.d3dbsp.material.json");
        Require(File.Exists(materialFile),"Attach a valid native material/shader template first.");
        var material=JsonNode.Parse(File.ReadAllText(materialFile))?.AsObject()
            ?? throw new InvalidOperationException("Invalid material JSON.");
        Require(material["textures"] is JsonArray textures && textures.Count>0 &&
            textures[0] is JsonObject,"Template has no texture slots.");
        // Avoid preserving a stock identity for a modified resident image.
        var name=$"codrevamped/{id}_color_"+Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(rgbaSource)))[..12].ToLowerInvariant();
        var outputFile=$"{id}_color.rgba";
        File.Copy(rgbaSource,Path.Combine(dir,outputFile),true);
        var first=material["textures"]![0]!.AsObject();
        first["image"]=name;
        var images=material["imageDefinitions"] as JsonArray;
        if(images is null)
        {
            images=new JsonArray();
            material["imageDefinitions"]=images;
        }
        // Replacing the selected color-map slot must not break other native
        // resident image definitions referenced by the template.
        for(int i=images.Count-1;i>=0;i--)
            if(images[i]?["name"]?.GetValue<string>()==name)images.RemoveAt(i);
        images.Add(new JsonObject{["name"]=name,["width"]=width,["height"]=height,
            ["rgba8"]=outputFile,["format"]=7});
        File.WriteAllText(materialFile,material.ToJsonString(new JsonSerializerOptions{WriteIndented=true}));
        Log($"Map material now references {name} ({width}x{height}). Rebuild the native zones. Shader must bind this color texture slot.");
    }

    private sealed class WeaponDesign
    {
        public int schema {get;set;}=2;
        public string id {get;set;}="";
        public string displayName {get;set;}="";
        public string category {get;set;}="assault_rifle";
        public int damage {get;set;}=30;
        public double rangeMeters {get;set;}=45;
        public int roundsPerMinute {get;set;}=750;
        public int magazineSize {get;set;}=30;
        public string modelSource {get;set;}="model.obj";
        public string animationProfile {get;set;}="unassigned";
        public string audioProfile {get;set;}="unassigned";
        public string[] attachments {get;set;}=[];
        public bool nativeFastfileBuilt {get;set;}=false;
        public string note {get;set;}="Authoring metadata ONLY; not an IW8 WeaponDef or an engine-ready fastfile.";
    }
    private static readonly string[] WeaponCategories = ["assault_rifle","smg","lmg","shotgun",
        "marksman_rifle","sniper_rifle","pistol"];
    private static int ParseInt(string value,int min,int max,string name)
    {
        Require(int.TryParse(value,NumberStyles.Integer,CultureInfo.InvariantCulture,out var n)
            && n>=min && n<=max,$"{name} must be an integer in [{min}, {max}].");
        return n;
    }
    private static string SafeSource(string path)
    {
        Require(!string.IsNullOrWhiteSpace(path) && path.Length<=180 && !Path.IsPathRooted(path)
            && !path.Contains(':') && path.IndexOfAny(Path.GetInvalidPathChars())<0
            && !path.Replace('\\','/').Split('/').Any(s=>s is ".." or "." or ""),
            "Model path must be a relative path without traversal (example: model.obj).");
        return path;
    }
    private WeaponDesign ReadWeaponControls(string id)
    {
        var p=new WeaponDesign {
            id=id,displayName=WeaponDisplayName.Text.Trim(),
            category=(WeaponCategory.SelectedItem as ComboBoxItem)?.Content?.ToString()??"assault_rifle",
            damage=ParseInt(WeaponDamage.Text,1,1000,"Damage"),
            rangeMeters=ParseCoordinate(WeaponRange.Text,"Range"),
            roundsPerMinute=ParseInt(WeaponRpm.Text,1,2000,"RPM"),
            magazineSize=ParseInt(WeaponMagazine.Text,1,500,"Magazine"),
            modelSource=SafeSource(WeaponModel.Text.Trim()),
            animationProfile=WeaponAnimation.Text.Trim(),audioProfile=WeaponAudio.Text.Trim(),
            attachments=WeaponAttachments.Text.Split(',',StringSplitOptions.TrimEntries|StringSplitOptions.RemoveEmptyEntries)
        };
        Require(p.displayName.Length is >0 and <=80,"Display name must be 1-80 characters.");
        Require(p.rangeMeters is >=0.1 and <=1000,"Range must be between 0.1 and 1000 meters.");
        Require(WeaponCategories.Contains(p.category),"Unknown weapon category.");
        Require(p.attachments.Length<=32 && p.attachments.All(a=>AssetPattern.IsMatch(a)),
            "Attachment names must be valid lower-case IDs, max 32 entries.");
        Require(p.animationProfile.Length<=100 && p.audioProfile.Length<=100,"Profile references too long.");
        return p;
    }
    private static JsonSerializerOptions WeaponJson => new(){WriteIndented=true};
    private string WeaponDirectory(string id)=>Path.Combine(ProjectRoot(),"source","weapons",id);
    private void ShowWeapon(WeaponDesign p)
    {
        _loadedWeaponId=p.id;WeaponId.Text=p.id;WeaponDisplayName.Text=p.displayName;
        WeaponCategory.SelectedIndex=Array.IndexOf(WeaponCategories,p.category);
        if(WeaponCategory.SelectedIndex<0)WeaponCategory.SelectedIndex=0;
        WeaponDamage.Text=p.damage.ToString(CultureInfo.InvariantCulture);
        WeaponRange.Text=p.rangeMeters.ToString("R",CultureInfo.InvariantCulture);
        WeaponRpm.Text=p.roundsPerMinute.ToString(CultureInfo.InvariantCulture);
        WeaponMagazine.Text=p.magazineSize.ToString(CultureInfo.InvariantCulture);
        WeaponModel.Text=p.modelSource;WeaponAnimation.Text=p.animationProfile;
        WeaponAudio.Text=p.audioProfile;WeaponAttachments.Text=string.Join(", ",p.attachments??[]);
    }
    private void Weapon_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        var id=WeaponId.Text.Trim().ToLowerInvariant();Require(AssetPattern.IsMatch(id),"Invalid weapon asset ID.");
        var folder=WeaponDirectory(id);
        Require(!Directory.Exists(folder),"Weapon already exists. Use Open profile instead.");
        Directory.CreateDirectory(folder);
        var p=new WeaponDesign{id=id,displayName=id};
        File.WriteAllText(Path.Combine(folder,"weapon.authoring.json"),JsonSerializer.Serialize(p,WeaponJson));
        ShowWeapon(p);Log("Created editable weapon design: "+id);
    });
    private void OpenWeapon_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        var id=WeaponId.Text.Trim().ToLowerInvariant();Require(AssetPattern.IsMatch(id),"Invalid weapon asset ID.");
        var path=Path.Combine(WeaponDirectory(id),"weapon.authoring.json");
        Require(File.Exists(path),"No weapon profile found for that ID. Create it first.");
        var p=JsonSerializer.Deserialize<WeaponDesign>(File.ReadAllText(path))
            ?? throw new InvalidOperationException("Invalid weapon profile JSON.");
        Require(p.id==id,"Stored profile ID does not match its directory.");
        ShowWeapon(p);Log("Opened weapon design: "+id);
    });
    private void SaveWeapon_Click(object sender,RoutedEventArgs e)=>Handle(()=>{
        var id=WeaponId.Text.Trim().ToLowerInvariant();Require(AssetPattern.IsMatch(id),"Invalid weapon asset ID.");
        Require(_loadedWeaponId==id,"Open or create this weapon ID before saving.");
        var folder=WeaponDirectory(id);Require(Directory.Exists(folder),"Weapon folder missing.");
        var p=ReadWeaponControls(id);
        var dest=Path.Combine(folder,"weapon.authoring.json");
        Require(File.Exists(dest),"Refusing to overwrite a missing original profile.");
        using(var doc=JsonDocument.Parse(File.ReadAllText(dest)))
            Require(doc.RootElement.GetProperty("id").GetString()==id,"On-disk profile ID mismatch.");
        var temp=dest+".tmp";
        File.WriteAllText(temp,JsonSerializer.Serialize(p,WeaponJson));
        File.Move(temp,dest,true);
        File.WriteAllText(Path.Combine(folder,"weapon.dependencies.json"),JsonSerializer.Serialize(new{
            schema=1,id,target="Replay-1.20",phase="authoring-only",
            requiredForNativeCompilation=new[]{"WeaponDef","weapon attachments","XModel + tags/rig",
                "XAnim","GfxImage + materials + shaders","sound aliases","FX and inventory registration"},
            sourceReferences=new{model=p.modelSource,animation=p.animationProfile,audio=p.audioProfile,attachments=p.attachments},
            missingAssetEncoding="Native asset serializers and verified per-build dependency graph required"
        },WeaponJson));
        Log("Saved source weapon profile and dependency checklist: "+id);
    });
    private async void Inspect_Click(object sender,RoutedEventArgs e){
        try {
            Require(File.Exists(NativeToolsPath.Text),"Build MWAssetLab and select its executable.");
            Require(File.Exists(InputFolder.Text)||Directory.Exists(InputFolder.Text),"Source folder/file missing.");
            var report=Path.Combine(Path.GetTempPath(),"CodRevamped_IW8AssetReport.json");
            await RunProgramAsync(NativeToolsPath.Text,"assets",InputFolder.Text,"--output",report);
            Log("Asset report saved: "+report);
        }catch(Exception ex){Log("INSPECTION FAILED: "+ex.Message);}
    }
    private async void InspectPackages_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Require(File.Exists(NativeToolsPath.Text), "Build IW8Tools.Native.exe first.");
            var picker = new OpenFileDialog
            {
                Title = "Select IW8 .ff / .fp / .xpak / .sabs samples",
                Filter = "IW8 files|*.ff;*.fp;*.xpak;*.sabs|All files|*.*",
                Multiselect = true
            };
            if (picker.ShowDialog() != true) return;
            var files = picker.FileNames;
            Require(files.Length is > 0 and <= 64, "Choose 1 to 64 files.");
            var arguments = new List<string> { "packages" };
            arguments.AddRange(files);
            await RunProgramAsync(NativeToolsPath.Text, arguments.ToArray());
        }
        catch (Exception ex) { Log("PACKAGE INSPECTION FAILED: " + ex.Message); }
    }
    private string RequireFastfileLab()
    {
        Require(File.Exists(NativeToolsPath.Text),"Build IW8FastfileLab and select its executable.");
        return NativeToolsPath.Text;
    }
    private string RequireResearchFastfile()
    {
        Require(File.Exists(InputFolder.Text) &&
            string.Equals(Path.GetExtension(InputFolder.Text),".ff",StringComparison.OrdinalIgnoreCase),
            "Choose a .ff file in the Source folder/file field (drag-and-drop works).");
        return InputFolder.Text;
    }
    private async void InspectFastfile_Click(object sender,RoutedEventArgs e)
    {
        try {
            var exe=RequireFastfileLab();var source=RequireResearchFastfile();
            var report=Path.Combine(Path.GetTempPath(),"IW8FastfileLab_"+Guid.NewGuid().ToString("N")+".json");
            await RunProgramAsync(exe,"fastfile","inspect",source,report);
            Log("Fastfile header/codec report: "+report);
        }catch(Exception ex){Log("FASTFILE INSPECTION FAILED: "+ex.Message);}
    }
    private async void CompareFastfiles_Click(object sender,RoutedEventArgs e)
    {
        try {
            var exe=RequireFastfileLab();var first=RequireResearchFastfile();
            Require(File.Exists(FastfileComparePath.Text),"Select the second fastfile.");
            await RunProgramAsync(exe,"fastfile","compare",first,FastfileComparePath.Text);
        }catch(Exception ex){Log("FASTFILE COMPARISON FAILED: "+ex.Message);}
    }
    private async void ExtractStoredFastfile_Click(object sender,RoutedEventArgs e)
    {
        try {
            var exe=RequireFastfileLab();var source=RequireResearchFastfile();
            var dest=FastfileWorkFolder.Text.Trim();
            Require(Path.IsPathFullyQualified(dest),"Enter a full path for a NEW extraction folder.");
            Require(!File.Exists(dest)&&!Directory.Exists(dest),"Extraction folder already exists. Choose a NEW folder; input is never overwritten.");
            await RunProgramAsync(exe,"fastfile","extract-stored",source,dest);
            Log("Stored raw zone extraction: "+dest);
        }catch(Exception ex){Log("FASTFILE EXTRACTION FAILED: "+ex.Message);}
    }
    private async void RebuildStoredFastfile_Click(object sender,RoutedEventArgs e)
    {
        try {
            var exe=RequireFastfileLab();
            var folder=FastfileWorkFolder.Text.Trim();var output=FastfileRebuiltPath.Text.Trim();
            Require(Directory.Exists(folder),"Select an existing extracted folder.");
            Require(Path.IsPathFullyQualified(output) && string.Equals(Path.GetExtension(output),".ff",StringComparison.OrdinalIgnoreCase),
                "Choose a full output .ff path.");
            Require(!File.Exists(output),"Refusing to overwrite an existing .ff.");
            await RunProgramAsync(exe,"fastfile","rebuild-stored",folder,output);
            Log("Rebuilt unsigned 1.20 stored fastfile: "+output);
        }catch(Exception ex){Log("FASTFILE REBUILD FAILED: "+ex.Message);}
    }
    private async void AnalyzeBinary_Click(object sender,RoutedEventArgs e)
    {
        try{
            Require(File.Exists(NativeToolsPath.Text),"Build/select IW8Tools.Native.exe first.");
            Require(File.Exists(OldBinary.Text),"Choose an executable or DLL.");
            var outPath=Path.Combine(Path.GetTempPath(),"IW8ReverseLab_scan.json");
            await RunProgramAsync(NativeToolsPath.Text,"reverse","scan",OldBinary.Text,outPath);
            Log("Read-only PE report: "+outPath);
        }catch(Exception ex){Log("PE ANALYSIS FAILED: "+ex.Message);}
    }
    private async void CompareBinaries_Click(object sender,RoutedEventArgs e)
    {
        try{
            Require(File.Exists(NativeToolsPath.Text),"Build/select IW8Tools.Native.exe first.");
            Require(File.Exists(OldBinary.Text)&&File.Exists(NewBinary.Text),"Choose two executables or DLLs.");
            var outPath=Path.Combine(Path.GetTempPath(),"IW8ReverseLab_compare.json");
            await RunProgramAsync(NativeToolsPath.Text,"reverse","compare",OldBinary.Text,NewBinary.Text,outPath);
            Log("Read-only comparison: "+outPath);
        }catch(Exception ex){Log("PE COMPARISON FAILED: "+ex.Message);}
    }
    private async void CompareAssets_Click(object sender,RoutedEventArgs e)
    {
        try{
            Require(File.Exists(NativeToolsPath.Text),"Build MWAssetLab and select its executable.");
            Require(File.Exists(InputFolder.Text)||Directory.Exists(InputFolder.Text),"Choose a new-build asset folder or file.");
            Require(Directory.Exists(BaselineFolder.Text),"Choose the Replay 1.20 baseline directory.");
            var path=Path.Combine(Path.GetTempPath(),"CodRevamped_AssetVersionDiff.json");
            await RunProgramAsync(NativeToolsPath.Text,"assets",InputFolder.Text,"--baseline",BaselineFolder.Text,"--output",path);
            Log("Read-only per-file asset compatibility report: "+path);
        }catch(Exception ex){Log("ASSET COMPARISON FAILED: "+ex.Message);}
    }
    private void Window_Drop(object sender,DragEventArgs e){
        if(!e.Data.GetDataPresent(DataFormats.FileDrop))return;
        var paths=(string[]?)e.Data.GetData(DataFormats.FileDrop);
        if(paths is not {Length:>0})return;
        InputFolder.Text=paths[0];Log("Asset selected: "+paths[0]);
    }
}
