using Microsoft.Win32;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace CodRevamped.IW8Tools;

public partial class LuaMenuWorkbench : Window
{
    private LuaMenuProject _project = LuaMenuProject.Starter("Gunsmith");
    private LuaMenuWidget? _selected;
    private string? _projectFile;
    private string? _imageOnDisk;
    private bool _dragging;
    private Point _dragFrom;
    private double _initialX, _initialY;
    private bool _updating;
    private const double Scale = 0.5;

    public LuaMenuWorkbench()
    {
        InitializeComponent();
        _project = LuaMenuProject.Starter("Gunsmith");
        SetMetadata();
        UpdateLayers(_project.Widgets.FirstOrDefault());
    }
    private static void Guard(bool condition, string explanation)
    {
        if (!condition) throw new InvalidOperationException(explanation);
    }
    private void Run(Action operation)
    {
        try { operation(); }
        catch (Exception ex) { Status.Text = "ERROR: " + ex.Message; MessageBox.Show(this, ex.Message, "CodRevamped Lua Builder", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }
    private void SetMetadata()
    {
        _updating = true;
        MenuId.Text = _project.MenuId;
        MenuTitle.Text = _project.DisplayName;
        _updating = false;
        DrawReference();
    }
    private void SyncMetadata()
    {
        _project.MenuId = MenuId.Text.Trim();
        _project.DisplayName = MenuTitle.Text.Trim();
        _project.Screen = (ScreenChoice.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Gunsmith";
    }
    private void UpdateLayers(LuaMenuWidget? selected)
    {
        _selected = selected;
        Layers.ItemsSource = null;
        Layers.ItemsSource = _project.Widgets.Select(x => $"{x.Kind.ToUpperInvariant(),-7} {x.Id}").ToArray();
        Layers.SelectedIndex = selected == null ? -1 : _project.Widgets.IndexOf(selected);
        ShowProperties();
        DrawPreview();
    }
    private void ShowProperties()
    {
        _updating = true;
        var w = _selected;
        WidgetId.Text = w?.Id ?? "";
        WidgetText.Text = w?.Text ?? "";
        WidgetX.Text = w?.X.ToString(CultureInfo.InvariantCulture) ?? "";
        WidgetY.Text = w?.Y.ToString(CultureInfo.InvariantCulture) ?? "";
        WidgetW.Text = w?.Width.ToString(CultureInfo.InvariantCulture) ?? "";
        WidgetH.Text = w?.Height.ToString(CultureInfo.InvariantCulture) ?? "";
        WidgetFont.Text = w?.FontSize.ToString(CultureInfo.InvariantCulture) ?? "";
        WidgetColor.Text = w?.Color ?? "";
        WidgetAction.SelectedIndex = w?.Action switch { "open_menu" => 1, "console_command" => 2, _ => 0 };
        WidgetActionValue.Text = w?.ActionValue ?? "";
        _updating = false;
    }
    private static double Number(TextBox input) =>
        double.Parse(input.Text, NumberStyles.Float, CultureInfo.InvariantCulture);
    private void Apply_Click(object sender, RoutedEventArgs e) => Run(() =>
    {
        Guard(_selected != null, "Select a control first.");
        var w = _selected!.Clone();
        w.Id = WidgetId.Text.Trim(); w.Text = WidgetText.Text;
        w.X = Number(WidgetX); w.Y = Number(WidgetY); w.Width = Number(WidgetW); w.Height = Number(WidgetH);
        w.FontSize = int.Parse(WidgetFont.Text, CultureInfo.InvariantCulture);
        w.Color = WidgetColor.Text.Trim();
        w.Action = (WidgetAction.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "none";
        w.ActionValue = WidgetActionValue.Text.Trim();
        var index = _project.Widgets.IndexOf(_selected);
        var previous = _project.Widgets[index];
        _project.Widgets[index] = w;
        try { SyncMetadata(); LuaMenuCompiler.Validate(_project); }
        catch { _project.Widgets[index] = previous; throw; }
        Status.Text = $"Updated {w.Id} ({w.X}, {w.Y})";
        UpdateLayers(w);
    });
    private void Add(string kind) => Run(() =>
    {
        var number = 1;
        while (_project.Widgets.Any(w => w.Id == $"cr_{kind}_{number}")) number++;
        var widget = new LuaMenuWidget { Kind=kind, Id=$"cr_{kind}_{number}",
            Text=kind == "label" ? "NEW LABEL" : kind == "button" ? "NEW OPTION" : "", 
            Width=kind == "panel" ? 450 : 330, Height=kind == "panel" ? 160 : 58,
            X=250, Y=250, FontSize=22, Color="#FFFFFF" };
        _project.Widgets.Add(widget); UpdateLayers(widget);
    });
    private void AddButton_Click(object sender, RoutedEventArgs e) => Add("button");
    private void AddLabel_Click(object sender, RoutedEventArgs e) => Add("label");
    private void AddPanel_Click(object sender, RoutedEventArgs e) => Add("panel");
    private void Duplicate_Click(object sender, RoutedEventArgs e) => Run(() =>
    {
        Guard(_selected != null, "Select a control.");
        var copy = _selected!.Clone();
        var count = 1;
        var prefix = copy.Id.Length > 55 ? copy.Id[..55] : copy.Id;
        while (_project.Widgets.Any(w => w.Id == prefix + "_" + count)) count++;
        copy.Id = prefix + "_" + count;
        copy.X = Math.Min(1920 - copy.Width, copy.X + 24);
        copy.Y = Math.Min(1080 - copy.Height, copy.Y + 24);
        _project.Widgets.Add(copy); UpdateLayers(copy);
    });
    private void Remove_Click(object sender, RoutedEventArgs e) => Run(() =>
    {
        if (_selected == null) return;
        _project.Widgets.Remove(_selected); UpdateLayers(_project.Widgets.LastOrDefault());
    });
    private void Layers_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updating || Layers.SelectedIndex < 0 || Layers.SelectedIndex >= _project.Widgets.Count) return;
        _selected = _project.Widgets[Layers.SelectedIndex]; ShowProperties(); DrawPreview();
    }
    private void DrawReference()
    {
        Wireframe.Children.Clear();
        if (!string.IsNullOrWhiteSpace(_imageOnDisk) && File.Exists(_imageOnDisk))
        {
            try
            {
                var bitmap = new BitmapImage();
                bitmap.BeginInit();bitmap.CacheOption = BitmapCacheOption.OnLoad;bitmap.UriSource = new Uri(Path.GetFullPath(_imageOnDisk));bitmap.EndInit();
                Reference.Source = bitmap;
                Reference.Visibility = Visibility.Visible;
                return;
            }
            catch { /* keep schematic fallback */ }
        }
        Reference.Visibility = Visibility.Collapsed;
        void Label(string text, double x, double y, double font, string color="#B9CFDF")
        {
            var box = new TextBlock { Text=text, FontSize=font, Foreground=(Brush)new BrushConverter().ConvertFrom(color)!,FontWeight=FontWeights.SemiBold };
            Canvas.SetLeft(box,x);Canvas.SetTop(box,y); Wireframe.Children.Add(box);
        }
        void Line(double x, double y, double w, double h, string color="#263F52")
        {
            var b = new Border { Width=w,Height=h,Background=(Brush)new BrushConverter().ConvertFrom(color)! };
            Canvas.SetLeft(b,x);Canvas.SetTop(b,y);Wireframe.Children.Add(b);
        }
        Line(0,0,960,55,"#12202D");Line(0,55,960,2,"#40627A");
        Label("MW   MULTIPLAYER     CAMPAIGN     WARZONE",25,17,17);
        switch(_project.Screen)
        {
            case "Gunsmith":
                Label("GUNSMITH",40,83,34,"#E0EBF4");
                Label("PRIMARY WEAPON / BUILD PREVIEW",40,133,13);
                // Schematic silhouette only: no copyrighted in-game assets bundled.
                Line(360,186,380,10,"#708493");Line(410,173,220,35,"#556D7C");Line(520,211,30,62,"#556D7C");
                Line(350,180,90,23,"#6B8090");Line(738,181,100,15,"#6B8090");
                Label("MUZZLE         BARREL           OPTIC           STOCK",350,321,14);
                for(int i=0;i<5;i++) Line(355 + 102*i,362,88,65,"#20303E");
                break;
            case "Loadouts":
                Label("EDIT LOADOUTS",40,83,34);for(int i=0;i<7;i++){Line(38,165+i*44,235,38,"#223440");Label($"CUSTOM LOADOUT {i+1}",47,174+i*44,14);}Label("PRIMARY / SECONDARY / PERKS",336,180,19);
                break;
            case "Warzone":
                Label("WARZONE",40,83,34);Label("PLAY     WEAPONS     OPERATORS     BATTLE PASS",40,152,18);Line(40,220,400,225,"#223440");
                break;
            default:
                Label("MULTIPLAYER",40,83,34);Label("PLAY     WEAPONS     OPERATORS     BARRACKS",40,155,18);Line(40,220,370,240,"#223440");
                break;
        }
    }
    private void DrawPreview()
    {
        Overlay.Children.Clear();
        foreach (var w in _project.Widgets)
        {
            Brush foreground;
            try { foreground = (Brush)new BrushConverter().ConvertFrom(w.Color)!; }
            catch { foreground = Brushes.White; }
            var selected = ReferenceEquals(_selected,w);
            var border = new Border
            {
                Width=w.Width*Scale,Height=w.Height*Scale,
                Background=w.Kind switch { "button" => new SolidColorBrush(Color.FromArgb(210,33,55,73)), "panel" => new SolidColorBrush(Color.FromArgb(150,27,41,55)), _=>Brushes.Transparent },
                BorderBrush=selected ? Brushes.Orange : w.Kind=="button" ? new SolidColorBrush(Color.FromRgb(85,139,173)) : Brushes.Transparent,
                BorderThickness=new Thickness(selected ? 2 : w.Kind=="button" ? 1 : 0),
                Child = w.Kind=="panel" ? null : new TextBlock
                {
                    Text=w.Text,Foreground=foreground,FontSize=w.FontSize*Scale,
                    FontWeight=FontWeights.SemiBold,VerticalAlignment=VerticalAlignment.Center,
                    TextTrimming=TextTrimming.CharacterEllipsis,Margin=new Thickness(7,0,0,0)
                },Tag=w
            };
            Canvas.SetLeft(border,w.X*Scale); Canvas.SetTop(border,w.Y*Scale);
            border.MouseLeftButtonDown += (s,e) =>
            {
                _selected=w; Layers.SelectedIndex=_project.Widgets.IndexOf(w);
                ShowProperties();DrawPreview();
                _dragging=true;_dragFrom=e.GetPosition(Overlay);_initialX=w.X;_initialY=w.Y;
                Overlay.CaptureMouse();e.Handled=true;
            };
            Overlay.Children.Add(border);
        }
        try { SyncMetadata(); LuaCode.Text=LuaMenuCompiler.Generate(_project); }
        catch (Exception ex) { LuaCode.Text="-- Correct validation errors before build\n-- " + ex.Message; }
    }
    private void Overlay_MouseMove(object sender, MouseEventArgs e)
    {
        if (!_dragging || _selected==null || e.LeftButton != MouseButtonState.Pressed) return;
        var location=e.GetPosition(Overlay);
        var dx = (location.X - _dragFrom.X) / Scale;
        var dy = (location.Y - _dragFrom.Y) / Scale;
        // 8px snapping with clamping inside the design canvas.
        _selected.X=Math.Clamp(Math.Round((_initialX+dx)/8)*8,0,1920-_selected.Width);
        _selected.Y=Math.Clamp(Math.Round((_initialY+dy)/8)*8,0,1080-_selected.Height);
        ShowProperties();DrawPreview();
    }
    private void Overlay_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    { _dragging=false;Overlay.ReleaseMouseCapture(); }
    private void New_Click(object sender,RoutedEventArgs e) => Run(() =>
    {
        _project=LuaMenuProject.Starter((ScreenChoice.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Gunsmith");
        _projectFile=null;_imageOnDisk=null;SetMetadata();UpdateLayers(_project.Widgets.FirstOrDefault());Status.Text="Created new " + _project.Screen + " authoring template.";
    });
    private void ScreenChoice_Changed(object sender,SelectionChangedEventArgs e)
    {
        if (_project==null || Wireframe==null || ScreenChoice.SelectedItem is not ComboBoxItem item) return;
        _project.Screen=item.Content?.ToString()??"Gunsmith";DrawReference();
        if (Overlay!=null) DrawPreview();
    }
    private void Metadata_LostFocus(object sender,RoutedEventArgs e)
    { if (!_updating && LuaCode!=null) DrawPreview(); }
    private void Open_Click(object sender,RoutedEventArgs e) => Run(() =>
    {
        var dlg = new OpenFileDialog { Filter="CodRevamped Lua menu (*.crlua.json;*.project.json)|*.crlua.json;*.project.json|JSON (*.json)|*.json" };
        if(dlg.ShowDialog(this)!=true) return;
        _project=LuaMenuCompiler.OpenProject(dlg.FileName); _projectFile=dlg.FileName;
        _imageOnDisk=_project.ReferenceImage.Length==0 ? null : Path.Combine(Path.GetDirectoryName(dlg.FileName)!,_project.ReferenceImage);
        _updating=true;
        for (int i=0;i<ScreenChoice.Items.Count;i++)
        { if ((ScreenChoice.Items[i] as ComboBoxItem)?.Content?.ToString()==_project.Screen) ScreenChoice.SelectedIndex=i; }
        _updating=false;SetMetadata();UpdateLayers(_project.Widgets.FirstOrDefault());Status.Text="Opened " + dlg.FileName;
    });
    private void Save_Click(object sender,RoutedEventArgs e) => Run(Save);
    private void Save()
    {
        SyncMetadata();LuaMenuCompiler.Validate(_project);
        if (_projectFile==null)
        {
            var dlg = new SaveFileDialog { Filter="CodRevamped Lua project (*.crlua.json)|*.crlua.json", FileName=_project.MenuId+".crlua.json" };
            if(dlg.ShowDialog(this)!=true) return;
            _projectFile=dlg.FileName;
        }
        if (_imageOnDisk!=null && File.Exists(_imageOnDisk))
        {
            var extension=Path.GetExtension(_imageOnDisk).ToLowerInvariant();
            var output="preview_reference" + (extension==".png" ? ".png" : ".jpg");
            var target=Path.Combine(Path.GetDirectoryName(_projectFile)!,output);
            if (!Path.GetFullPath(_imageOnDisk).Equals(Path.GetFullPath(target),StringComparison.OrdinalIgnoreCase)) File.Copy(_imageOnDisk,target,true);
            _project.ReferenceImage=output;_imageOnDisk=target;
        }
        LuaMenuCompiler.SaveProject(_projectFile,_project);
        Status.Text="Saved editable layout: " + _projectFile;
    }
    private void Build_Click(object sender,RoutedEventArgs e) => Run(() =>
    {
        SyncMetadata();LuaMenuCompiler.Validate(_project);
        var folder=BuildFolder.Text.Trim();Guard(Directory.Exists(folder),"Choose an existing output folder.");
        var built=LuaMenuCompiler.Build(folder,_project);
        Status.Text="Built LUI SOURCE (not game-compiled): " + built;
    });
    private void Stage_Click(object sender,RoutedEventArgs e) => Run(() =>
    {
        SyncMetadata();LuaMenuCompiler.Validate(_project);
        var folder=GameFolder.Text.Trim(); Guard(Directory.Exists(folder),"Select a real game directory before staging.");
        LuaMenuCompiler.VerifyReplay120Executable(Path.Combine(folder,"game_dx12_ship_replay.exe"));
        var built=LuaMenuCompiler.Deploy(folder,_project);
        Status.Text="Staged source to " + built + ". Native LUI loader still unverified: this does NOT execute the script in-game.";
    });
    private void TestInGame_Click(object sender, RoutedEventArgs e) => Run(() =>
    {
        SyncMetadata(); LuaMenuCompiler.Validate(_project);
        var game = GameFolder.Text.Trim();
        Guard(Directory.Exists(game), "Choose an existing Replay game folder.");
        LuaMenuCompiler.VerifyReplay120Executable(Path.Combine(game, "game_dx12_ship_replay.exe"));
        LuaMenuCompiler.Deploy(game, _project);
        var request = Path.Combine(game, "lua", "open_request.ini");
        File.WriteAllText(request, _project.MenuId + "\n");
        Status.Text = "Test queued for " + _project.MenuId + ". Build/copy CodRevamped version.dll, restart Replay with codrevamped_lua.ini experimental_load=1, then open any native menu. Check [LUA120] logs. This is an experimental live test, not guaranteed.";
    });
    private void Preview_Click(object sender,RoutedEventArgs e)
    {
        Status.Text=_selected==null ? "Select an option on the preview." :
            $"Preview only: {_selected.Id}, action={_selected.Action}, value={_selected.ActionValue}. No engine Lua executed.";
    }
    private void Image_Click(object sender,RoutedEventArgs e) => Run(() =>
    {
        var dlg=new OpenFileDialog { Filter="Reference screenshot (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg" };
        if(dlg.ShowDialog(this)!=true) return;
        Guard(new FileInfo(dlg.FileName).Length<=30*1024*1024,"Reference image exceeds 30 MB.");
        _imageOnDisk=dlg.FileName; DrawReference();Status.Text="Loaded local screenshot for alignment (not part of compiled Lua).";
    });
    private void ChooseBuild_Click(object sender,RoutedEventArgs e)
    { var d=new OpenFolderDialog();if(d.ShowDialog(this)==true)BuildFolder.Text=d.FolderName; }
    private void ChooseGame_Click(object sender,RoutedEventArgs e)
    { var d=new OpenFolderDialog();if(d.ShowDialog(this)==true)GameFolder.Text=d.FolderName; }
}
