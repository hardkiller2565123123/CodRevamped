using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace CodRevamped.Launcher;

internal sealed class LauncherSettings
{
    public string GameFolder { get; set; } = "";
    public string GameVersion { get; set; } = "1.20";
    public string PlayerName { get; set; } = "revamped";
}

public sealed class MainWindow : Window
{
    private readonly LauncherSettings _settings;
    private readonly TextBlock _folderLabel = new();
    private readonly TextBlock _statusLabel = new();
    private readonly Button _play = new();
    private Process? _server;
    private bool _launching;

    private static string SettingsFile => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CodRevamped", "launcher.json");

    public MainWindow()
    {
        Title = "CodRevamped";
        Width = 960;
        Height = 555;
        MinWidth = 760;
        MinHeight = 460;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Brushes.Black;
        _settings = Load();
        var root = new Grid();
        var image = new BitmapImage(new Uri("pack://application:,,,/Assets/BattlePassSeason3.png"));
        root.Background = new ImageBrush(image) { Stretch = Stretch.UniformToFill };
        Content = root;

        var shade = new Border
        {
            Background = new LinearGradientBrush(
                Color.FromArgb(30, 6, 10, 16), Color.FromArgb(245, 7, 12, 17), 90),
            VerticalAlignment = VerticalAlignment.Bottom,
            Height = 150
        };
        root.Children.Add(shade);

        var controls = new Grid { Margin = new Thickness(32, 0, 32, 28), VerticalAlignment = VerticalAlignment.Bottom };
        controls.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        controls.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        root.Children.Add(controls);

        var left = new StackPanel { Orientation = Orientation.Vertical, VerticalAlignment = VerticalAlignment.Bottom };
        var browse = MakeButton("SELECT GAME FOLDER", Color.FromRgb(31, 46, 56), 192);
        browse.HorizontalAlignment = HorizontalAlignment.Left;
        browse.Click += (_, _) => ChooseFolder();
        left.Children.Add(browse);
        _folderLabel.Foreground = Brushes.White;
        _folderLabel.FontSize = 12;
        _folderLabel.Opacity = 0.8;
        _folderLabel.MaxWidth = 595;
        _folderLabel.TextTrimming = TextTrimming.CharacterEllipsis;
        _folderLabel.Margin = new Thickness(0, 10, 0, 0);
        left.Children.Add(_folderLabel);
        _statusLabel.Foreground = new SolidColorBrush(Color.FromRgb(199, 219, 224));
        _statusLabel.FontSize = 11;
        _statusLabel.Margin = new Thickness(0, 4, 0, 0);
        left.Children.Add(_statusLabel);
        controls.Children.Add(left);

        var right = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Bottom };
        var gear = MakeButton("⚙", Color.FromRgb(33, 48, 56), 52);
        gear.FontSize = 25;
        gear.ToolTip = "Version and player name";
        gear.Click += (_, _) => SettingsDialog();
        right.Children.Add(gear);
        _play.Content = "▶  PLAY";
        _play.Width = 180;
        _play.Height = 52;
        _play.FontSize = 17;
        _play.FontWeight = FontWeights.SemiBold;
        _play.Margin = new Thickness(10, 0, 0, 0);
        _play.BorderThickness = new Thickness(0);
        _play.Foreground = Brushes.White;
        ApplyButtonStyle(_play, Color.FromRgb(32, 133, 70), Color.FromRgb(38, 146, 78), Color.FromRgb(24, 106, 56));
        _play.Click += async (_, _) => await Launch();
        right.Children.Add(_play);
        Grid.SetColumn(right, 1);
        controls.Children.Add(right);
        Refresh();
    }

    // Explicit templates are required: Windows' default Button theme can render the
    // disabled Play button white and hide the Save label despite Foreground/Background.
    private static void ApplyButtonStyle(Button button, Color normal, Color hover, Color pressed)
    {
        button.Background = new SolidColorBrush(normal);
        button.Foreground = new SolidColorBrush(Color.FromRgb(232, 239, 240));
        button.BorderThickness = new Thickness(0);
        button.Cursor = Cursors.Hand;

        var chrome = new FrameworkElementFactory(typeof(Border));
        chrome.Name = "ButtonChrome";
        chrome.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
        chrome.SetBinding(Border.BackgroundProperty, new Binding(nameof(Button.Background))
        {
            RelativeSource = RelativeSource.TemplatedParent
        });
        chrome.SetValue(Border.SnapsToDevicePixelsProperty, true);

        var content = new FrameworkElementFactory(typeof(TextBlock));
        content.Name = "ButtonText";
        content.SetBinding(TextBlock.TextProperty, new Binding(nameof(Button.Content))
        {
            RelativeSource = RelativeSource.TemplatedParent
        });
        content.SetBinding(TextBlock.ForegroundProperty, new Binding(nameof(Button.Foreground))
        {
            RelativeSource = RelativeSource.TemplatedParent
        });
        content.SetBinding(TextBlock.FontWeightProperty, new Binding(nameof(Button.FontWeight))
        {
            RelativeSource = RelativeSource.TemplatedParent
        });
        content.SetBinding(TextBlock.FontSizeProperty, new Binding(nameof(Button.FontSize))
        {
            RelativeSource = RelativeSource.TemplatedParent
        });
        content.SetValue(TextBlock.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        content.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
        content.SetValue(TextBlock.TextAlignmentProperty, TextAlignment.Center);
        content.SetValue(TextBlock.MarginProperty, new Thickness(7, 0, 7, 0));
        chrome.AppendChild(content);

        var template = new ControlTemplate(typeof(Button)) { VisualTree = chrome };
        var over = new MultiTrigger();
        over.Conditions.Add(new Condition(UIElement.IsEnabledProperty, true));
        over.Conditions.Add(new Condition(UIElement.IsMouseOverProperty, true));
        over.Setters.Add(new Setter(Border.BackgroundProperty, new SolidColorBrush(hover), "ButtonChrome"));
        template.Triggers.Add(over);

        var down = new Trigger { Property = ButtonBase.IsPressedProperty, Value = true };
        down.Setters.Add(new Setter(Border.BackgroundProperty, new SolidColorBrush(pressed), "ButtonChrome"));
        template.Triggers.Add(down);

        var disabled = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
        disabled.Setters.Add(new Setter(Border.BackgroundProperty,
            new SolidColorBrush(Color.FromRgb(59, 66, 72)), "ButtonChrome"));
        disabled.Setters.Add(new Setter(TextBlock.ForegroundProperty,
            new SolidColorBrush(Color.FromRgb(156, 166, 172)), "ButtonText"));
        disabled.Setters.Add(new Setter(FrameworkElement.CursorProperty, Cursors.Arrow));
        template.Triggers.Add(disabled);

        var style = new Style(typeof(Button));
        style.Setters.Add(new Setter(Control.TemplateProperty, template));
        style.Setters.Add(new Setter(FrameworkElement.FocusVisualStyleProperty, null));
        button.Style = style;
    }

    private static Button MakeButton(string label, Color background, double width)
    {
        var button = new Button
        {
            Content = label, Width = width, Height = 48,
            BorderThickness = new Thickness(0), FontWeight = FontWeights.Medium
        };
        ApplyButtonStyle(button, background,
            Lighten(background, 11), Darken(background, 12));
        return button;
    }

    private static Color Lighten(Color color, byte difference) => Color.FromRgb(
        (byte)Math.Min(255, color.R + difference),
        (byte)Math.Min(255, color.G + difference),
        (byte)Math.Min(255, color.B + difference));

    private static Color Darken(Color color, byte difference) => Color.FromRgb(
        (byte)Math.Max(0, color.R - difference),
        (byte)Math.Max(0, color.G - difference),
        (byte)Math.Max(0, color.B - difference));

    private static ComboBox MakeVersionSelector()
    {
        var selector = new ComboBox
        {
            ItemsSource = new[] { "1.20" },
            SelectedItem = "1.20",
            Height = 32,
            Foreground = new SolidColorBrush(Color.FromRgb(224, 235, 237)),
            Background = new SolidColorBrush(Color.FromRgb(26, 36, 43)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(62, 77, 86)),
            BorderThickness = new Thickness(1),
            FocusVisualStyle = null
        };

        // The system ComboBox can otherwise turn white or bright blue on highlight.
        var itemChrome = new FrameworkElementFactory(typeof(Border));
        itemChrome.Name = "ItemChrome";
        itemChrome.SetValue(Border.BackgroundProperty,
            new SolidColorBrush(Color.FromRgb(27, 37, 44)));
        itemChrome.SetValue(Border.PaddingProperty, new Thickness(10, 7, 10, 7));
        var itemContent = new FrameworkElementFactory(typeof(ContentPresenter));
        itemContent.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
        itemContent.SetValue(ContentPresenter.ContentSourceProperty, "Content");
        itemChrome.AppendChild(itemContent);
        var itemTemplate = new ControlTemplate(typeof(ComboBoxItem)) { VisualTree = itemChrome };
        var highlighted = new Trigger { Property = ComboBoxItem.IsHighlightedProperty, Value = true };
        highlighted.Setters.Add(new Setter(Border.BackgroundProperty,
            new SolidColorBrush(Color.FromRgb(51, 65, 72)), "ItemChrome"));
        itemTemplate.Triggers.Add(highlighted);
        var selected = new Trigger { Property = ComboBoxItem.IsSelectedProperty, Value = true };
        selected.Setters.Add(new Setter(Border.BackgroundProperty,
            new SolidColorBrush(Color.FromRgb(45, 61, 68)), "ItemChrome"));
        itemTemplate.Triggers.Add(selected);
        var itemStyle = new Style(typeof(ComboBoxItem));
        itemStyle.Setters.Add(new Setter(Control.TemplateProperty, itemTemplate));
        itemStyle.Setters.Add(new Setter(Control.ForegroundProperty,
            new SolidColorBrush(Color.FromRgb(224, 235, 237))));
        itemStyle.Setters.Add(new Setter(FrameworkElement.FocusVisualStyleProperty, null));
        selector.ItemContainerStyle = itemStyle;

        var border = new FrameworkElementFactory(typeof(Border));
        border.Name = "SelectorChrome";
        border.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
        border.SetValue(Border.BackgroundProperty, new SolidColorBrush(Color.FromRgb(26, 36, 43)));
        border.SetValue(Border.BorderBrushProperty, new SolidColorBrush(Color.FromRgb(62, 77, 86)));
        border.SetValue(Border.BorderThicknessProperty, new Thickness(1));
        var grid = new FrameworkElementFactory(typeof(Grid));

        var displayed = new FrameworkElementFactory(typeof(ContentPresenter));
        displayed.SetBinding(ContentPresenter.ContentProperty, new Binding("SelectionBoxItem")
        {
            RelativeSource = RelativeSource.TemplatedParent
        });
        displayed.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
        displayed.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Left);
        displayed.SetValue(ContentPresenter.MarginProperty, new Thickness(10, 0, 40, 0));
        displayed.SetValue(UIElement.IsHitTestVisibleProperty, false);
        grid.AppendChild(displayed);

        var arrow = new FrameworkElementFactory(typeof(TextBlock));
        arrow.SetValue(TextBlock.TextProperty, "⌄");
        arrow.SetValue(TextBlock.ForegroundProperty, new SolidColorBrush(Color.FromRgb(150, 164, 171)));
        arrow.SetValue(TextBlock.FontSizeProperty, 17.0);
        arrow.SetValue(TextBlock.HorizontalAlignmentProperty, HorizontalAlignment.Right);
        arrow.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
        arrow.SetValue(TextBlock.MarginProperty, new Thickness(0, 0, 13, 3));
        arrow.SetValue(UIElement.IsHitTestVisibleProperty, false);
        grid.AppendChild(arrow);

        var toggle = new FrameworkElementFactory(typeof(ToggleButton));
        toggle.SetValue(Control.BackgroundProperty, Brushes.Transparent);
        toggle.SetValue(Control.BorderThicknessProperty, new Thickness(0));
        toggle.SetValue(Control.FocusVisualStyleProperty, null);
        toggle.SetBinding(ToggleButton.IsCheckedProperty, new Binding("IsDropDownOpen")
        {
            RelativeSource = RelativeSource.TemplatedParent, Mode = BindingMode.TwoWay
        });
        // A transparent click target with no system-theme chrome or bright focus rectangle.
        var toggleBorder = new FrameworkElementFactory(typeof(Border));
        toggleBorder.SetValue(Border.BackgroundProperty, Brushes.Transparent);
        var toggleTemplate = new ControlTemplate(typeof(ToggleButton)) { VisualTree = toggleBorder };
        var toggleStyle = new Style(typeof(ToggleButton));
        toggleStyle.Setters.Add(new Setter(Control.TemplateProperty, toggleTemplate));
        toggle.SetValue(FrameworkElement.StyleProperty, toggleStyle);
        grid.AppendChild(toggle);

        var popup = new FrameworkElementFactory(typeof(Popup));
        popup.Name = "PART_Popup";
        popup.SetValue(Popup.PlacementProperty, PlacementMode.Bottom);
        popup.SetValue(Popup.AllowsTransparencyProperty, true);
        popup.SetValue(Popup.StaysOpenProperty, false);
        popup.SetBinding(Popup.IsOpenProperty, new Binding("IsDropDownOpen")
        {
            RelativeSource = RelativeSource.TemplatedParent, Mode = BindingMode.TwoWay
        });
        var popupChrome = new FrameworkElementFactory(typeof(Border));
        popupChrome.SetValue(Border.MinWidthProperty, 260.0);
        popupChrome.SetValue(Border.BackgroundProperty,
            new SolidColorBrush(Color.FromRgb(26, 36, 43)));
        popupChrome.SetValue(Border.BorderBrushProperty,
            new SolidColorBrush(Color.FromRgb(62, 77, 86)));
        popupChrome.SetValue(Border.BorderThicknessProperty, new Thickness(1));
        var scroll = new FrameworkElementFactory(typeof(ScrollViewer));
        scroll.SetValue(ScrollViewer.VerticalScrollBarVisibilityProperty, ScrollBarVisibility.Auto);
        var items = new FrameworkElementFactory(typeof(ItemsPresenter));
        scroll.AppendChild(items);
        popupChrome.AppendChild(scroll);
        popup.AppendChild(popupChrome);
        grid.AppendChild(popup);
        border.AppendChild(grid);

        var selectorTemplate = new ControlTemplate(typeof(ComboBox)) { VisualTree = border };
        var selectorStyle = new Style(typeof(ComboBox));
        selectorStyle.Setters.Add(new Setter(Control.TemplateProperty, selectorTemplate));
        selectorStyle.Setters.Add(new Setter(FrameworkElement.FocusVisualStyleProperty, null));
        selector.Style = selectorStyle;
        return selector;
    }

    private static LauncherSettings Load()
    {
        try
        {
            return JsonSerializer.Deserialize<LauncherSettings>(File.ReadAllText(SettingsFile)) ?? new LauncherSettings();
        }
        catch { return new LauncherSettings(); }
    }

    // Apply the settings only after persistence succeeds. A failed write keeps
    // the dialog open and explains why Save did not work.
    private bool TrySaveSettings(LauncherSettings candidate, Window owner)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
            var temporary = SettingsFile + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(candidate));
            File.Move(temporary, SettingsFile, overwrite: true);
            _settings.GameFolder = candidate.GameFolder;
            _settings.GameVersion = candidate.GameVersion;
            _settings.PlayerName = candidate.PlayerName;
            Refresh();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(owner, $"Unable to save launcher settings:\n{ex.Message}",
                "CodRevamped Settings", MessageBoxButton.OK, MessageBoxImage.Error);
            return false;
        }
    }

    private string? GameExecutable()
    {
        if (_settings.GameVersion != "1.20" || !Directory.Exists(_settings.GameFolder)) return null;
        var path = Path.Combine(_settings.GameFolder, "game_dx12_ship_replay.exe");
        if (!File.Exists(path)) return null;
        try
        {
            using var file = File.OpenRead(path);
            using var reader = new BinaryReader(file);
            file.Position = 0x3C;
            var pe = reader.ReadInt32();
            if (pe < 0 || pe > file.Length - 256) return null;
            file.Position = pe;
            if (reader.ReadUInt32() != 0x4550) return null;
            file.Position = pe + 8;
            var timestamp = reader.ReadUInt32();
            file.Position = pe + 0x18 + 0x38;
            var imageSize = reader.ReadUInt32();
            return timestamp == 0x5E9BAF80 && imageSize == 0x1324B000 ? path : null;
        }
        catch { return null; }
    }

    private void Refresh()
    {
        var game = GameExecutable();
        _play.IsEnabled = game is not null && !_launching;
        _play.Background = new SolidColorBrush(_play.IsEnabled
            ? Color.FromRgb(32, 133, 70) : Color.FromRgb(59, 66, 72));
        _folderLabel.Text = string.IsNullOrWhiteSpace(_settings.GameFolder)
            ? "No game folder selected" : _settings.GameFolder;
        _statusLabel.Text = _launching ? "Launching…" : game is not null
            ? $"MW2019 {_settings.GameVersion}  •  {_settings.PlayerName}"
            : "Select a valid MW2019 1.20 game folder to enable Play";
    }

    private void ChooseFolder()
    {
        var dialog = new OpenFolderDialog { Title = "Select MW2019 1.20 game folder" };
        if (Directory.Exists(_settings.GameFolder)) dialog.InitialDirectory = _settings.GameFolder;
        if (dialog.ShowDialog(this) == true)
        {
            TrySaveSettings(new LauncherSettings
            {
                GameFolder = dialog.FolderName,
                GameVersion = _settings.GameVersion,
                PlayerName = _settings.PlayerName
            }, this);
        }
    }

    private void SettingsDialog()
    {
        var dialog = new Window
        {
            Title = "Settings", Owner = this, Width = 360, Height = 230,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize, Background = new SolidColorBrush(Color.FromRgb(22, 29, 35))
        };
        var content = new StackPanel { Margin = new Thickness(22) };
        dialog.Content = content;
        content.Children.Add(new TextBlock { Text = "GAME VERSION", Foreground = Brushes.White, Margin = new Thickness(0, 0, 0, 5) });
        var version = MakeVersionSelector();
        content.Children.Add(version);
        content.Children.Add(new TextBlock { Text = "PLAYER NAME", Foreground = Brushes.White, Margin = new Thickness(0, 14, 0, 5) });
        var name = new TextBox
        {
            Text = _settings.PlayerName, MaxLength = 24, Height = 32,
            Background = new SolidColorBrush(Color.FromRgb(26, 36, 43)),
            Foreground = new SolidColorBrush(Color.FromRgb(226, 235, 237)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(62, 77, 86)),
            BorderThickness = new Thickness(1),
            CaretBrush = new SolidColorBrush(Color.FromRgb(207, 225, 229)),
            SelectionBrush = new SolidColorBrush(Color.FromRgb(68, 101, 115)),
            SelectionOpacity = 0.56,
            Padding = new Thickness(9, 4, 9, 4),
            VerticalContentAlignment = VerticalAlignment.Center,
            FocusVisualStyle = null
        };
        content.Children.Add(name);
        var save = MakeButton("SAVE", Color.FromRgb(32, 133, 70), 100);
        save.HorizontalAlignment = HorizontalAlignment.Right;
        save.Margin = new Thickness(0, 16, 0, 0);
        void CommitSettings()
        {
            var trimmed = name.Text.Trim();
            if (trimmed.Length is < 1 or > 24 || trimmed.Any(c => !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c is '_' or '-' or '.')))
            {
                MessageBox.Show(dialog, "Use 1–24 letters, numbers, underscores, hyphens or dots.");
                return;
            }
            var candidate = new LauncherSettings
            {
                GameFolder = _settings.GameFolder,
                GameVersion = version.SelectedItem as string ?? "1.20",
                PlayerName = trimmed
            };
            if (TrySaveSettings(candidate, dialog)) dialog.DialogResult = true;
        }
        save.Click += (_, _) => CommitSettings();
        name.KeyDown += (_, e) =>
        {
            if (e.Key != Key.Enter) return;
            e.Handled = true;
            CommitSettings();
        };
        content.Children.Add(save);
        dialog.ShowDialog();
    }

    private static byte[] Embedded(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Debug build is missing {name}. Rebuild the launcher.");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static bool Deploy(string file, byte[] bytes, Window owner)
    {
        if (File.Exists(file))
        {
            var current = SHA256.HashData(File.ReadAllBytes(file));
            if (current.SequenceEqual(SHA256.HashData(bytes))) return true;
            var answer = MessageBox.Show(owner,
                $"Replace {Path.GetFileName(file)}? Your existing version will be backed up.",
                "CodRevamped", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (answer != MessageBoxResult.Yes) return false;
            File.Copy(file, file + ".codrevamped.backup", overwrite: true);
        }
        File.WriteAllBytes(file, bytes);
        return true;
    }

    private async Task Launch()
    {
        var game = GameExecutable();
        if (game is null || _launching) return;
        _launching = true;
        Refresh();
        try
        {
            if (!Deploy(Path.Combine(_settings.GameFolder, "version.dll"),
                  Embedded("CodRevamped.Embedded.Client"), this) ||
                !Deploy(Path.Combine(_settings.GameFolder, "RevampedIW8Server.exe"),
                  Embedded("CodRevamped.Embedded.Server"), this)) return;
            var serverInfo = new ProcessStartInfo(Path.Combine(_settings.GameFolder, "RevampedIW8Server.exe"))
            {
                WorkingDirectory = _settings.GameFolder,
                UseShellExecute = false
            };
            serverInfo.Environment["CODREVAMPED_PLAYER_NAME"] = _settings.PlayerName;
            _server = Process.Start(serverInfo)
                ?? throw new InvalidOperationException("The server did not start.");
            await Task.Delay(1500);
            if (_server.HasExited)
                throw new InvalidOperationException("The server exited before the game could start. Check its console.");
            var gameInfo = new ProcessStartInfo(game)
            {
                WorkingDirectory = _settings.GameFolder,
                UseShellExecute = false
            };
            gameInfo.Environment["CODREVAMPED_PLAYER_NAME"] = _settings.PlayerName;
            var process = Process.Start(gameInfo)
                ?? throw new InvalidOperationException("The game did not start.");
            _statusLabel.Text = "Game started";
            await process.WaitForExitAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Unable to launch", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            try { if (_server is { HasExited: false }) _server.Kill(); } catch { }
            _server?.Dispose();
            _server = null;
            _launching = false;
            Refresh();
        }
    }
}

public static class Program
{
    [STAThread]
    public static void Main()
    {
        var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
        app.Run(new MainWindow());
    }
}
