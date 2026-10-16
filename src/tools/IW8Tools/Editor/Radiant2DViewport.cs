using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Media3D;

namespace CodRevamped.IW8Tools;

/// <summary>
/// Radiant-style orthographic map editing surface, sharing the real authored convex geometry.
/// It does not change the native .ff serializer or attempt to render stock game assets.
/// </summary>
public sealed class Radiant2DViewport : FrameworkElement
{
    public enum ViewPlane { XY, XZ, YZ }
    public ViewPlane Plane { get; set; } = ViewPlane.XY;
    public sealed record BrushGeometry(string Label, string Shape, Point3D[] Points, int[][] Faces);
    public sealed record EntityMarker(string Label, Point3D Location);

    public Action<int>? BrushSelected { get; set; }
    public Action<int, Vector3D>? BrushMoved { get; set; }
    public Action<Point3D>? CreateBox { get; set; }
    public Action<Point3D>? CreateSpawn { get; set; }
    public Action<string>? CursorChanged { get; set; }

    private IReadOnlyList<BrushGeometry> _brushes = Array.Empty<BrushGeometry>();
    private IReadOnlyList<EntityMarker> _entities = Array.Empty<EntityMarker>();
    private int _selected = -1;
    private double _grid = 32;
    private double _scale = .45; // pixels per game unit
    private Vector _pan;
    private bool _panning;
    private bool _dragging;
    private int _dragIndex = -1;
    private Point _last;
    private Point _dragStart;
    private Vector _dragDelta;
    private Point3D _contextWorld;
    private readonly Brush _background = new SolidColorBrush(Color.FromRgb(16, 22, 26));
    private static readonly Pen MinorPen = new(new SolidColorBrush(Color.FromRgb(37, 49, 56)), .8);
    private static readonly Pen MajorPen = new(new SolidColorBrush(Color.FromRgb(65, 77, 82)), 1);
    private static readonly Pen AxisXPen = new(new SolidColorBrush(Color.FromRgb(165, 75, 72)), 1.2);
    private static readonly Pen AxisYPen = new(new SolidColorBrush(Color.FromRgb(78, 148, 100)), 1.2);
    private static readonly Pen BrushPen = new(new SolidColorBrush(Color.FromRgb(92, 178, 198)), 1.1);
    private static readonly Pen SelectedPen = new(new SolidColorBrush(Color.FromRgb(255, 202, 77)), 2.4);
    private static readonly Brush SelectFill = new SolidColorBrush(Color.FromArgb(33, 255, 193, 55));
    private static readonly Brush FloorFill = new SolidColorBrush(Color.FromArgb(22, 76, 153, 202));
    private static readonly Brush EntityFill = new SolidColorBrush(Color.FromRgb(235, 173, 74));

    public Radiant2DViewport()
    {
        ClipToBounds = true;
        Focusable = true;
        SnapsToDevicePixels = true;
        var menu = new ContextMenu();
        var box = new MenuItem { Header = "Create brush at cursor" };
        box.Click += (_, _) => CreateBox?.Invoke(_contextWorld);
        var spawn = new MenuItem { Header = "Create spawn at cursor" };
        spawn.Click += (_, _) => CreateSpawn?.Invoke(_contextWorld);
        menu.Items.Add(box);
        menu.Items.Add(spawn);
        ContextMenu = menu;
        SizeChanged += (_, _) => InvalidateVisual();
    }

    public void SetScene(IReadOnlyList<BrushGeometry> brushes, IReadOnlyList<EntityMarker> entities, int selected)
    {
        _brushes = brushes;
        _entities = entities;
        _selected = selected;
        InvalidateVisual();
    }

    public void SetSelected(int selected) { _selected = selected; InvalidateVisual(); }

    public void SetGrid(double size)
    {
        _grid = Math.Clamp(size, 1, 4096);
        InvalidateVisual();
    }

    private (double U, double V) Project(Point3D p) => Plane switch
    {
        ViewPlane.XY => (p.X, p.Y),
        ViewPlane.XZ => (p.X, p.Z),
        ViewPlane.YZ => (p.Y, p.Z),
        _ => (p.X, p.Y)
    };

    private Point Screen(double u, double v) => new(
        ActualWidth / 2 + _pan.X + u * _scale,
        ActualHeight / 2 + _pan.Y - v * _scale);

    private (double U, double V) World2D(Point screen) => (
        (screen.X - ActualWidth / 2 - _pan.X) / _scale,
        (ActualHeight / 2 + _pan.Y - screen.Y) / _scale);

    private Point3D World3D(Point screen)
    {
        var (u, v) = World2D(screen);
        return Plane switch
        {
            ViewPlane.XY => new Point3D(u, v, 0),
            ViewPlane.XZ => new Point3D(u, 0, v),
            ViewPlane.YZ => new Point3D(0, u, v),
            _ => new Point3D(u, v, 0)
        };
    }

    private static double Snap(double value, double grid) =>
        Math.Round(value / grid, MidpointRounding.AwayFromZero) * grid;

    public void FrameAll()
    {
        var all = _brushes.SelectMany(b => b.Points).Concat(_entities.Select(e => e.Location))
            .Select(Project).ToArray();
        if (all.Length == 0) { _pan = default; _scale = .45; InvalidateVisual(); return; }
        var loU = all.Min(p => p.U); var hiU = all.Max(p => p.U);
        var loV = all.Min(p => p.V); var hiV = all.Max(p => p.V);
        _scale = Math.Clamp(Math.Min(
            Math.Max(1, ActualWidth - 44) / Math.Max(64, hiU - loU),
            Math.Max(1, ActualHeight - 44) / Math.Max(64, hiV - loV)), .004, 12);
        _pan = new Vector(-(loU + hiU) * .5 * _scale, (loV + hiV) * .5 * _scale);
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        if (ActualWidth < 2 || ActualHeight < 2) return;
        dc.DrawRectangle(_background, null, new Rect(RenderSize));
        DrawGrid(dc);
        foreach (var (b, index) in _brushes.Select((b, index) => (b, index)))
        {
            var moving = _dragging && index == _dragIndex ? _dragDelta : default;
            var pen = index == _selected ? SelectedPen : BrushPen;
            // Each face uses the same vertices as the 3D editor and native map source.
            foreach (var face in b.Faces)
            {
                if (face.Length < 3) continue;
                var g = new StreamGeometry();
                using (var context = g.Open())
                {
                    var points = face.Select(idx => Project(b.Points[idx]))
                        .Select(p => Screen(p.U, p.V) + moving).ToArray();
                    context.BeginFigure(points[0], true, true);
                    context.PolyLineTo(points.Skip(1).ToArray(), true, true);
                }
                g.Freeze();
                dc.DrawGeometry(index == _selected ? SelectFill : FloorFill, pen, g);
            }
        }
        foreach (var entity in _entities)
        {
            var (u, v) = Project(entity.Location);
            var center = Screen(u, v);
            dc.DrawEllipse(EntityFill, null, center, 4.5, 4.5);
            dc.DrawLine(SelectedPen, new Point(center.X - 7, center.Y), new Point(center.X + 7, center.Y));
            dc.DrawLine(SelectedPen, new Point(center.X, center.Y - 7), new Point(center.X, center.Y + 7));
        }
        dc.DrawText(Text($"{Plane}   grid {_grid:0.#}   zoom {_scale:0.##} px/u", 11, Brushes.LightSteelBlue), new Point(7, 6));
    }

    private void DrawGrid(DrawingContext dc)
    {
        // Increase grid spacing when zoomed out to cap the number of rendered lines.
        var step = _grid;
        while (step * _scale < 12) step *= 2;
        var (loU, hiV) = World2D(new Point(0, 0));
        var (hiU, loV) = World2D(new Point(ActualWidth, ActualHeight));
        var startU = Math.Ceiling(Math.Min(loU, hiU) / step) * step;
        var startV = Math.Ceiling(Math.Min(loV, hiV) / step) * step;
        var verticalLineCount = 0;
        for (var u = startU; u <= Math.Max(loU, hiU) && verticalLineCount++ < 600; u += step)
        {
            var p = Screen(u, 0);
            dc.DrawLine(Math.Abs(u) < .0001 ? AxisXPen : Math.Abs(u / (step * 8) - Math.Round(u / (step * 8))) < .001 ? MajorPen : MinorPen,
                new Point(p.X, 0), new Point(p.X, ActualHeight));
        }
        var horizontalLineCount = 0;
        for (var v = startV; v <= Math.Max(loV, hiV) && horizontalLineCount++ < 600; v += step)
        {
            var p = Screen(0, v);
            dc.DrawLine(Math.Abs(v) < .0001 ? AxisYPen : Math.Abs(v / (step * 8) - Math.Round(v / (step * 8))) < .001 ? MajorPen : MinorPen,
                new Point(0, p.Y), new Point(ActualWidth, p.Y));
        }
    }

    private FormattedText Text(string value, double size, Brush foreground) => new(
        value, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
        new Typeface("Consolas"), size, foreground, VisualTreeHelper.GetDpi(this).PixelsPerDip);

    private int HitBrush(Point cursor)
    {
        // Choose the smallest visible projected brush under the pointer, so a large
        // floor does not prevent selecting cover or props sitting inside it.
        var best = -1; var bestArea = double.PositiveInfinity;
        for (var i = 0; i < _brushes.Count; ++i)
        {
            var points = _brushes[i].Points.Select(Project).Select(p => Screen(p.U, p.V)).ToArray();
            if (points.Length == 0) continue;
            var left = points.Min(p => p.X); var right = points.Max(p => p.X);
            var top = points.Min(p => p.Y); var bottom = points.Max(p => p.Y);
            if (cursor.X < left - 5 || cursor.X > right + 5 || cursor.Y < top - 5 || cursor.Y > bottom + 5)
                continue;
            var area = Math.Max(1, right - left) * Math.Max(1, bottom - top);
            if (area < bestArea) { best = i; bestArea = area; }
        }
        return best;
    }

    protected override void OnMouseDown(MouseButtonEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        _last = e.GetPosition(this);
        if (e.ChangedButton == MouseButton.Middle)
        {
            _panning = true; CaptureMouse(); e.Handled = true; return;
        }
        if (e.ChangedButton == MouseButton.Right)
        {
            _contextWorld = World3D(_last);
            // WPF handles opening the ContextMenu on right-click.
            return;
        }
        if (e.ChangedButton != MouseButton.Left) return;
        _dragIndex = HitBrush(_last);
        if (_dragIndex >= 0)
        {
            BrushSelected?.Invoke(_dragIndex);
            _dragStart = _last;
            _dragging = true;
            _dragDelta = default;
            CaptureMouse();
        }
        e.Handled = true;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var cursor = e.GetPosition(this);
        var pos = World3D(cursor);
        CursorChanged?.Invoke($"{Plane}  {pos.X:0.#}, {pos.Y:0.#}, {pos.Z:0.#}");
        if (_panning)
        {
            if (e.MiddleButton != MouseButtonState.Pressed) { _panning = false; ReleaseMouseCapture(); return; }
            _pan += cursor - _last;
            InvalidateVisual();
        }
        else if (_dragging)
        {
            if (e.LeftButton != MouseButtonState.Pressed) { _dragging = false; ReleaseMouseCapture(); return; }
            _dragDelta = cursor - _dragStart;
            InvalidateVisual();
        }
        _last = cursor;
    }

    protected override void OnMouseUp(MouseButtonEventArgs e)
    {
        base.OnMouseUp(e);
        if (e.ChangedButton == MouseButton.Middle && _panning)
        {
            _panning = false; ReleaseMouseCapture(); e.Handled = true;
        }
        if (e.ChangedButton == MouseButton.Left && _dragging)
        {
            _dragging = false; ReleaseMouseCapture();
            var moved = _dragDelta;
            _dragDelta = default;
            InvalidateVisual();
            if (moved.Length > 2 && _dragIndex >= 0)
            {
                var du = Snap(moved.X / _scale, _grid);
                var dv = Snap(-moved.Y / _scale, _grid);
                var d = Plane switch
                {
                    ViewPlane.XY => new Vector3D(du, dv, 0),
                    ViewPlane.XZ => new Vector3D(du, 0, dv),
                    ViewPlane.YZ => new Vector3D(0, du, dv),
                    _ => new Vector3D(du, dv, 0)
                };
                if (d.LengthSquared > 0) BrushMoved?.Invoke(_dragIndex, d);
            }
            e.Handled = true;
        }
    }

    protected override void OnMouseWheel(MouseWheelEventArgs e)
    {
        base.OnMouseWheel(e);
        var cursor = e.GetPosition(this);
        var world = World2D(cursor);
        _scale = Math.Clamp(_scale * Math.Pow(1.2, e.Delta / 120.0), .004, 20);
        // Zoom around the mouse position, like Radiant's orthographic editors.
        _pan = new Vector(cursor.X - ActualWidth / 2 - world.U * _scale,
                          cursor.Y - ActualHeight / 2 + world.V * _scale);
        InvalidateVisual();
        e.Handled = true;
    }
}
