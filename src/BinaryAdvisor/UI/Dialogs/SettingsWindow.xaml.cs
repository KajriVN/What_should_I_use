using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using BinaryAdvisor.Core;
using BinaryAdvisor.Models;
using Microsoft.Win32;

namespace BinaryAdvisor.UI.Dialogs;

public partial class SettingsWindow : Window
{
    private readonly ToolsConfig _workingConfig;
    private readonly List<ToolRowControls> _rows = new();

    private sealed class ToolRowControls
    {
        public required Border Container { get; init; }
        public required TextBox KeyBox { get; init; }
        public required TextBox NameBox { get; init; }
        public required TextBlock RuleTag { get; init; }
        public required Button TypeToggleBtn { get; init; }
        public required TextBox ExeBox { get; init; }
        public required TextBox ArgsBox { get; init; }
        public required Ellipse StatusDot { get; init; }
        public string CurrentType { get; set; } = "gui";
        public CustomToolRule? CustomRule { get; set; }
    }

    public ToolsConfig SavedConfig => _workingConfig;

    public SettingsWindow(ToolsConfig currentConfig)
    {
        InitializeComponent();

        // Clone so Cancel discards unsaved edits
        _workingConfig = new ToolsConfig
        {
            DiecPath = currentConfig.DiecPath,
            Tools = currentConfig.Tools.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.Clone(),
                StringComparer.OrdinalIgnoreCase)
        };

        TxtConfigFileHint.Text = $"Tệp lưu trữ: {ConfigManager.GetToolsConfigPath()}";
        TxtDiecPath.Text = _workingConfig.DiecPath;
        RefreshDiecStatus();
        RebuildToolRows();
    }

    private void RebuildToolRows()
    {
        ToolsRowsPanel.Children.Clear();
        _rows.Clear();

        foreach (var (toolId, entry) in _workingConfig.Tools)
        {
            AddRowControl(toolId, entry, isCustomNew: false);
        }

        UpdateReadyCounter();
    }

    private void AddRowControl(string toolId, ToolEntry entry, bool isCustomNew)
    {
        var rowBorder = new Border
        {
            Background = (Brush)FindResource("BgCardBrush"),
            BorderBrush = (Brush)FindResource("BorderSubtleBrush"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(8, 7, 8, 7),
            Margin = new Thickness(0, 0, 0, 6)
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(26) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(175) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(66) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(215) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(158) });

        var dot = new Ellipse
        {
            Width = 10,
            Height = 10,
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Center
        };
        Grid.SetColumn(dot, 0);

        // Name + Key stacked compactly
        var nameStack = new StackPanel { Margin = new Thickness(0, 0, 8, 0) };
        var nameBox = new TextBox
        {
            Text = entry.Name,
            Style = (Style)FindResource("DarkTextBoxStyle"),
            FontWeight = FontWeights.SemiBold,
            Padding = new Thickness(6, 3, 6, 3)
        };

        var subKeyWrap = new WrapPanel { Margin = new Thickness(2, 2, 0, 0) };
        var keyBox = new TextBox
        {
            Text = toolId,
            IsReadOnly = !isCustomNew,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Foreground = (Brush)FindResource("TextMutedBrush"),
            FontFamily = (FontFamily)FindResource("MonoFont"),
            FontSize = 10.5,
            ToolTip = $"Key liên kết: {toolId}"
        };
        var ruleTag = new TextBlock
        {
            Text = " • 🎯 Tự gợi ý",
            FontSize = 10,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0xA6, 0x57)),
            VerticalAlignment = VerticalAlignment.Center,
            Visibility = entry.CustomRule?.Enabled == true ? Visibility.Visible : Visibility.Collapsed
        };
        subKeyWrap.Children.Add(keyBox);
        subKeyWrap.Children.Add(ruleTag);

        nameStack.Children.Add(nameBox);
        nameStack.Children.Add(subKeyWrap);
        Grid.SetColumn(nameStack, 1);

        // Type Toggle Button (GUI / CLI)
        string initialType = entry.IsGui ? "gui" : "cli";
        var typeBtn = new Button
        {
            Style = (Style)FindResource("SecondaryButtonStyle"),
            Margin = new Thickness(0, 0, 8, 0),
            Padding = new Thickness(6, 4, 6, 4),
            VerticalAlignment = VerticalAlignment.Top,
            ToolTip = "Bấm để chuyển đổi giữa GUI (mở cửa sổ phần mềm) và CLI (chạy dòng lệnh ngầm)"
        };
        ApplyTypeButtonAppearance(typeBtn, initialType);
        Grid.SetColumn(typeBtn, 2);

        var exeBox = new TextBox
        {
            Text = entry.Executable,
            Style = (Style)FindResource("DarkTextBoxStyle"),
            FontFamily = (FontFamily)FindResource("MonoFont"),
            FontSize = 11.5,
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 0, 8, 0)
        };
        Grid.SetColumn(exeBox, 3);

        string formattedArgs = string.Join(" ", entry.Args.Select(RuleEngine.QuoteArgumentIfNeeded));
        var argsBox = new TextBox
        {
            Text = formattedArgs,
            Style = (Style)FindResource("DarkTextBoxStyle"),
            FontFamily = (FontFamily)FindResource("MonoFont"),
            FontSize = 11.5,
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 0, 8, 0),
            ToolTip = "Hỗ trợ biến giữ chỗ: {file}, {file_dir}, {file_name}, {file_stem}, {file_ext}"
        };
        Grid.SetColumn(argsBox, 4);

        var btnPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Top,
            HorizontalAlignment = HorizontalAlignment.Right
        };

        var browseBtn = new Button
        {
            Content = "Browse",
            Style = (Style)FindResource("SecondaryButtonStyle"),
            Padding = new Thickness(8, 4, 8, 4),
            Margin = new Thickness(0, 0, 4, 0),
            ToolTip = "Chọn tệp .exe / .bat"
        };

        var editRuleBtn = new Button
        {
            Content = "✎",
            Style = (Style)FindResource("SecondaryButtonStyle"),
            Padding = new Thickness(8, 4, 8, 4),
            Margin = new Thickness(0, 0, 4, 0),
            ToolTip = "Cấu hình chi tiết & Quy tắc tự động gợi ý cho công cụ này"
        };

        var removeBtn = new Button
        {
            Content = "✕",
            Style = (Style)FindResource("SecondaryButtonStyle"),
            Padding = new Thickness(8, 4, 8, 4),
            ToolTip = "Xóa công cụ này khỏi danh sách"
        };

        btnPanel.Children.Add(browseBtn);
        btnPanel.Children.Add(editRuleBtn);
        btnPanel.Children.Add(removeBtn);
        Grid.SetColumn(btnPanel, 5);

        grid.Children.Add(dot);
        grid.Children.Add(nameStack);
        grid.Children.Add(typeBtn);
        grid.Children.Add(exeBox);
        grid.Children.Add(argsBox);
        grid.Children.Add(btnPanel);
        rowBorder.Child = grid;

        var rowModel = new ToolRowControls
        {
            Container = rowBorder,
            KeyBox = keyBox,
            NameBox = nameBox,
            RuleTag = ruleTag,
            TypeToggleBtn = typeBtn,
            ExeBox = exeBox,
            ArgsBox = argsBox,
            StatusDot = dot,
            CurrentType = initialType,
            CustomRule = entry.CustomRule?.Clone()
        };

        editRuleBtn.Click += (_, _) =>
        {
            var currentSnapshot = new ToolEntry
            {
                Name = rowModel.NameBox.Text.Trim(),
                Type = rowModel.CurrentType,
                Executable = rowModel.ExeBox.Text.Trim(),
                Args = ToolLauncher.SplitCommandLine(rowModel.ArgsBox.Text),
                CustomRule = rowModel.CustomRule?.Clone()
            };

            var existingSet = _rows.Select(r => r.KeyBox.Text.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var editDlg = new AddEditToolDialog(existingSet, rowModel.KeyBox.Text.Trim(), currentSnapshot) { Owner = this };
            if (editDlg.ShowDialog() == true)
            {
                ToolEntry updated = editDlg.ResultToolEntry;
                rowModel.NameBox.Text = updated.Name;
                rowModel.CurrentType = updated.Type;
                ApplyTypeButtonAppearance(rowModel.TypeToggleBtn, updated.Type);
                rowModel.ExeBox.Text = updated.Executable;
                rowModel.ArgsBox.Text = string.Join(" ", updated.Args.Select(RuleEngine.QuoteArgumentIfNeeded));
                rowModel.CustomRule = updated.CustomRule?.Clone();
                rowModel.RuleTag.Visibility = rowModel.CustomRule?.Enabled == true ? Visibility.Visible : Visibility.Collapsed;
                RefreshRowStatusDot(rowModel);
                UpdateReadyCounter();
            }
        };

        typeBtn.Click += (_, _) =>
        {
            rowModel.CurrentType = rowModel.CurrentType == "gui" ? "cli" : "gui";
            ApplyTypeButtonAppearance(typeBtn, rowModel.CurrentType);
        };

        exeBox.TextChanged += (_, _) =>
        {
            RefreshRowStatusDot(rowModel);
            UpdateReadyCounter();
        };

        browseBtn.Click += (_, _) =>
        {
            var dlg = new OpenFileDialog
            {
                Title = $"Chọn tệp thực thi cho {nameBox.Text}",
                Filter = "Tệp thực thi (*.exe;*.bat;*.cmd)|*.exe;*.bat;*.cmd|Tất cả tệp (*.*)|*.*"
            };
            if (dlg.ShowDialog(this) == true)
            {
                exeBox.Text = dlg.FileName.Replace('\\', '/');
            }
        };

        removeBtn.Click += (_, _) =>
        {
            ToolsRowsPanel.Children.Remove(rowBorder);
            _rows.Remove(rowModel);
            UpdateReadyCounter();
        };

        RefreshRowStatusDot(rowModel);
        _rows.Add(rowModel);
        ToolsRowsPanel.Children.Add(rowBorder);

        if (isCustomNew)
            nameBox.Focus();
    }

    private static void ApplyTypeButtonAppearance(Button btn, string type)
    {
        if (string.Equals(type, "gui", StringComparison.OrdinalIgnoreCase))
        {
            btn.Content = "GUI";
            btn.Foreground = new SolidColorBrush(Color.FromRgb(0x58, 0xA6, 0xFF));
        }
        else
        {
            btn.Content = "CLI";
            btn.Foreground = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
        }
    }

    private static void RefreshRowStatusDot(ToolRowControls row)
    {
        string? resolved = ConfigManager.ResolveExecutablePath(row.ExeBox.Text);
        if (resolved is not null)
        {
            row.StatusDot.Fill = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
            row.StatusDot.ToolTip = $"Sẵn sàng: {resolved}";
        }
        else
        {
            row.StatusDot.Fill = new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x49));
            row.StatusDot.ToolTip = "Chưa tìm thấy tệp thực thi tại đường dẫn này";
        }
    }

    private void RefreshDiecStatus()
    {
        string? resolved = ConfigManager.ResolveExecutablePath(TxtDiecPath.Text);
        if (resolved is not null)
        {
            DiecStatusDot.Fill = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
            TxtDiecStatus.Text = $"● Đã sẵn sàng ({resolved})";
            TxtDiecStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
        }
        else
        {
            DiecStatusDot.Fill = new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x49));
            TxtDiecStatus.Text = "● Chưa tìm thấy diec.exe (Ứng dụng sẽ dùng bộ quét PE/ELF nội bộ cho tới khi cấu hình)";
            TxtDiecStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x49));
        }
    }

    private void UpdateReadyCounter()
    {
        int ready = _rows.Count(r => ConfigManager.IsExecutableAvailable(r.ExeBox.Text));
        TxtReadyCounter.Text = $"Sẵn sàng: {ready} / {_rows.Count}";
    }

    private void TxtDiecPath_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded)
            return;
        RefreshDiecStatus();
    }

    private void BtnBrowseDiec_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Chọn tệp thực thi Detect It Easy CLI (diec.exe)",
            Filter = "Detect It Easy CLI (diec.exe)|diec.exe|Tệp thực thi (*.exe)|*.exe"
        };

        if (dlg.ShowDialog(this) == true)
        {
            TxtDiecPath.Text = dlg.FileName.Replace('\\', '/');
            RefreshDiecStatus();
        }
    }

    private async void BtnTestDiec_Click(object sender, RoutedEventArgs e)
    {
        string? resolved = ConfigManager.ResolveExecutablePath(TxtDiecPath.Text);
        if (resolved is null)
        {
            MessageBox.Show(
                this,
                "Không tìm thấy tệp diec.exe tại đường dẫn đã nhập.\nHãy bấm 'Browse...' để trỏ tới thư mục chứa diec.exe (bản Detect It Easy Portable).",
                "Chưa tìm thấy diec.exe",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = resolved,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            psi.ArgumentList.Add("--version");

            using var proc = Process.Start(psi);
            if (proc is not null)
            {
                string stdout = await proc.StandardOutput.ReadToEndAsync();
                string stderr = await proc.StandardError.ReadToEndAsync();
                await proc.WaitForExitAsync();

                string info = !string.IsNullOrWhiteSpace(stdout) ? stdout.Trim() : stderr.Trim();
                MessageBox.Show(
                    this,
                    $"Kết nối thành công tới diec.exe!\n\nĐường dẫn: {resolved}\nPhản hồi: {(string.IsNullOrWhiteSpace(info) ? "OK" : info)}",
                    "Kiểm tra diec.exe thành công",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                $"Lỗi khi chạy thử diec.exe:\n{ex.Message}",
                "Lỗi thực thi",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void BtnAutoDetect_Click(object sender, RoutedEventArgs e)
    {
        SyncUiIntoWorkingConfig();
        int detected = ConfigManager.AutoDetectInstalledTools(_workingConfig);

        TxtDiecPath.Text = _workingConfig.DiecPath;
        RefreshDiecStatus();
        RebuildToolRows();

        MessageBox.Show(
            this,
            detected > 0
                ? $"Đã tự động phát hiện và cập nhật đường dẫn cho {detected} công cụ trên máy!"
                : "Không tìm thấy thêm công cụ mới nào trong PATH hoặc các thư mục mặc định (C:\\Tools, Program Files, Scoop, WinGet). Bạn có thể bấm 'Browse' ở từng dòng để chọn thủ công.",
            "Tự động dò công cụ",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void BtnAddTool_Click(object sender, RoutedEventArgs e)
    {
        var existingSet = _rows.Select(r => r.KeyBox.Text.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var addDlg = new AddEditToolDialog(existingSet) { Owner = this };
        if (addDlg.ShowDialog() == true)
        {
            AddRowControl(addDlg.ResultToolId, addDlg.ResultToolEntry, isCustomNew: false);
            UpdateReadyCounter();
            ToolsScrollViewer.ScrollToEnd();
        }
    }

    private void SyncUiIntoWorkingConfig()
    {
        _workingConfig.DiecPath = TxtDiecPath.Text.Trim();
        var updatedTools = new Dictionary<string, ToolEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (ToolRowControls row in _rows)
        {
            string key = row.KeyBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(key))
                continue;

            List<string> parsedArgs = ToolLauncher.SplitCommandLine(row.ArgsBox.Text);

            updatedTools[key] = new ToolEntry
            {
                Name = string.IsNullOrWhiteSpace(row.NameBox.Text) ? key : row.NameBox.Text.Trim(),
                Type = row.CurrentType,
                Executable = row.ExeBox.Text.Trim(),
                Args = parsedArgs,
                CustomRule = row.CustomRule?.Clone()
            };
        }

        _workingConfig.Tools = updatedTools;
    }

    private void BtnSave_Click(object sender, RoutedEventArgs e)
    {
        SyncUiIntoWorkingConfig();
        ConfigManager.SaveToolsConfig(_workingConfig);
        DialogResult = true;
        Close();
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
