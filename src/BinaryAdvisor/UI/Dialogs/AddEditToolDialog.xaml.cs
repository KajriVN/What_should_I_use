using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using BinaryAdvisor.Core;
using BinaryAdvisor.Models;
using Microsoft.Win32;

namespace BinaryAdvisor.UI.Dialogs;

public partial class AddEditToolDialog : Window
{
    private readonly bool _isEditMode;
    private readonly IReadOnlySet<string> _existingKeys;
    private string _selectedType = "gui";
    private int _triggerMode = 1; // 0 = Manual, 1 = Keyword/FileType, 2 = Always
    private int _selectedStep = 1;
    private int _selectedPriority = 2;
    private bool _userEditedKeyManually;

    public string ResultToolId { get; private set; } = string.Empty;
    public ToolEntry ResultToolEntry { get; private set; } = new();

    public AddEditToolDialog(
        IReadOnlySet<string> existingKeys,
        string? editToolId = null,
        ToolEntry? existingEntry = null)
    {
        InitializeComponent();
        _existingKeys = existingKeys;
        _isEditMode = !string.IsNullOrWhiteSpace(editToolId) && existingEntry is not null;

        if (_isEditMode && existingEntry is not null && editToolId is not null)
        {
            TxtDialogTitle.Text = $"✎ Chỉnh sửa Công cụ: {existingEntry.Name}";
            TxtToolId.Text = editToolId;
            TxtToolId.IsReadOnly = true;
            TxtToolId.Opacity = 0.7;
            _userEditedKeyManually = true;

            TxtToolName.Text = existingEntry.Name;
            TxtExecutable.Text = existingEntry.Executable;
            TxtArgs.Text = existingEntry.Args.Count > 0
                ? string.Join(" ", existingEntry.Args.Select(RuleEngine.QuoteArgumentIfNeeded))
                : "";

            SetToolType(existingEntry.IsGui ? "gui" : "cli");

            if (existingEntry.CustomRule is { Enabled: true } cr)
            {
                SetTriggerMode(cr.AlwaysRecommend ? 2 : 1);
                TxtKeywords.Text = string.Join(", ", cr.Keywords);
                TxtFileTypes.Text = string.Join(", ", cr.FileTypes);
                SetStep(cr.Step);
                SetPriority(cr.Priority);
                TxtReason.Text = cr.Reason;
                TxtWarning.Text = cr.Warning;
            }
            else
            {
                SetTriggerMode(0);
                SetStep(2);
                SetPriority(2);
            }
        }
        else
        {
            // Default for brand new custom tool: Keyword trigger enabled so user sees immediately how to auto-recommend!
            SetToolType("gui");
            SetTriggerMode(1);
            SetStep(1);
            SetPriority(2);
        }

        TxtToolId.KeyUp += (_, _) => _userEditedKeyManually = true;
        RefreshExeStatus();
    }

    private void SetToolType(string type)
    {
        _selectedType = type;
        BtnTypeGui.Style = (Style)FindResource(type == "gui" ? "AccentButtonStyle" : "SecondaryButtonStyle");
        BtnTypeCli.Style = (Style)FindResource(type == "cli" ? "PrimaryButtonStyle" : "SecondaryButtonStyle");
    }

    private void SetTriggerMode(int mode)
    {
        _triggerMode = mode;
        BtnModeManual.Style = (Style)FindResource(mode == 0 ? "AccentButtonStyle" : "SecondaryButtonStyle");
        BtnModeKeyword.Style = (Style)FindResource(mode == 1 ? "AccentButtonStyle" : "SecondaryButtonStyle");
        BtnModeAlways.Style = (Style)FindResource(mode == 2 ? "AccentButtonStyle" : "SecondaryButtonStyle");

        CustomRuleDetailsPanel.Visibility = mode == 0 ? Visibility.Collapsed : Visibility.Visible;
        KeywordFilterGrid.Visibility = mode == 1 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void SetStep(int step)
    {
        _selectedStep = Math.Clamp(step, 1, 3);
        BtnStep1.Style = (Style)FindResource(_selectedStep == 1 ? "AccentButtonStyle" : "SecondaryButtonStyle");
        BtnStep2.Style = (Style)FindResource(_selectedStep == 2 ? "AccentButtonStyle" : "SecondaryButtonStyle");
        BtnStep3.Style = (Style)FindResource(_selectedStep == 3 ? "AccentButtonStyle" : "SecondaryButtonStyle");
    }

    private void SetPriority(int priority)
    {
        _selectedPriority = Math.Clamp(priority, 1, 3);
        BtnPrio1.Style = (Style)FindResource(_selectedPriority == 1 ? "AccentButtonStyle" : "SecondaryButtonStyle");
        BtnPrio2.Style = (Style)FindResource(_selectedPriority == 2 ? "AccentButtonStyle" : "SecondaryButtonStyle");
        BtnPrio3.Style = (Style)FindResource(_selectedPriority == 3 ? "AccentButtonStyle" : "SecondaryButtonStyle");
    }

    private void RefreshExeStatus()
    {
        if (!IsLoaded && string.IsNullOrWhiteSpace(TxtExecutable.Text))
        {
            ExeStatusDot.Fill = new SolidColorBrush(Color.FromRgb(0x6E, 0x76, 0x81));
            TxtExeStatus.Text = "Chưa chọn tệp";
            TxtExeStatus.Foreground = (Brush)FindResource("TextMutedBrush");
            return;
        }

        string? resolved = ConfigManager.ResolveExecutablePath(TxtExecutable.Text);
        if (resolved is not null)
        {
            ExeStatusDot.Fill = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
            TxtExeStatus.Text = "Sẵn sàng";
            TxtExeStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
        }
        else
        {
            ExeStatusDot.Fill = new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x49));
            TxtExeStatus.Text = "Chưa tìm thấy tệp tại đường dẫn này";
            TxtExeStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x49));
        }
    }

    private void TxtToolName_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_isEditMode || _userEditedKeyManually)
            return;

        string slug = Regex.Replace(TxtToolName.Text.Trim().ToLowerInvariant(), @"[^a-z0-9]+", "_").Trim('_');
        TxtToolId.Text = slug;
    }

    private void TxtExecutable_TextChanged(object sender, TextChangedEventArgs e)
    {
        RefreshExeStatus();
    }

    private void BtnBrowseExe_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Chọn tệp thực thi của công cụ",
            Filter = "Tệp thực thi (*.exe;*.bat;*.cmd)|*.exe;*.bat;*.cmd|Tất cả tệp (*.*)|*.*"
        };

        if (dlg.ShowDialog(this) == true)
        {
            TxtExecutable.Text = dlg.FileName.Replace('\\', '/');
            if (string.IsNullOrWhiteSpace(TxtToolName.Text))
            {
                TxtToolName.Text = Path.GetFileNameWithoutExtension(dlg.FileName);
            }

            // Auto-hint CLI if executable name ends with .CLI or console conventions
            if (dlg.FileName.Contains(".CLI", StringComparison.OrdinalIgnoreCase) ||
                dlg.FileName.EndsWith("cmd.exe", StringComparison.OrdinalIgnoreCase))
            {
                SetToolType("cli");
            }
        }
    }

    private void BtnInsertPlaceholder_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string token })
            return;

        if (string.IsNullOrWhiteSpace(TxtArgs.Text))
            TxtArgs.Text = $"\"{token}\"";
        else
            TxtArgs.Text = $"{TxtArgs.Text.TrimEnd()} \"{token}\"";

        TxtArgs.Focus();
        TxtArgs.CaretIndex = TxtArgs.Text.Length;
    }

    private void BtnTypeGui_Click(object sender, RoutedEventArgs e) => SetToolType("gui");
    private void BtnTypeCli_Click(object sender, RoutedEventArgs e) => SetToolType("cli");

    private void BtnModeManual_Click(object sender, RoutedEventArgs e) => SetTriggerMode(0);
    private void BtnModeKeyword_Click(object sender, RoutedEventArgs e) => SetTriggerMode(1);
    private void BtnModeAlways_Click(object sender, RoutedEventArgs e) => SetTriggerMode(2);

    private void BtnStep1_Click(object sender, RoutedEventArgs e) => SetStep(1);
    private void BtnStep2_Click(object sender, RoutedEventArgs e) => SetStep(2);
    private void BtnStep3_Click(object sender, RoutedEventArgs e) => SetStep(3);

    private void BtnPrio1_Click(object sender, RoutedEventArgs e) => SetPriority(1);
    private void BtnPrio2_Click(object sender, RoutedEventArgs e) => SetPriority(2);
    private void BtnPrio3_Click(object sender, RoutedEventArgs e) => SetPriority(3);

    private void BtnSave_Click(object sender, RoutedEventArgs e)
    {
        string name = TxtToolName.Text.Trim();
        string key = TxtToolId.Text.Trim();

        if (string.IsNullOrWhiteSpace(name))
        {
            MessageBox.Show(this, "Vui lòng nhập Tên hiển thị cho công cụ.", "Thiếu thông tin", MessageBoxButton.OK, MessageBoxImage.Warning);
            TxtToolName.Focus();
            return;
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            key = $"custom_{Guid.NewGuid().ToString("N")[..6]}";
        }

        if (!_isEditMode && _existingKeys.Contains(key))
        {
            MessageBox.Show(
                this,
                $"Mã định danh '{key}' đã tồn tại trong danh sách công cụ. Vui lòng đặt mã khác.",
                "Trùng mã công cụ",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            TxtToolId.Focus();
            return;
        }

        List<string> keywords = SplitCommaSeparated(TxtKeywords.Text);
        List<string> fileTypes = SplitCommaSeparated(TxtFileTypes.Text);

        if (_triggerMode == 1 && keywords.Count == 0 && fileTypes.Count == 0)
        {
            MessageBox.Show(
                this,
                "Bạn đang chọn chế độ 'Tự gợi ý khi khớp Từ khóa / Định dạng' nhưng chưa nhập Từ khóa hoặc Định dạng nào.\n\nHãy nhập ít nhất 1 từ khóa (ví dụ: .NET Reactor, UPX) hoặc chuyển sang chế độ 'Chỉ mở thủ công' / 'Luôn gợi ý'.",
                "Thiếu điều kiện kích hoạt",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            TxtKeywords.Focus();
            return;
        }

        CustomToolRule? customRule = _triggerMode == 0
            ? null
            : new CustomToolRule
            {
                Enabled = true,
                AlwaysRecommend = _triggerMode == 2,
                Keywords = _triggerMode == 1 ? keywords : new List<string>(),
                FileTypes = _triggerMode == 1 ? fileTypes : new List<string>(),
                Step = _selectedStep,
                Priority = _selectedPriority,
                Reason = TxtReason.Text.Trim(),
                Warning = TxtWarning.Text.Trim()
            };

        ResultToolId = key;
        ResultToolEntry = new ToolEntry
        {
            Name = name,
            Type = _selectedType,
            Executable = TxtExecutable.Text.Trim(),
            Args = ToolLauncher.SplitCommandLine(TxtArgs.Text),
            CustomRule = customRule
        };

        DialogResult = true;
        Close();
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private static List<string> SplitCommaSeparated(string raw) =>
        raw.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
           .Where(s => !string.IsNullOrWhiteSpace(s))
           .Distinct(StringComparer.OrdinalIgnoreCase)
           .ToList();
}
