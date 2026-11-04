using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using BinaryAdvisor.Core;
using BinaryAdvisor.Models;
using BinaryAdvisor.UI.Controls;
using BinaryAdvisor.UI.Dialogs;
using Microsoft.Win32;

namespace BinaryAdvisor;

public partial class MainWindow : Window
{
    private readonly Scanner _scanner = new();
    private readonly ToolLauncher _launcher = new();
    private ToolsConfig _toolsConfig;
    private RuleEngine _ruleEngine;

    private ScanResult? _currentScan;
    private ToolRecommendationCard? _selectedCard;
    private CancellationTokenSource? _scanCts;
    private CancellationTokenSource? _cliCts;

    public MainWindow()
    {
        InitializeComponent();
        _toolsConfig = ConfigManager.LoadToolsConfig();
        _ruleEngine = RuleEngine.LoadFromFile();
        RefreshTopDiecBadge();
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        // Support dragging a file onto BinaryAdvisor.exe or passing file path via CLI
        string[] cmdArgs = Environment.GetCommandLineArgs();
        if (cmdArgs.Length > 1 && File.Exists(cmdArgs[1]))
        {
            await AnalyzeTargetFileAsync(cmdArgs[1]);
        }
    }

    private void RefreshTopDiecBadge()
    {
        string? resolved = ConfigManager.ResolveExecutablePath(_toolsConfig.DiecPath);
        if (resolved is not null)
        {
            TopDiecDot.Fill = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
            TxtTopDiecState.Text = "diec.exe: Sẵn sàng";
            TxtTopDiecState.Foreground = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
            DiecStatusPill.ToolTip = $"Đang dùng Detect It Easy CLI: {resolved}\n(Bấm để mở Settings)";
        }
        else
        {
            TopDiecDot.Fill = new SolidColorBrush(Color.FromRgb(0xD2, 0x99, 0x22));
            TxtTopDiecState.Text = "diec.exe: Chế độ Nội bộ (Cấu hình ⚙)";
            TxtTopDiecState.Foreground = new SolidColorBrush(Color.FromRgb(0xE3, 0xB3, 0x41));
            DiecStatusPill.ToolTip = "Chưa trỏ đường dẫn diec.exe — Ứng dụng đang dùng bộ phân tích PE/ELF & Entropy nội bộ.\nBấm vào đây để chọn đường dẫn diec.exe.";
        }
    }

    // =====================================================================
    // DRAG & DROP HANDLERS
    // =====================================================================
    private void Window_PreviewDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
            DragOverlay.Visibility = Visibility.Visible;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
        e.Handled = true;
    }

    private void Window_DragLeave(object sender, DragEventArgs e)
    {
        DragOverlay.Visibility = Visibility.Collapsed;
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        DragOverlay.Visibility = Visibility.Collapsed;
        if (!e.Data.GetDataPresent(DataFormats.FileDrop))
            return;

        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
        {
            string target = files[0];
            if (File.Exists(target))
            {
                await AnalyzeTargetFileAsync(target);
            }
            else if (Directory.Exists(target))
            {
                AppendLog($"[!] '{target}' là một thư mục. Vui lòng kéo thả một tệp thực thi cụ thể (.exe, .dll, ELF...).");
            }
        }
    }

    // =====================================================================
    // TOP BAR ACTIONS
    // =====================================================================
    private async void BtnBrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Chọn tệp nhị phân cần phân tích",
            Filter = "Tệp thực thi & Gói cài đặt (*.exe;*.dll;*.sys;*.ocx;*.scr;*.msi;*.elf;*.so;*.bin)|*.exe;*.dll;*.sys;*.ocx;*.scr;*.msi;*.elf;*.so;*.bin|Tất cả tệp (*.*)|*.*"
        };

        if (dlg.ShowDialog(this) == true)
        {
            await AnalyzeTargetFileAsync(dlg.FileName);
        }
    }

    private async void BtnRescan_Click(object sender, RoutedEventArgs e)
    {
        if (_currentScan is not null && File.Exists(_currentScan.File.FullPath))
        {
            _ruleEngine = RuleEngine.LoadFromFile();
            await AnalyzeTargetFileAsync(_currentScan.File.FullPath);
        }
    }

    private void BtnOpenSettings_Click(object sender, RoutedEventArgs e) => OpenSettingsDialog();

    private void DiecStatusPill_Click(object sender, MouseButtonEventArgs e) => OpenSettingsDialog();

    private async void OpenSettingsDialog()
    {
        var dlg = new SettingsWindow(_toolsConfig) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            _toolsConfig = dlg.SavedConfig;
            RefreshTopDiecBadge();
            AppendLog("[⚙] Đã cập nhật cấu hình đường dẫn công cụ (tools_config.json).");

            // Re-evaluate or re-scan automatically if a file is already loaded
            if (_currentScan is not null && File.Exists(_currentScan.File.FullPath))
            {
                await AnalyzeTargetFileAsync(_currentScan.File.FullPath);
            }
        }
    }

    private void BtnCancelScan_Click(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    // =====================================================================
    // BACKGROUND SCANNING & EVALUATION PIPELINE
    // =====================================================================
    public async Task AnalyzeTargetFileAsync(string filePath)
    {
        // Cancel any previous in-flight scan
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();
        CancellationToken token = _scanCts.Token;

        ScanLoadingBar.Visibility = Visibility.Visible;
        TxtScanProgressStatus.Text = $"Đang chuẩn bị quét '{Path.GetFileName(filePath)}'...";

        var progress = new Progress<string>(msg =>
        {
            Dispatcher.InvokeAsync(() => TxtScanProgressStatus.Text = msg);
        });

        try
        {
            AppendLog($"[+] Bắt đầu phân tích tệp: {filePath}");

            ScanResult scanResult = await _scanner.ScanFileAsync(
                filePath,
                _toolsConfig.DiecPath,
                progress,
                token);

            AnalysisPlan plan = await Task.Run(() => _ruleEngine.Evaluate(scanResult, _toolsConfig), token);

            _currentScan = scanResult;
            BtnRescan.IsEnabled = true;

            RenderFileMetadata(scanResult);
            RenderDieTreeAndEntropy(scanResult);
            RenderWorkflowPlan(plan);

            AppendLog($"[✔] Hoàn tất quét '{scanResult.File.FileName}' ({scanResult.File.FileType}) trong {scanResult.ScanDuration.TotalMilliseconds:F0} ms — Entropy tổng: {scanResult.TotalEntropy:F2}/8.00 — Đề xuất {plan.Cards.Count} công cụ.");
        }
        catch (OperationCanceledException)
        {
            AppendLog("[!] Đã hủy quá trình quét tệp.");
        }
        catch (Exception ex)
        {
            AppendLog($"[✘] Lỗi khi phân tích tệp: {ex.Message}");
            MessageBox.Show(
                this,
                $"Không thể phân tích tệp:\n{ex.Message}",
                "Lỗi quét tệp",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            ScanLoadingBar.Visibility = Visibility.Collapsed;
        }
    }

    // =====================================================================
    // UI RENDERING: VÙNG 1, VÙNG 2, VÙNG 3
    // =====================================================================
    private void RenderFileMetadata(ScanResult scan)
    {
        EmptyDropPrompt.Visibility = Visibility.Collapsed;
        FileMetadataPanel.Visibility = Visibility.Visible;

        TxtFileFormatBadge.Text = scan.File.FileType;
        TxtFileName.Text = scan.File.FileName;
        TxtFileSize.Text = scan.File.FormattedSize;
        TxtScanTime.Text = $"• Quét trong {scan.ScanDuration.TotalMilliseconds:F0} ms";
        TxtFileFullPath.Text = scan.File.FullPath;
        TxtFileFullPath.ToolTip = scan.File.FullPath;
        TxtMd5.Text = scan.File.Md5;
        TxtMd5.ToolTip = scan.File.Md5;
        TxtSha256.Text = scan.File.Sha256;
        TxtSha256.ToolTip = scan.File.Sha256;
    }

    private void RenderDieTreeAndEntropy(ScanResult scan)
    {
        // Notice banner if using Native Inspector fallback
        if (!string.IsNullOrWhiteSpace(scan.ScannerNotice))
        {
            ScannerNoticeBox.Visibility = Visibility.Visible;
            TxtScannerNotice.Text = scan.ScannerNotice;
        }
        else
        {
            ScannerNoticeBox.Visibility = Visibility.Collapsed;
        }

        TxtDetectSourceBadge.Text = scan.UsedNativeFallback ? "Nguồn: Native Inspector" : "Nguồn: diec.exe";

        // Populate DIE TreeView
        DieTreeView.Items.Clear();
        if (scan.DetectionGroups.Count == 0)
        {
            DieTreeView.Items.Add(new TreeViewItem
            {
                Header = "Không phát hiện chữ ký trình biên dịch/đóng gói cụ thể",
                Foreground = (Brush)FindResource("TextMutedBrush")
            });
        }
        else
        {
            foreach (DieDetectionGroup group in scan.DetectionGroups)
            {
                var rootNode = new TreeViewItem
                {
                    Header = $"📦 {group.HeaderDisplay}",
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x79, 0xC0, 0xFF)),
                    IsExpanded = true
                };

                foreach (var byCategory in group.Items.GroupBy(i => i.Type))
                {
                    var catNode = new TreeViewItem
                    {
                        Header = $"{GetCategoryIcon(byCategory.Key)} {byCategory.Key} ({byCategory.Count()})",
                        FontWeight = FontWeights.SemiBold,
                        Foreground = GetCategoryBrush(byCategory.Key),
                        IsExpanded = true
                    };

                    foreach (DieDetectionItem item in byCategory)
                    {
                        var leaf = new TreeViewItem
                        {
                            Header = item.DisplayLabel,
                            FontWeight = FontWeights.Normal,
                            Foreground = (Brush)FindResource("TextPrimaryBrush"),
                            ToolTip = string.IsNullOrWhiteSpace(item.RawString) ? item.DisplayLabel : item.RawString
                        };
                        catNode.Items.Add(leaf);
                    }

                    rootNode.Items.Add(catNode);
                }

                DieTreeView.Items.Add(rootNode);
            }
        }

        // Populate Overall & Section Entropy
        TxtTotalEntropy.Text = $"{scan.TotalEntropy:F2} / 8.00";
        BarTotalEntropy.Value = Math.Clamp(scan.TotalEntropy, 0.0, 8.0);
        BarTotalEntropy.Foreground = GetEntropyBrush(scan.TotalEntropy, false);
        TxtTotalEntropy.Foreground = GetEntropyBrush(scan.TotalEntropy, false);

        bool anyWarning = scan.TotalEntropy > 7.2 ||
                          scan.Sections.Any(s => s.IsWarning) ||
                          (scan.OverallPackStatus.Contains("packed", StringComparison.OrdinalIgnoreCase) &&
                           !scan.OverallPackStatus.Contains("not packed", StringComparison.OrdinalIgnoreCase));

        if (anyWarning)
        {
            PackStatusBadge.Background = new SolidColorBrush(Color.FromRgb(0x49, 0x16, 0x19));
            TxtPackStatus.Text = "⚠ PACKED / HIGH ENTROPY";
            TxtPackStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x7B, 0x72));
        }
        else
        {
            PackStatusBadge.Background = new SolidColorBrush(Color.FromRgb(0x16, 0x36, 0x22));
            TxtPackStatus.Text = "✔ NOT PACKED";
            TxtPackStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
        }

        SectionsEntropyPanel.Children.Clear();
        foreach (SectionEntropy sec in scan.Sections)
        {
            SectionsEntropyPanel.Children.Add(BuildSectionEntropyRow(sec));
        }
    }

    private UIElement BuildSectionEntropyRow(SectionEntropy sec)
    {
        Brush barBrush = GetEntropyBrush(sec.Entropy, sec.IsPackedStatus);

        var border = new Border
        {
            Background = sec.IsWarning
                ? new SolidColorBrush(Color.FromRgb(0x28, 0x14, 0x17))
                : new SolidColorBrush(Color.FromRgb(0x12, 0x16, 0x1D)),
            BorderBrush = sec.IsWarning
                ? new SolidColorBrush(Color.FromRgb(0x8E, 0x2A, 0x2F))
                : new SolidColorBrush(Color.FromRgb(0x26, 0x2C, 0x36)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(9, 6, 9, 6),
            Margin = new Thickness(0, 0, 0, 6),
            ToolTip = $"Offset: 0x{sec.Offset:X8} • Kích thước: {sec.SizeFormatted} • Trạng thái: {sec.Status}"
        };

        var stack = new StackPanel();
        var headerGrid = new Grid { Margin = new Thickness(0, 0, 0, 4) };
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var leftWrap = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
        leftWrap.Children.Add(new TextBlock
        {
            Text = sec.Name,
            FontFamily = (FontFamily)FindResource("MonoFont"),
            FontSize = 12,
            FontWeight = FontWeights.Bold,
            Foreground = (Brush)FindResource("TextPrimaryBrush"),
            Margin = new Thickness(0, 0, 8, 0)
        });
        leftWrap.Children.Add(new TextBlock
        {
            Text = $"({FileMetadata.FormatBytes(sec.Size).Split('(')[0].Trim()})",
            FontSize = 11,
            Foreground = (Brush)FindResource("TextMutedBrush"),
            VerticalAlignment = VerticalAlignment.Center
        });

        if (sec.IsWarning)
        {
            var warnTag = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x58, 0x19, 0x1C)),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(5, 1, 5, 1),
                Margin = new Thickness(6, 0, 0, 0)
            };
            warnTag.Child = new TextBlock
            {
                Text = sec.IsHighEntropy ? "⚠ > 7.2" : "PACKED",
                FontSize = 9.5,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x7B, 0x72))
            };
            leftWrap.Children.Add(warnTag);
        }

        var valTxt = new TextBlock
        {
            Text = $"{sec.Entropy:F2}",
            FontFamily = (FontFamily)FindResource("MonoFont"),
            FontSize = 12,
            FontWeight = FontWeights.Bold,
            Foreground = barBrush
        };
        Grid.SetColumn(valTxt, 1);

        headerGrid.Children.Add(leftWrap);
        headerGrid.Children.Add(valTxt);

        var bar = new ProgressBar
        {
            Minimum = 0,
            Maximum = 8,
            Value = Math.Clamp(sec.Entropy, 0.0, 8.0),
            Height = 6,
            Background = new SolidColorBrush(Color.FromRgb(0x21, 0x26, 0x2D)),
            Foreground = barBrush,
            BorderThickness = new Thickness(0)
        };

        stack.Children.Add(headerGrid);
        stack.Children.Add(bar);
        border.Child = stack;
        return border;
    }

    private void RenderWorkflowPlan(AnalysisPlan plan)
    {
        WelcomePlaceholder.Visibility = Visibility.Collapsed;
        StepsPipelinePanel.Visibility = Visibility.Visible;

        if (plan.IsSuspectedCustomPacker)
        {
            HeuristicAlertBanner.Visibility = Visibility.Visible;
            TxtHeuristicTitle.Text = $"🚨 {plan.HeuristicAlertTitle}";
            TxtHeuristicDetails.Text = plan.HeuristicAlertDetails;
        }
        else
        {
            HeuristicAlertBanner.Visibility = Visibility.Collapsed;
        }

        StrategySummaryBox.Visibility = Visibility.Visible;
        TxtStrategySummary.Text = $"💡 Chiến lược đề xuất: {plan.PrimaryStrategySummary}";

        TxtMatchedRulesCount.Text = plan.MatchedRules.Count > 0
            ? $"Khớp {plan.MatchedRules.Count} quy tắc • {plan.Cards.Count} công cụ gợi ý"
            : $"Chế độ mặc định/Heuristic • {plan.Cards.Count} công cụ gợi ý";

        PopulateStepHost(Step1CardsHost, plan.Step1Cards, "✔ Không phát hiện gói cài đặt hoặc trình nén cần bung trước — bạn có thể bắt đầu ngay từ Bước 2 (Phân tích tĩnh).");
        PopulateStepHost(Step2CardsHost, plan.Step2Cards, "Không có công cụ phân tích tĩnh riêng biệt nào cho bước này.");
        PopulateStepHost(Step3CardsHost, plan.Step3Cards, "Không yêu cầu trình gỡ lỗi động chuyên biệt (hoặc tệp không thực thi trực tiếp trên Windows).");

        // Automatically select the top recommended card into the Bottom Drawer
        if (plan.Cards.Count > 0)
        {
            SelectCardIntoDrawer(plan.Cards[0]);
        }
    }

    private void PopulateStepHost(StackPanel host, IReadOnlyList<ToolRecommendationCard> cards, string emptyNote)
    {
        host.Children.Clear();
        if (cards.Count == 0)
        {
            host.Children.Add(new TextBlock
            {
                Text = emptyNote,
                FontSize = 12,
                Foreground = (Brush)FindResource("TextSecondaryBrush"),
                Margin = new Thickness(4, 2, 4, 4),
                TextWrapping = TextWrapping.Wrap
            });
            return;
        }

        foreach (ToolRecommendationCard card in cards)
        {
            var cardControl = new ToolCardControl(card);
            cardControl.SelectToDrawerRequested += SelectCardIntoDrawer;
            cardControl.CopyCommandRequested += CopyCardCommand;
            cardControl.PrimaryActionRequested += ExecuteCardPrimaryAction;
            host.Children.Add(cardControl);
        }
    }

    // =====================================================================
    // VÙNG 4: DRAWER & ONE-CLICK TOOL LAUNCHER
    // =====================================================================
    private void SelectCardIntoDrawer(ToolRecommendationCard card)
    {
        _selectedCard = card;
        TxtActiveDrawerTool.Text = $"{(card.IsGui ? "🚀" : "⌨")} {card.ToolName} ▾";
        TxtCommandLine.Text = card.CommandPreview;
    }

    private void BtnQuickAddCustomTool_Click(object sender, RoutedEventArgs e)
    {
        OpenAddCustomToolDialogAndRefresh();
    }

    private void OpenAddCustomToolDialogAndRefresh()
    {
        var existingKeys = _toolsConfig.Tools.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var dlg = new AddEditToolDialog(existingKeys) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            _toolsConfig.Tools[dlg.ResultToolId] = dlg.ResultToolEntry;
            ConfigManager.SaveToolsConfig(_toolsConfig);
            AppendLog($"[＋] Đã thêm công cụ tùy chỉnh '{dlg.ResultToolEntry.Name}' ({dlg.ResultToolId}) vào tools_config.json.");

            // Re-evaluate immediately if a file is currently loaded, and load new tool into Drawer!
            if (_currentScan is not null)
            {
                AnalysisPlan updatedPlan = _ruleEngine.Evaluate(_currentScan, _toolsConfig);
                RenderWorkflowPlan(updatedPlan);
            }

            ToolRecommendationCard quickCard = RuleEngine.CreateQuickLaunchCard(
                dlg.ResultToolId,
                dlg.ResultToolEntry,
                _currentScan?.File);
            SelectCardIntoDrawer(quickCard);
        }
    }

    private void BtnQuickSelectTool_Click(object sender, RoutedEventArgs e)
    {
        var menu = new ContextMenu();

        foreach (var (toolId, entry) in _toolsConfig.Tools.OrderBy(k => k.Value.Name))
        {
            bool ready = ConfigManager.IsExecutableAvailable(entry.Executable);
            string dot = ready ? "🟢" : "🔴";
            string kind = entry.IsGui ? "GUI" : "CLI";
            var item = new MenuItem
            {
                Header = $"{dot}  [{kind}]  {entry.Name}"
            };

            item.Click += (_, _) =>
            {
                ToolRecommendationCard adHocCard = RuleEngine.CreateQuickLaunchCard(toolId, entry, _currentScan?.File);
                SelectCardIntoDrawer(adHocCard);
                AppendLog($"[⚡] Đã nạp '{entry.Name}' vào thanh khởi chạy.");
            };

            menu.Items.Add(item);
        }

        menu.Items.Add(new Separator { Background = (Brush)FindResource("BorderSubtleBrush"), Margin = new Thickness(4, 4, 4, 4) });

        var addNewItem = new MenuItem
        {
            Header = "＋ Tự thêm công cụ mới...",
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x79, 0xC0, 0xFF))
        };
        addNewItem.Click += (_, _) => OpenAddCustomToolDialogAndRefresh();
        menu.Items.Add(addNewItem);

        menu.PlacementTarget = BtnQuickSelectTool;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Top;
        menu.IsOpen = true;
    }

    private void CopyCardCommand(ToolRecommendationCard card)
    {
        Clipboard.SetText(card.CommandPreview);
        SelectCardIntoDrawer(card);
        AppendLog($"[📋] Đã sao chép câu lệnh của '{card.ToolName}' vào Clipboard.");
    }

    private async void ExecuteCardPrimaryAction(ToolRecommendationCard card)
    {
        if (card.IsGui)
        {
            LaunchGuiToolWithPrompt(card.ToolName, card.ExecutablePath, card.ResolvedArgs);
        }
        else
        {
            await ExecuteDrawerCliAsync(card.CommandPreview);
        }
    }

    private void LaunchGuiToolWithPrompt(string toolDisplayName, string executablePath, IReadOnlyList<string> args)
    {
        if (!ConfigManager.IsExecutableAvailable(executablePath))
        {
            MessageBoxResult choice = MessageBox.Show(
                this,
                $"Chưa tìm thấy công cụ '{toolDisplayName}' tại đường dẫn:\n{executablePath}\n\nBạn có muốn mở hộp thoại Settings (⚙) ngay bây giờ để trỏ tới tệp .exe của công cụ này không?",
                "Chưa cấu hình đường dẫn công cụ",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (choice == MessageBoxResult.Yes)
                OpenSettingsDialog();

            return;
        }

        try
        {
            _launcher.OpenInGuiTool(executablePath, args);
            AppendLog($"[🚀] Đã mở '{toolDisplayName}' với tệp đích.");
        }
        catch (Exception ex)
        {
            AppendLog($"[✘] Lỗi khi mở '{toolDisplayName}': {ex.Message}");
            MessageBox.Show(this, ex.Message, "Không thể mở công cụ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task ExecuteDrawerCliAsync(string commandLineText)
    {
        if (_cliCts is not null)
        {
            // Currently running -> cancel it
            _cliCts.Cancel();
            return;
        }

        List<string> tokens = ToolLauncher.SplitCommandLine(commandLineText);
        if (tokens.Count == 0)
        {
            AppendLog("[!] Ô dòng lệnh đang trống.");
            return;
        }

        string exeToken = tokens[0];
        if (!ConfigManager.IsExecutableAvailable(exeToken))
        {
            MessageBoxResult choice = MessageBox.Show(
                this,
                $"Không tìm thấy công cụ dòng lệnh:\n{exeToken}\n\nBạn có muốn mở Settings (⚙) để cấu hình đường dẫn thực tế không?",
                "Chưa tìm thấy công cụ CLI",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (choice == MessageBoxResult.Yes)
                OpenSettingsDialog();

            return;
        }

        _cliCts = new CancellationTokenSource();
        BtnDrawerRunCli.Content = "⏹ Dừng CLI";
        BtnDrawerRunCli.Style = (Style)FindResource("DangerButtonStyle");

        try
        {
            await _launcher.RunCliCommandLineAsync(
                commandLineText,
                line => Dispatcher.InvokeAsync(() => AppendLog(line)),
                _cliCts.Token);
        }
        catch (OperationCanceledException)
        {
            // Handled inside launcher callback
        }
        catch (Exception ex)
        {
            AppendLog($"[✘] Lỗi khi thực thi CLI: {ex.Message}");
        }
        finally
        {
            _cliCts.Dispose();
            _cliCts = null;
            BtnDrawerRunCli.Content = "▶ Run CLI";
            BtnDrawerRunCli.Style = (Style)FindResource("PrimaryButtonStyle");
        }
    }

    private void BtnDrawerCopy_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(TxtCommandLine.Text))
            return;

        Clipboard.SetText(TxtCommandLine.Text);
        AppendLog("[📋] Đã sao chép dòng lệnh từ Drawer vào Clipboard.");
    }

    private async void BtnDrawerRunCli_Click(object sender, RoutedEventArgs e)
    {
        await ExecuteDrawerCliAsync(TxtCommandLine.Text);
    }

    private void BtnDrawerOpenGui_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedCard is not null && TxtCommandLine.Text == _selectedCard.CommandPreview)
        {
            LaunchGuiToolWithPrompt(_selectedCard.ToolName, _selectedCard.ExecutablePath, _selectedCard.ResolvedArgs);
            return;
        }

        List<string> tokens = ToolLauncher.SplitCommandLine(TxtCommandLine.Text);
        if (tokens.Count == 0)
            return;

        LaunchGuiToolWithPrompt(Path.GetFileNameWithoutExtension(tokens[0]), tokens[0], tokens.Skip(1).ToList());
    }

    private void BtnClearLog_Click(object sender, RoutedEventArgs e)
    {
        TxtTerminalLog.Clear();
    }

    private void BtnCopyMd5_Click(object sender, RoutedEventArgs e)
    {
        if (_currentScan is null)
            return;
        Clipboard.SetText(_currentScan.File.Md5);
        AppendLog($"[📋] Đã sao chép MD5: {_currentScan.File.Md5}");
    }

    private void BtnCopySha256_Click(object sender, RoutedEventArgs e)
    {
        if (_currentScan is null)
            return;
        Clipboard.SetText(_currentScan.File.Sha256);
        AppendLog($"[📋] Đã sao chép SHA-256: {_currentScan.File.Sha256}");
    }

    private void AppendLog(string line)
    {
        if (TxtTerminalLog.Text.Length > 0)
            TxtTerminalLog.AppendText(Environment.NewLine);

        TxtTerminalLog.AppendText(line);
        TxtTerminalLog.ScrollToEnd();
    }

    // =====================================================================
    // VISUAL HELPERS
    // =====================================================================
    private static Brush GetEntropyBrush(double entropy, bool isMarkedPacked)
    {
        if (entropy > 7.2 || isMarkedPacked)
            return new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x49)); // Red Danger (> 7.2)
        if (entropy >= 6.8)
            return new SolidColorBrush(Color.FromRgb(0xD2, 0x99, 0x22)); // Amber Caution
        return new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));     // Green Safe
    }

    private static string GetCategoryIcon(string type)
    {
        if (type.Contains("Installer", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("SFX", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("Archive", StringComparison.OrdinalIgnoreCase))
            return "📦";

        if (type.Contains("Packer", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("Protector", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("Cryptor", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("Obfuscator", StringComparison.OrdinalIgnoreCase))
            return "🛡";

        if (type.Contains("Compiler", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("Language", StringComparison.OrdinalIgnoreCase))
            return "⚙";

        if (type.Contains("Library", StringComparison.OrdinalIgnoreCase))
            return "📚";

        return "🔹";
    }

    private static Brush GetCategoryBrush(string type)
    {
        if (type.Contains("Installer", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("SFX", StringComparison.OrdinalIgnoreCase))
            return new SolidColorBrush(Color.FromRgb(0xFF, 0xA6, 0x57)); // Orange Priority 1

        if (type.Contains("Packer", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("Protector", StringComparison.OrdinalIgnoreCase) ||
            type.Contains("Obfuscator", StringComparison.OrdinalIgnoreCase))
            return new SolidColorBrush(Color.FromRgb(0xFF, 0x7B, 0x72)); // Red Priority 2

        return new SolidColorBrush(Color.FromRgb(0xD2, 0xA8, 0xFF));     // Purple Priority 3
    }
}
