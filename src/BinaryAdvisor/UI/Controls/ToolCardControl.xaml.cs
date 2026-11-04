using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using BinaryAdvisor.Models;

namespace BinaryAdvisor.UI.Controls;

public partial class ToolCardControl : UserControl
{
    public ToolRecommendationCard Card { get; }

    public event Action<ToolRecommendationCard>? PrimaryActionRequested;
    public event Action<ToolRecommendationCard>? CopyCommandRequested;
    public event Action<ToolRecommendationCard>? SelectToDrawerRequested;

    public ToolCardControl(ToolRecommendationCard card)
    {
        InitializeComponent();
        Card = card;
        BindCard();
    }

    private void BindCard()
    {
        TxtToolName.Text = Card.ToolName;
        TxtRuleBadge.Text = Card.MatchedRuleTitle;
        TxtReason.Text = Card.Reason;
        TxtCommandPreview.Text = Card.CommandPreview;
        TxtCommandPreview.ToolTip = Card.CommandPreview;

        // Status indicator dot (Green = Ready, Red = Missing)
        if (Card.IsToolInstalled)
        {
            StatusDot.Fill = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
            StatusDot.ToolTip = $"Đã cài đặt: {Card.ExecutablePath}";
            TxtInstallState.Text = "Sẵn sàng";
            TxtInstallState.Foreground = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
        }
        else
        {
            StatusDot.Fill = new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x49));
            StatusDot.ToolTip = $"Chưa tìm thấy tại: {Card.ExecutablePath} (Bấm Settings ⚙ để cấu hình)";
            TxtInstallState.Text = "Chưa cấu hình đường dẫn";
            TxtInstallState.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x49));
        }

        // GUI vs CLI badge
        if (Card.IsGui)
        {
            TypeBadge.Background = new SolidColorBrush(Color.FromRgb(0x18, 0x32, 0x56));
            TxtTypeBadge.Text = "GUI TOOL";
            TxtTypeBadge.Foreground = new SolidColorBrush(Color.FromRgb(0x58, 0xA6, 0xFF));
            BtnPrimaryAction.Content = $"🚀 Open in {Card.ToolName}";
            BtnPrimaryAction.Style = (Style)Application.Current.FindResource("AccentButtonStyle");
        }
        else
        {
            TypeBadge.Background = new SolidColorBrush(Color.FromRgb(0x16, 0x36, 0x22));
            TxtTypeBadge.Text = "CLI TOOL";
            TxtTypeBadge.Foreground = new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50));
            BtnPrimaryAction.Content = "▶ Run CLI";
            BtnPrimaryAction.Style = (Style)Application.Current.FindResource("PrimaryButtonStyle");
        }

        // Heuristic Priority highlight border
        if (Card.Priority == 0)
        {
            CardRoot.BorderBrush = new SolidColorBrush(Color.FromRgb(0xD2, 0x99, 0x22));
        }

        // Optional Warning Box
        if (!string.IsNullOrWhiteSpace(Card.Warning))
        {
            WarningBox.Visibility = Visibility.Visible;
            TxtWarning.Text = $"⚠ Lưu ý: {Card.Warning}";
        }
    }

    private void BtnPrimaryAction_Click(object sender, RoutedEventArgs e)
    {
        e.Handled = true;
        SelectToDrawerRequested?.Invoke(Card);
        PrimaryActionRequested?.Invoke(Card);
    }

    private void BtnCopyCmd_Click(object sender, RoutedEventArgs e)
    {
        e.Handled = true;
        CopyCommandRequested?.Invoke(Card);
    }

    private void BtnSelectDrawer_Click(object sender, RoutedEventArgs e)
    {
        e.Handled = true;
        SelectToDrawerRequested?.Invoke(Card);
    }

    private void CardRoot_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        SelectToDrawerRequested?.Invoke(Card);
    }
}
