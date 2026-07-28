using Microsoft.UI.Xaml;
using LocalDocumentOrganizer.Application.UseCases;
using Windows.Graphics;

namespace LocalDocumentOrganizer.App;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        AppWindow.Title = "Proof to Closure";
        AppWindow.Resize(new SizeInt32(1580, 980));
    }

    private void ApproveActionButton_Click(object sender, RoutedEventArgs e)
    {
        if (!ApproveCaseAction.TryApprove(
                DateTimeOffset.UtcNow,
                out var failure))
        {
            ApprovalStatusText.Text = $"Action blocked: {failure}";
            return;
        }

        ApproveActionButton.IsEnabled = false;
        ApproveActionButton.Content = "✓  Action approved";
        ApprovalStatusText.Text = "Approval recorded locally. The original files remain unchanged.";
    }
}
