using Microsoft.UI.Xaml;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Cases.CloseCase;
using System.Collections.Immutable;
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
        var caseId = new CaseId(Guid.Parse("20CDA91C-D41E-4F19-A6DB-4B35A24F9968"));
        var proofDocumentId = new DocumentId(Guid.Parse("2C8B4E54-E38A-4269-A8C3-34EFD790AF2E"));
        var state = new CaseState(caseId, CaseStatus.Open, [proofDocumentId], []);
        var decision = CloseCaseDecider.Decide(
            state,
            new CloseCaseCommand(
                caseId,
                proofDocumentId,
                null,
                new ExplicitApproval(DateTimeOffset.UtcNow)));

        if (!decision.IsAccepted)
        {
            ApprovalStatusText.Text = $"Action blocked: {decision.Failure}";
            return;
        }

        ApproveActionButton.IsEnabled = false;
        ApproveActionButton.Content = "✓  Action approved";
        ApprovalStatusText.Text = "Approval recorded locally. The original files remain unchanged.";
    }
}
