using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("LocalDocumentOrganizer.Intake.Tests")]

namespace LocalDocumentOrganizer.Infrastructure.Windows.Intake;

public enum VaultImportFaultPoint
{
    IntentPersisted,
    IdentityLocked,
    Copying,
    TemporaryCreated,
    Copied,
    Verified,
    Publishing,
    FileApplied,
    ProductCommitted,
    EventAndProjectionCommitted,
    SideEffectsPending,
    SourceHashing,
    AdmissionRevalidated,
}

internal interface IVaultImportFaultInjector
{
    void OnFaultPoint(VaultImportFaultPoint point);
}

internal sealed class InjectedVaultImportFaultException : IOException
{
    internal InjectedVaultImportFaultException(
        VaultImportFaultPoint point)
        : base("An injected VaultImport fault interrupted processing.")
    {
        Point = point;
    }

    internal VaultImportFaultPoint Point { get; }
}

internal sealed class NoOpVaultImportFaultInjector :
    IVaultImportFaultInjector
{
    internal static NoOpVaultImportFaultInjector Instance { get; } = new();

    private NoOpVaultImportFaultInjector()
    {
    }

    public void OnFaultPoint(VaultImportFaultPoint point)
    {
    }
}
