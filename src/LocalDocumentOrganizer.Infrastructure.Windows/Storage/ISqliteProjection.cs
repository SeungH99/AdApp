using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

/// <summary>
/// Defines a trusted in-process projection component. Projection SQL is constrained by an
/// SQLite authorizer and any denied operation fails the enclosing Vault transaction, but this
/// boundary is not a sandbox for code that replaces native callbacks or modifies Vault files.
/// </summary>
internal interface ISqliteProjection
{
    string Name { get; }

    int SchemaVersion { get; }

    int EncryptionVersion { get; }

    Task<ProjectionCompatibilityResult> InitializeAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken);

    Task ApplyAsync(
        EventForReplay replayEvent,
        long globalPosition,
        SqliteProjectionApplyContext context,
        CancellationToken cancellationToken);

    Task PurgeOwnerAsync(
        SensitiveObjectRef owner,
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken);

    Task ResetAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken);

    Task<string> CalculateChecksumAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken);
}
