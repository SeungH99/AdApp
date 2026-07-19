using LocalDocumentOrganizer.Core.Events;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

/// <summary>
/// Defines a trusted in-process projection component. Projection SQL is constrained by an
/// SQLite authorizer and any denied operation fails the enclosing Vault transaction, but this
/// boundary is not a sandbox for code that replaces native callbacks or modifies Vault files.
/// </summary>
public interface ISqliteProjection
{
    string Name { get; }

    Task InitializeAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken);

    Task ApplyAsync(
        DecryptedEvent decryptedEvent,
        long globalPosition,
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken);

    Task ResetAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken);

    Task<string> CalculateChecksumAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken);
}
