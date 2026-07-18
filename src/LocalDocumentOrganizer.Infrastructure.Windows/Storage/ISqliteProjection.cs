using LocalDocumentOrganizer.Core.Events;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

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
