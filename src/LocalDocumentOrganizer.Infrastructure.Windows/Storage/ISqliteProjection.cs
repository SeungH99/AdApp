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
        StoredEvent storedEvent,
        long globalPosition,
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken);
}
