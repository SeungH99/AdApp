using System.Collections.Frozen;
using System.Collections;
using System.Collections.ObjectModel;
using System.Runtime.CompilerServices;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal readonly record struct EncryptedProjectionLocation
{
    internal EncryptedProjectionLocation(string tableName, string fieldName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tableName);
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldName);
        ProjectionValueAdditionalData.ValidateIdentifier(tableName);
        ProjectionValueAdditionalData.ValidateIdentifier(fieldName);
        TableName = tableName;
        FieldName = fieldName;
    }

    public string TableName { get; }

    public string FieldName { get; }
}

internal readonly record struct ProjectionOwnedTable
{
    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "timeline_events",
        "event_streams",
        "vault_metadata",
        "projection_checkpoints",
        "secure_compaction_queue",
        "managed_vault_copies",
        "projection_rebuild_manifest",
        "sqlite_sequence",
        "sqlite_schema",
        "sqlite_master",
    };

    internal ProjectionOwnedTable(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ProjectionValueAdditionalData.ValidateIdentifier(name);
        if (!IsSqlIdentifier(name) || ReservedNames.Contains(name))
        {
            throw new ArgumentException("A non-reserved SQLite table identifier is required.", nameof(name));
        }

        Name = name;
    }

    public string Name { get; }

    private static bool IsSqlIdentifier(string value)
    {
        if (value.Length == 0 || !(value[0] == '_' || char.IsAsciiLetter(value[0])))
        {
            return false;
        }

        foreach (var character in value.AsSpan(1))
        {
            if (character != '_' && !char.IsAsciiLetterOrDigit(character))
            {
                return false;
            }
        }

        return true;
    }
}

internal sealed class SqliteProjectionRegistration
{
    internal SqliteProjectionRegistration(
        ISqliteProjection projection,
        IEnumerable<EncryptedProjectionLocation> encryptedLocations)
        : this(projection, Snapshot(encryptedLocations))
    {
    }

    private SqliteProjectionRegistration(
        ISqliteProjection projection,
        EncryptedProjectionLocation[] encryptedLocations)
        : this(
            projection,
            encryptedLocations
                .Select(location => location.TableName)
                .Distinct(StringComparer.Ordinal)
                .Select(name => new ProjectionOwnedTable(name)),
            encryptedLocations)
    {
    }

    internal SqliteProjectionRegistration(
        ISqliteProjection projection,
        IEnumerable<ProjectionOwnedTable> ownedTables,
        IEnumerable<EncryptedProjectionLocation> encryptedLocations)
    {
        ArgumentNullException.ThrowIfNull(projection);
        ArgumentNullException.ThrowIfNull(ownedTables);
        ArgumentNullException.ThrowIfNull(encryptedLocations);
        if (string.IsNullOrWhiteSpace(projection.Name))
            throw new ArgumentException("A stable projection name is required.", nameof(projection));
        ProjectionValueAdditionalData.ValidateIdentifier(projection.Name);
        if (projection.SchemaVersion <= 0)
            throw new ArgumentOutOfRangeException(nameof(projection), "Projection schema versions must be positive.");
        if (projection.EncryptionVersion != EncryptedProjectionValue.CurrentVersion)
            throw new ArgumentOutOfRangeException(
                nameof(projection),
                "The projection encryption version is unsupported.");

        var tables = ownedTables
            .OrderBy(table => table.Name, StringComparer.Ordinal)
            .ToArray();
        if (tables.Length != tables.Select(table => table.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count())
        {
            throw new ArgumentException("Projection-owned table names must be unique.", nameof(ownedTables));
        }

        var locations = encryptedLocations.ToArray();
        if (locations.Length != locations.ToHashSet().Count)
            throw new ArgumentException(
                "Encrypted projection locations must be unique.",
                nameof(encryptedLocations));
        var ownedNames = tables.Select(table => table.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (locations.Any(location => !ownedNames.Contains(location.TableName)))
        {
            throw new ArgumentException(
                "Every encrypted projection location must belong to an owned table.",
                nameof(encryptedLocations));
        }

        Projection = projection;
        Name = projection.Name;
        SchemaVersion = projection.SchemaVersion;
        EncryptionVersion = projection.EncryptionVersion;
        OwnedTables = new ReadOnlyCollection<ProjectionOwnedTable>(tables);
        EncryptedLocations = locations.ToFrozenSet();
    }

    public ISqliteProjection Projection { get; }

    public string Name { get; }

    public int SchemaVersion { get; }

    public int EncryptionVersion { get; }

    public IReadOnlyList<ProjectionOwnedTable> OwnedTables { get; }

    public IReadOnlySet<EncryptedProjectionLocation> EncryptedLocations { get; }

    private static EncryptedProjectionLocation[] Snapshot(
        IEnumerable<EncryptedProjectionLocation> encryptedLocations)
    {
        ArgumentNullException.ThrowIfNull(encryptedLocations);
        return encryptedLocations.ToArray();
    }
}

[CollectionBuilder(typeof(SqliteProjectionRegistryBuilder), nameof(SqliteProjectionRegistryBuilder.Create))]
internal sealed class SqliteProjectionRegistry : IEnumerable<ISqliteProjection>
{
    internal static SqliteProjectionRegistry Empty { get; } = new([], allowsLegacyTestObjects: false);

    internal SqliteProjectionRegistry(IEnumerable<SqliteProjectionRegistration> registrations)
        : this(registrations, allowsLegacyTestObjects: false)
    {
    }

    private SqliteProjectionRegistry(
        IEnumerable<SqliteProjectionRegistration> registrations,
        bool allowsLegacyTestObjects)
    {
        ArgumentNullException.ThrowIfNull(registrations);
        var ordered = registrations
            .OrderBy(registration => registration?.Name, StringComparer.Ordinal)
            .ToArray();
        var names = new HashSet<string>(StringComparer.Ordinal);
        var tableOwners = new Dictionary<string, SqliteProjectionRegistration>(StringComparer.OrdinalIgnoreCase);
        foreach (var registration in ordered)
        {
            ArgumentNullException.ThrowIfNull(registration);
            if (!names.Add(registration.Name))
                throw new ArgumentException("Projection names must be stable and unique.", nameof(registrations));
            foreach (var table in registration.OwnedTables)
            {
                if (!tableOwners.TryAdd(table.Name, registration))
                {
                    throw new ArgumentException(
                        "Projection-owned table names must be unique across the registry.",
                        nameof(registrations));
                }
            }
        }

        Registrations = new ReadOnlyCollection<SqliteProjectionRegistration>(ordered);
        Projections = new ReadOnlyCollection<ISqliteProjection>(
            ordered.Select(registration => registration.Projection).ToArray());
        TableOwners = tableOwners.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
        AllowsLegacyTestObjects = allowsLegacyTestObjects;
    }

    internal IReadOnlyList<SqliteProjectionRegistration> Registrations { get; }

    internal IReadOnlyList<ISqliteProjection> Projections { get; }

    internal IReadOnlyDictionary<string, SqliteProjectionRegistration> TableOwners { get; }

    internal bool AllowsLegacyTestObjects { get; }

    internal SqliteProjectionRegistration? FindOwner(string tableName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tableName);
        return TableOwners.GetValueOrDefault(tableName);
    }

    internal static SqliteProjectionRegistry CreateForTests(
        IEnumerable<ISqliteProjection> projections)
    {
        ArgumentNullException.ThrowIfNull(projections);
        return new SqliteProjectionRegistry(
            projections.Select(projection => new SqliteProjectionRegistration(projection, [])),
            allowsLegacyTestObjects: true);
    }

    public IEnumerator<ISqliteProjection> GetEnumerator() => Projections.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

internal static class SqliteProjectionRegistryBuilder
{
    public static SqliteProjectionRegistry Create(ReadOnlySpan<ISqliteProjection> projections) =>
        SqliteProjectionRegistry.CreateForTests(projections.ToArray());
}
