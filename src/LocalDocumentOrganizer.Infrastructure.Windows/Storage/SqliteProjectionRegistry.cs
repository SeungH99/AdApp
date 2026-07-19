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

internal sealed class SqliteProjectionRegistration
{
    internal SqliteProjectionRegistration(
        ISqliteProjection projection,
        IEnumerable<EncryptedProjectionLocation> encryptedLocations)
    {
        ArgumentNullException.ThrowIfNull(projection);
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

        var locations = encryptedLocations.ToArray();
        if (locations.Length != locations.ToHashSet().Count)
            throw new ArgumentException(
                "Encrypted projection locations must be unique.",
                nameof(encryptedLocations));

        Projection = projection;
        Name = projection.Name;
        SchemaVersion = projection.SchemaVersion;
        EncryptionVersion = projection.EncryptionVersion;
        EncryptedLocations = locations.ToFrozenSet();
    }

    public ISqliteProjection Projection { get; }

    public string Name { get; }

    public int SchemaVersion { get; }

    public int EncryptionVersion { get; }

    public IReadOnlySet<EncryptedProjectionLocation> EncryptedLocations { get; }
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
        foreach (var registration in ordered)
        {
            ArgumentNullException.ThrowIfNull(registration);
            if (!names.Add(registration.Name))
                throw new ArgumentException("Projection names must be stable and unique.", nameof(registrations));
        }

        Registrations = new ReadOnlyCollection<SqliteProjectionRegistration>(ordered);
        Projections = new ReadOnlyCollection<ISqliteProjection>(
            ordered.Select(registration => registration.Projection).ToArray());
        AllowsLegacyTestObjects = allowsLegacyTestObjects;
    }

    internal IReadOnlyList<SqliteProjectionRegistration> Registrations { get; }

    internal IReadOnlyList<ISqliteProjection> Projections { get; }

    internal bool AllowsLegacyTestObjects { get; }

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
