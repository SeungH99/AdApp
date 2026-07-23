using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Security.Cryptography;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal sealed record ReplayEventCoordinates(
    long GlobalPosition,
    StreamId StreamId,
    StreamVersion StreamVersion,
    EventId EventId,
    OperationId OperationId,
    int OperationIndex,
    int OperationCount);

internal sealed class ProjectionReplayManifest
{
    private ProjectionReplayManifest(
        long totalEventCount,
        long requiredGlobalPosition,
        IEnumerable<KeyValuePair<StreamId, StreamVersion>> streamHeads,
        ReadOnlySpan<byte> coordinateDigest,
        ReadOnlySpan<byte> streamHeadDigest,
        ReadOnlySpan<byte> operationDigest,
        VaultKeyRingIdentity keyRingIdentity)
    {
        TotalEventCount = totalEventCount;
        RequiredGlobalPosition = requiredGlobalPosition;
        StreamHeads = streamHeads.ToFrozenDictionary(
            pair => pair.Key,
            pair => pair.Value);
        CoordinateDigest = ImmutableArray.CreateRange(coordinateDigest.ToArray());
        StreamHeadDigest = ImmutableArray.CreateRange(streamHeadDigest.ToArray());
        OperationDigest = ImmutableArray.CreateRange(operationDigest.ToArray());
        KeyRingIdentity = new VaultKeyRingIdentity(keyRingIdentity.Export());
    }

    internal long TotalEventCount { get; }

    internal long RequiredGlobalPosition { get; }

    internal FrozenDictionary<StreamId, StreamVersion> StreamHeads { get; }

    internal ImmutableArray<byte> CoordinateDigest { get; }

    internal ImmutableArray<byte> StreamHeadDigest { get; }

    internal ImmutableArray<byte> OperationDigest { get; }

    internal VaultKeyRingIdentity KeyRingIdentity { get; }

    internal static ProjectionReplayManifest Create(
        long totalEventCount,
        long requiredGlobalPosition,
        IEnumerable<KeyValuePair<StreamId, StreamVersion>> streamHeads,
        ReadOnlySpan<byte> coordinateDigest,
        ReadOnlySpan<byte> streamHeadDigest,
        ReadOnlySpan<byte> operationDigest,
        VaultKeyRingIdentity keyRingIdentity) =>
        new(
            totalEventCount,
            requiredGlobalPosition,
            streamHeads,
            coordinateDigest,
            streamHeadDigest,
            operationDigest,
            keyRingIdentity);
}

internal sealed class ProjectionRebuildValidationResult
{
    private ProjectionRebuildValidationResult(
        ProjectionReplayManifest manifest,
        FrozenDictionary<string, string> projectionChecksums)
    {
        Manifest = manifest;
        ProjectionChecksums = projectionChecksums;
    }

    internal ProjectionReplayManifest Manifest { get; }

    internal FrozenDictionary<string, string> ProjectionChecksums { get; }

    internal static ProjectionRebuildValidationResult Create(
        ProjectionReplayManifest manifest,
        IEnumerable<KeyValuePair<string, string>> projectionChecksums)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(projectionChecksums);
        var checksums = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in projectionChecksums)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(pair.Key);
            if (!IsChecksum(pair.Value) || !checksums.TryAdd(pair.Key, pair.Value))
            {
                throw new ArgumentException("Projection checksums must be unique lowercase SHA-256 values.");
            }
        }

        return new ProjectionRebuildValidationResult(
            manifest,
            checksums.ToFrozenDictionary(StringComparer.Ordinal));
    }

    private static bool IsChecksum(string? value) =>
        value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

internal readonly record struct ProjectionCheckpointSnapshot(
    int SchemaVersion,
    int EncryptionVersion,
    long Position);

internal sealed class ProjectionRebuildSourceSnapshot
{
    private ProjectionRebuildSourceSnapshot(
        long totalEventCount,
        long requiredGlobalPosition,
        IEnumerable<string> projectionNames,
        IEnumerable<KeyValuePair<StreamId, StreamVersion>> streamHeads,
        IEnumerable<KeyValuePair<string, string>> compatibleProjectionChecksums,
        VaultKeyRingIdentity keyRingIdentity)
    {
        if (totalEventCount < 0 || requiredGlobalPosition < 0)
            throw new ArgumentOutOfRangeException(nameof(totalEventCount));
        ArgumentNullException.ThrowIfNull(projectionNames);
        ArgumentNullException.ThrowIfNull(streamHeads);
        ArgumentNullException.ThrowIfNull(compatibleProjectionChecksums);
        ArgumentNullException.ThrowIfNull(keyRingIdentity);

        TotalEventCount = totalEventCount;
        RequiredGlobalPosition = requiredGlobalPosition;
        ProjectionNames = projectionNames
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToImmutableArray();
        if (ProjectionNames.Any(string.IsNullOrWhiteSpace)
            || ProjectionNames.Distinct(StringComparer.Ordinal).Count() != ProjectionNames.Length)
        {
            throw new ArgumentException("Projection names must be stable and unique.", nameof(projectionNames));
        }

        StreamHeads = streamHeads
            .OrderBy(pair => CanonicalGuidHex(pair.Key.Value), StringComparer.Ordinal)
            .ToFrozenDictionary(pair => pair.Key, pair => pair.Value);
        CompatibleProjectionChecksums = compatibleProjectionChecksums
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .ToFrozenDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        KeyRingIdentity = new VaultKeyRingIdentity(keyRingIdentity.Export());
    }

    internal long TotalEventCount { get; }

    internal long RequiredGlobalPosition { get; }

    internal ImmutableArray<string> ProjectionNames { get; }

    internal FrozenDictionary<StreamId, StreamVersion> StreamHeads { get; }

    internal FrozenDictionary<string, string> CompatibleProjectionChecksums { get; }

    internal VaultKeyRingIdentity KeyRingIdentity { get; }

    internal static ProjectionRebuildSourceSnapshot Create(
        long totalEventCount,
        long requiredGlobalPosition,
        IEnumerable<string> projectionNames,
        IEnumerable<KeyValuePair<StreamId, StreamVersion>> streamHeads,
        IEnumerable<KeyValuePair<string, string>> compatibleProjectionChecksums,
        VaultKeyRingIdentity keyRingIdentity) =>
        new(
            totalEventCount,
            requiredGlobalPosition,
            projectionNames,
            streamHeads,
            compatibleProjectionChecksums,
            keyRingIdentity);

    private static string CanonicalGuidHex(Guid value)
    {
        Span<byte> bytes = stackalloc byte[16];
        value.TryWriteBytes(bytes, bigEndian: true, out _);
        return Convert.ToHexString(bytes);
    }
}

internal sealed class ProjectionRebuildValidator
{
    internal ManifestAccumulator BeginManifest(VaultKeyRingIdentity keyRingIdentity)
    {
        ArgumentNullException.ThrowIfNull(keyRingIdentity);
        return new ManifestAccumulator(keyRingIdentity);
    }

    internal async Task<ProjectionRebuildValidationResult> ValidateTemporaryAsync(
        SqliteConnection temporaryConnection,
        SqliteTransaction temporaryTransaction,
        IReadOnlyList<SqliteProjectionRegistration> selected,
        ProjectionReplayManifest expectedManifest,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(temporaryConnection);
        ArgumentNullException.ThrowIfNull(temporaryTransaction);
        ArgumentNullException.ThrowIfNull(selected);
        ArgumentNullException.ThrowIfNull(expectedManifest);
        ArgumentNullException.ThrowIfNull(keyRing);
        keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Rebuild);
        await keyRing.RequireCanonicalIdentityAsync(
            expectedManifest.KeyRingIdentity,
            cancellationToken).ConfigureAwait(false);
        await RequireManifestRowAsync(
            temporaryConnection,
            temporaryTransaction,
            expectedManifest,
            cancellationToken).ConfigureAwait(false);
        await RequireExactSchemaAsync(
            temporaryConnection,
            temporaryTransaction,
            selected,
            cancellationToken).ConfigureAwait(false);
        await SqliteProjectionCheckpointStore.RequireExactSelectedAsync(
            temporaryConnection,
            temporaryTransaction,
            ProjectionCheckpointSchema.Main,
            selected,
            expectedManifest.RequiredGlobalPosition,
            requireOnlySelected: true,
            cancellationToken).ConfigureAwait(false);

        var checksums = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var registration in selected)
        {
            string checksum;
            try
            {
                checksum = await SqliteProjectionAuthorizer.RunAsync(
                    temporaryConnection,
                    registration.OwnedTables,
                    () => registration.Projection.CalculateChecksumAsync(
                        SqliteProjectionContexts.CreateAdministrative(
                            temporaryConnection,
                            temporaryTransaction,
                            keyRing,
                            lease,
                            registration),
                        cancellationToken)).ConfigureAwait(false);
            }
            catch (SqliteException exception)
            {
                throw new VaultRecoveryRequiredException(exception);
            }
            if (checksum is not { Length: 64 }
                || checksum.Any(character => character is not (>= '0' and <= '9')
                    and not (>= 'a' and <= 'f')))
            {
                throw new InvalidProjectionChecksumException(registration.Name, checksum ?? string.Empty);
            }
            checksums.Add(registration.Name, checksum);
        }

        return ProjectionRebuildValidationResult.Create(expectedManifest, checksums);
    }

    internal async Task RequireAuthoritativeSnapshotAsync(
        SqliteConnection liveConnection,
        SqliteTransaction liveTransaction,
        ProjectionReplayManifest expected,
        CancellationToken cancellationToken)
    {
        await using (var command = liveConnection.CreateCommand())
        {
            command.Transaction = liveTransaction;
            command.CommandText =
                "SELECT COUNT(*), COALESCE(MAX(global_position),0) FROM main.timeline_events;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)
                || reader.GetInt64(0) != expected.TotalEventCount
                || reader.GetInt64(1) != expected.RequiredGlobalPosition
                || await reader.ReadAsync(cancellationToken))
            {
                throw new VaultRecoveryRequiredException();
            }
        }

        var heads = new Dictionary<StreamId, StreamVersion>();
        await using (var command = liveConnection.CreateCommand())
        {
            command.Transaction = liveTransaction;
            command.CommandText =
                "SELECT stream_id,head_version FROM main.event_streams ORDER BY stream_id COLLATE BINARY;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                heads.Add(
                    new StreamId(SqliteEventStore.ParseCanonicalGuid(reader.GetString(0))),
                    new StreamVersion(reader.GetInt64(1)));
            }
        }

        if (heads.Count != expected.StreamHeads.Count
            || heads.Any(pair =>
                !expected.StreamHeads.TryGetValue(pair.Key, out var version)
                || version != pair.Value))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    internal async Task<ProjectionReplayManifest> ReadAuthoritativeManifestAsync(
        SqliteConnection liveConnection,
        SqliteTransaction liveTransaction,
        VaultKeyRingIdentity keyRingIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(liveConnection);
        ArgumentNullException.ThrowIfNull(liveTransaction);
        ArgumentNullException.ThrowIfNull(keyRingIdentity);
        var accumulator = BeginManifest(keyRingIdentity);
        await using (var command = liveConnection.CreateCommand())
        {
            command.Transaction = liveTransaction;
            command.CommandText = """
                SELECT global_position,stream_id,stream_version,event_id,
                       operation_id,operation_index,operation_count
                FROM main.timeline_events
                ORDER BY global_position;
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (reader.GetValue(0) is not long globalPosition
                    || reader.GetValue(1) is not string streamId
                    || reader.GetValue(2) is not long streamVersion
                    || reader.GetValue(3) is not string eventId
                    || reader.GetValue(4) is not string operationId
                    || reader.GetValue(5) is not long operationIndex
                    || operationIndex is < int.MinValue or > int.MaxValue
                    || reader.GetValue(6) is not long operationCount
                    || operationCount is < int.MinValue or > int.MaxValue)
                {
                    throw new VaultRecoveryRequiredException();
                }

                accumulator.Accept(new ReplayEventCoordinates(
                    globalPosition,
                    new StreamId(SqliteEventStore.ParseCanonicalGuid(streamId)),
                    new StreamVersion(streamVersion),
                    new EventId(SqliteEventStore.ParseCanonicalGuid(eventId)),
                    new OperationId(SqliteEventStore.ParseCanonicalGuid(operationId)),
                    checked((int)operationIndex),
                    checked((int)operationCount)));
            }
        }

        var heads = new Dictionary<StreamId, StreamVersion>();
        await using (var command = liveConnection.CreateCommand())
        {
            command.Transaction = liveTransaction;
            command.CommandText = """
                SELECT stream_id,head_version
                FROM main.event_streams
                ORDER BY stream_id COLLATE BINARY;
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (reader.GetValue(0) is not string streamId
                    || reader.GetValue(1) is not long headVersion
                    || !heads.TryAdd(
                        new StreamId(SqliteEventStore.ParseCanonicalGuid(streamId)),
                        new StreamVersion(headVersion)))
                {
                    throw new VaultRecoveryRequiredException();
                }
            }
        }

        return accumulator.Freeze(heads);
    }

    internal static async Task RequireManifestRowAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ProjectionReplayManifest expected,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT generation_id,keyring_id,required_global_position,total_event_count,
                   coordinate_digest,stream_head_digest,operation_digest
            FROM main.projection_rebuild_manifest WHERE singleton=1;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)
            || reader.GetValue(0) is not string generation
            || !Guid.TryParseExact(generation, "N", out _)
            || reader.GetValue(1) is not byte[] keyRingId
            || !expected.KeyRingIdentity.FixedTimeEquals(keyRingId)
            || reader.GetInt64(2) != expected.RequiredGlobalPosition
            || reader.GetInt64(3) != expected.TotalEventCount
            || reader.GetValue(4) is not byte[] coordinate
            || !CryptographicOperations.FixedTimeEquals(coordinate, expected.CoordinateDigest.AsSpan())
            || reader.GetValue(5) is not byte[] streamHeads
            || !CryptographicOperations.FixedTimeEquals(streamHeads, expected.StreamHeadDigest.AsSpan())
            || reader.GetValue(6) is not byte[] operations
            || !CryptographicOperations.FixedTimeEquals(operations, expected.OperationDigest.AsSpan())
            || await reader.ReadAsync(cancellationToken))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    internal static async Task RequireExactSchemaAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyList<SqliteProjectionRegistration> selected,
        CancellationToken cancellationToken)
    {
        var owners = selected
            .SelectMany(registration => registration.OwnedTables.Select(table =>
                new KeyValuePair<string, SqliteProjectionRegistration>(table.Name, registration)))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        var expectedTables = owners.Keys
            .Append("projection_rebuild_manifest")
            .Append("projection_checkpoints")
            .ToHashSet(StringComparer.Ordinal);
        var actualTables = new HashSet<string>(StringComparer.Ordinal);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT type,name,tbl_name FROM main.sqlite_master
                WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name COLLATE BINARY;
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var type = reader.GetString(0);
                var name = reader.GetString(1);
                var table = reader.GetString(2);
                if (type == "table")
                {
                    if (!actualTables.Add(name)) throw new VaultRecoveryRequiredException();
                    continue;
                }

                if (type == "view" || !owners.ContainsKey(table))
                {
                    throw new VaultRecoveryRequiredException();
                }
            }
        }

        if (!actualTables.SetEquals(expectedTables))
        {
            throw new VaultRecoveryRequiredException();
        }

        foreach (var owner in owners)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"PRAGMA main.foreign_key_list(\"{owner.Key}\");";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var referenced = reader.GetString(2);
                if (!owner.Value.OwnedTables.Any(table => table.Name == referenced))
                {
                    throw new VaultRecoveryRequiredException();
                }
            }
        }
    }

    internal sealed class ManifestAccumulator
    {
        private static readonly byte[] CoordinateDomain =
            "LocalDocumentOrganizer/ProjectionRebuild/Coordinates/v1"u8.ToArray();
        private static readonly byte[] OperationDomain =
            "LocalDocumentOrganizer/ProjectionRebuild/Operations/v1"u8.ToArray();
        private static readonly byte[] StreamDomain =
            "LocalDocumentOrganizer/ProjectionRebuild/StreamHeads/v1"u8.ToArray();

        private readonly VaultKeyRingIdentity _keyRingIdentity;
        private readonly IncrementalHash _coordinates = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private readonly IncrementalHash _operations = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private readonly Dictionary<StreamId, StreamVersion> _computedHeads = [];
        private long _totalEventCount;
        private long _lastGlobalPosition;
        private OperationId? _currentOperation;
        private StreamId? _operationStream;
        private int _operationCount;
        private int _nextOperationIndex;
        private bool _frozen;

        internal ManifestAccumulator(VaultKeyRingIdentity keyRingIdentity)
        {
            _keyRingIdentity = new VaultKeyRingIdentity(keyRingIdentity.Export());
            _coordinates.AppendData(CoordinateDomain);
            _operations.AppendData(OperationDomain);
        }

        internal void Accept(ReplayEventCoordinates coordinates)
        {
            ArgumentNullException.ThrowIfNull(coordinates);
            if (_frozen
                || coordinates.GlobalPosition <= 0
                || coordinates.GlobalPosition != _lastGlobalPosition + 1)
            {
                throw new EventStreamCorruptionException("Replay event positions are not contiguous.");
            }

            var expectedVersion = _computedHeads.TryGetValue(coordinates.StreamId, out var head)
                ? head.Next()
                : new StreamVersion(0);
            if (coordinates.StreamVersion != expectedVersion)
            {
                throw new EventStreamCorruptionException("Replay stream versions are not contiguous.");
            }

            AcceptOperation(coordinates);
            AppendInt64(_coordinates, coordinates.GlobalPosition);
            AppendGuid(_coordinates, coordinates.StreamId.Value);
            AppendInt64(_coordinates, coordinates.StreamVersion.Value);
            AppendGuid(_coordinates, coordinates.EventId.Value);
            AppendGuid(_operations, coordinates.OperationId.Value);
            AppendInt32(_operations, coordinates.OperationIndex);
            AppendInt32(_operations, coordinates.OperationCount);
            _computedHeads[coordinates.StreamId] = coordinates.StreamVersion;
            _lastGlobalPosition = coordinates.GlobalPosition;
            _totalEventCount = checked(_totalEventCount + 1);
        }

        internal ProjectionReplayManifest Freeze(
            IEnumerable<KeyValuePair<StreamId, StreamVersion>> streamHeads)
        {
            ArgumentNullException.ThrowIfNull(streamHeads);
            if (_frozen)
            {
                throw new InvalidOperationException("The replay manifest is already frozen.");
            }

            CompleteOperation();
            var ordered = streamHeads
                .OrderBy(pair => CanonicalGuidHex(pair.Key.Value), StringComparer.Ordinal)
                .ToArray();
            var supplied = ordered.ToDictionary(pair => pair.Key, pair => pair.Value);
            if (supplied.Count != _computedHeads.Count
                || supplied.Any(pair =>
                    !_computedHeads.TryGetValue(pair.Key, out var version)
                    || version != pair.Value))
            {
                throw new EventStreamCorruptionException("Replay stream heads do not match event coordinates.");
            }

            using var streamDigest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            streamDigest.AppendData(StreamDomain);
            foreach (var pair in ordered)
            {
                AppendGuid(streamDigest, pair.Key.Value);
                AppendInt64(streamDigest, pair.Value.Value);
            }

            _frozen = true;
            return ProjectionReplayManifest.Create(
                _totalEventCount,
                _lastGlobalPosition,
                ordered,
                _coordinates.GetHashAndReset(),
                streamDigest.GetHashAndReset(),
                _operations.GetHashAndReset(),
                _keyRingIdentity);
        }

        private void AcceptOperation(ReplayEventCoordinates coordinates)
        {
            if (_currentOperation != coordinates.OperationId)
            {
                CompleteOperation();
                if (coordinates.OperationIndex != 0 || coordinates.OperationCount <= 0)
                {
                    throw new EventStreamCorruptionException("The operation group is malformed.");
                }

                _currentOperation = coordinates.OperationId;
                _operationStream = coordinates.StreamId;
                _operationCount = coordinates.OperationCount;
                _nextOperationIndex = 0;
            }

            if (_operationStream != coordinates.StreamId
                || coordinates.OperationCount != _operationCount
                || coordinates.OperationIndex != _nextOperationIndex)
            {
                throw new EventStreamCorruptionException("The operation group is not contiguous.");
            }

            _nextOperationIndex++;
        }

        private void CompleteOperation()
        {
            if (_currentOperation is not null && _nextOperationIndex != _operationCount)
            {
                throw new EventStreamCorruptionException("The operation group is incomplete.");
            }

            _currentOperation = null;
            _operationStream = null;
            _operationCount = 0;
            _nextOperationIndex = 0;
        }

        private static void AppendInt32(IncrementalHash hash, int value)
        {
            Span<byte> bytes = stackalloc byte[sizeof(int)];
            BinaryPrimitives.WriteInt32BigEndian(bytes, value);
            hash.AppendData(bytes);
        }

        private static void AppendInt64(IncrementalHash hash, long value)
        {
            Span<byte> bytes = stackalloc byte[sizeof(long)];
            BinaryPrimitives.WriteInt64BigEndian(bytes, value);
            hash.AppendData(bytes);
        }

        private static void AppendGuid(IncrementalHash hash, Guid value)
        {
            Span<byte> bytes = stackalloc byte[16];
            if (!value.TryWriteBytes(bytes, bigEndian: true, out var written) || written != bytes.Length)
            {
                throw new EventStreamCorruptionException("A replay identifier is invalid.");
            }

            hash.AppendData(bytes);
        }

        private static string CanonicalGuidHex(Guid value)
        {
            Span<byte> bytes = stackalloc byte[16];
            value.TryWriteBytes(bytes, bigEndian: true, out _);
            return Convert.ToHexString(bytes);
        }
    }
}
