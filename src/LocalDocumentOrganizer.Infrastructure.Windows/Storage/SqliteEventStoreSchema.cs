using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class SqliteEventStoreSchema
{
    private const int CurrentVersion = 6;
    private const string VersionTwoSql = """
        CREATE TABLE event_streams(
            stream_id TEXT PRIMARY KEY CHECK(stream_id <> '00000000-0000-0000-0000-000000000000' AND length(stream_id) = 36 AND stream_id = lower(stream_id) AND substr(stream_id,9,1)='-' AND substr(stream_id,14,1)='-' AND substr(stream_id,19,1)='-' AND substr(stream_id,24,1)='-' AND length(replace(stream_id,'-','')) = 32 AND replace(stream_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            head_version INTEGER NOT NULL CHECK(head_version >= 0)
        ) STRICT;
        CREATE UNIQUE INDEX event_streams_stream_id_nocase
            ON event_streams(CAST(stream_id AS TEXT) COLLATE NOCASE);
        CREATE TABLE timeline_events(
            global_position INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL CHECK(event_id <> '00000000-0000-0000-0000-000000000000' AND length(event_id) = 36 AND event_id = lower(event_id) AND substr(event_id,9,1)='-' AND substr(event_id,14,1)='-' AND substr(event_id,19,1)='-' AND substr(event_id,24,1)='-' AND length(replace(event_id,'-','')) = 32 AND replace(event_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            stream_id TEXT NOT NULL CHECK(stream_id <> '00000000-0000-0000-0000-000000000000' AND length(stream_id) = 36 AND stream_id = lower(stream_id) AND substr(stream_id,9,1)='-' AND substr(stream_id,14,1)='-' AND substr(stream_id,19,1)='-' AND substr(stream_id,24,1)='-' AND length(replace(stream_id,'-','')) = 32 AND replace(stream_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            stream_version INTEGER NOT NULL CHECK(stream_version >= 0),
            event_type TEXT NOT NULL CHECK(length(event_type) > 0),
            schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
            recorded_at_utc TEXT NOT NULL CHECK(length(recorded_at_utc) > 0),
            operation_id TEXT NOT NULL CHECK(operation_id <> '00000000-0000-0000-0000-000000000000' AND length(operation_id) = 36 AND operation_id = lower(operation_id) AND substr(operation_id,9,1)='-' AND substr(operation_id,14,1)='-' AND substr(operation_id,19,1)='-' AND substr(operation_id,24,1)='-' AND length(replace(operation_id,'-','')) = 32 AND replace(operation_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            operation_index INTEGER NOT NULL CHECK(operation_index >= 0),
            operation_count INTEGER NOT NULL CHECK(operation_count > 0),
            protection_kind INTEGER NOT NULL CHECK(protection_kind IN (0, 1)),
            owner_kind INTEGER,
            owner_id TEXT,
            key_id TEXT,
            envelope_version INTEGER NOT NULL,
            payload_nonce BLOB,
            payload_ciphertext BLOB NOT NULL CHECK(typeof(payload_ciphertext) = 'blob'),
            payload_tag BLOB,
            UNIQUE(stream_id, stream_version),
            UNIQUE(operation_id, operation_index),
            FOREIGN KEY(stream_id) REFERENCES event_streams(stream_id),
            CHECK(operation_index < operation_count),
            CHECK(
                (protection_kind = 0
                    AND owner_kind IS NULL AND owner_id IS NULL AND key_id IS NULL
                    AND envelope_version = 0 AND payload_nonce IS NULL AND payload_tag IS NULL)
                OR
                (protection_kind = 1
                    AND owner_kind IS NOT NULL AND owner_kind IN (0, 1, 2, 3)
                    AND owner_id IS NOT NULL AND key_id IS NOT NULL
                    AND owner_id <> '00000000-0000-0000-0000-000000000000' AND length(owner_id) = 36 AND owner_id = lower(owner_id) AND substr(owner_id,9,1)='-' AND substr(owner_id,14,1)='-' AND substr(owner_id,19,1)='-' AND substr(owner_id,24,1)='-' AND length(replace(owner_id,'-','')) = 32 AND replace(owner_id,'-','') NOT GLOB '*[^0-9a-f]*'
                    AND key_id <> '00000000-0000-0000-0000-000000000000' AND length(key_id) = 36 AND key_id = lower(key_id) AND substr(key_id,9,1)='-' AND substr(key_id,14,1)='-' AND substr(key_id,19,1)='-' AND substr(key_id,24,1)='-' AND length(replace(key_id,'-','')) = 32 AND replace(key_id,'-','') NOT GLOB '*[^0-9a-f]*'
                    AND envelope_version = 1
                    AND payload_nonce IS NOT NULL AND typeof(payload_nonce) = 'blob' AND length(payload_nonce) = 12
                    AND payload_tag IS NOT NULL AND typeof(payload_tag) = 'blob' AND length(payload_tag) = 16)
            )
        ) STRICT;
        CREATE INDEX timeline_events_stream_position_nocase
            ON timeline_events(CAST(stream_id AS TEXT) COLLATE NOCASE, global_position);
        CREATE INDEX timeline_events_operation_position
            ON timeline_events(operation_id COLLATE NOCASE, global_position);
        CREATE INDEX timeline_events_operation_representation
            ON timeline_events(CAST(operation_id AS TEXT) COLLATE NOCASE, global_position);
        CREATE TABLE vault_metadata(
            singleton INTEGER PRIMARY KEY CHECK(typeof(singleton) = 'integer' AND singleton = 1),
            keyring_id BLOB NOT NULL CHECK(typeof(keyring_id) = 'blob' AND length(keyring_id) = 32)
        ) STRICT;
        CREATE TRIGGER vault_metadata_immutable_update
        BEFORE UPDATE ON vault_metadata
        BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END;
        CREATE TRIGGER vault_metadata_immutable_delete
        BEFORE DELETE ON vault_metadata
        BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END;
        CREATE TABLE projection_checkpoints(
            projection_name TEXT PRIMARY KEY,
            last_global_position INTEGER NOT NULL CHECK(last_global_position >= 0)
        ) STRICT;
        CREATE TRIGGER timeline_events_immutable_update
        BEFORE UPDATE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        CREATE TRIGGER timeline_events_immutable_delete
        BEFORE DELETE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        PRAGMA main.user_version = 2;
        """;

    private const string VersionThreeProjectionSql = """
        DROP TABLE projection_checkpoints;
        CREATE TABLE projection_checkpoints(
            projection_name TEXT PRIMARY KEY CHECK(length(projection_name) > 0),
            projection_schema_version INTEGER NOT NULL CHECK(projection_schema_version > 0),
            encryption_version INTEGER NOT NULL CHECK(encryption_version = 1),
            last_global_position INTEGER NOT NULL CHECK(last_global_position >= 0)
        ) STRICT;
        PRAGMA main.user_version = 3;
        """;

    private const string VersionFourDeletionSql = """
        CREATE TABLE secure_compaction_queue(
            owner_kind INTEGER NOT NULL CHECK(owner_kind IN (0, 1, 2, 3)),
            owner_id TEXT NOT NULL CHECK(owner_id <> '00000000-0000-0000-0000-000000000000' AND length(owner_id) = 36 AND owner_id = lower(owner_id) AND substr(owner_id,9,1)='-' AND substr(owner_id,14,1)='-' AND substr(owner_id,19,1)='-' AND substr(owner_id,24,1)='-' AND length(replace(owner_id,'-','')) = 32 AND replace(owner_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            destroyed_key_id TEXT NOT NULL CHECK(destroyed_key_id <> '00000000-0000-0000-0000-000000000000' AND length(destroyed_key_id) = 36 AND destroyed_key_id = lower(destroyed_key_id) AND substr(destroyed_key_id,9,1)='-' AND substr(destroyed_key_id,14,1)='-' AND substr(destroyed_key_id,19,1)='-' AND substr(destroyed_key_id,24,1)='-' AND length(replace(destroyed_key_id,'-','')) = 32 AND replace(destroyed_key_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            stream_id TEXT NOT NULL CHECK(stream_id <> '00000000-0000-0000-0000-000000000000' AND length(stream_id) = 36 AND stream_id = lower(stream_id) AND substr(stream_id,9,1)='-' AND substr(stream_id,14,1)='-' AND substr(stream_id,19,1)='-' AND substr(stream_id,24,1)='-' AND length(replace(stream_id,'-','')) = 32 AND replace(stream_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            tombstone_stream_version INTEGER NOT NULL CHECK(tombstone_stream_version >= 0),
            operation_id TEXT NOT NULL UNIQUE CHECK(operation_id <> '00000000-0000-0000-0000-000000000000' AND length(operation_id) = 36 AND operation_id = lower(operation_id) AND substr(operation_id,9,1)='-' AND substr(operation_id,14,1)='-' AND substr(operation_id,19,1)='-' AND substr(operation_id,24,1)='-' AND length(replace(operation_id,'-','')) = 32 AND replace(operation_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            tombstone_event_id TEXT NOT NULL UNIQUE CHECK(tombstone_event_id <> '00000000-0000-0000-0000-000000000000' AND length(tombstone_event_id) = 36 AND tombstone_event_id = lower(tombstone_event_id) AND substr(tombstone_event_id,9,1)='-' AND substr(tombstone_event_id,14,1)='-' AND substr(tombstone_event_id,19,1)='-' AND substr(tombstone_event_id,24,1)='-' AND length(replace(tombstone_event_id,'-','')) = 32 AND replace(tombstone_event_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            PRIMARY KEY(owner_kind, owner_id)
        ) STRICT;
        CREATE TRIGGER secure_compaction_queue_immutable_update
        BEFORE UPDATE ON secure_compaction_queue
        BEGIN SELECT RAISE(ABORT, 'secure_compaction_queue is immutable'); END;
        PRAGMA main.user_version = 4;
        """;

    private const string VersionFiveManagedCopiesSql = """
        DROP TRIGGER timeline_events_immutable_update;
        DROP TRIGGER timeline_events_immutable_delete;
        DROP INDEX timeline_events_stream_position_nocase;
        DROP INDEX timeline_events_operation_position;
        DROP INDEX timeline_events_operation_representation;
        ALTER TABLE timeline_events RENAME TO timeline_events_v4;
        CREATE TABLE timeline_events(
            global_position INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL CHECK(event_id <> '00000000-0000-0000-0000-000000000000' AND length(event_id) = 36 AND event_id = lower(event_id) AND substr(event_id,9,1)='-' AND substr(event_id,14,1)='-' AND substr(event_id,19,1)='-' AND substr(event_id,24,1)='-' AND length(replace(event_id,'-','')) = 32 AND replace(event_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            stream_id TEXT NOT NULL CHECK(stream_id <> '00000000-0000-0000-0000-000000000000' AND length(stream_id) = 36 AND stream_id = lower(stream_id) AND substr(stream_id,9,1)='-' AND substr(stream_id,14,1)='-' AND substr(stream_id,19,1)='-' AND substr(stream_id,24,1)='-' AND length(replace(stream_id,'-','')) = 32 AND replace(stream_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            stream_version INTEGER NOT NULL CHECK(stream_version >= 0),
            event_type TEXT NOT NULL CHECK(length(event_type) > 0),
            schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
            recorded_at_utc TEXT NOT NULL CHECK(length(recorded_at_utc) > 0),
            operation_id TEXT NOT NULL CHECK(operation_id <> '00000000-0000-0000-0000-000000000000' AND length(operation_id) = 36 AND operation_id = lower(operation_id) AND substr(operation_id,9,1)='-' AND substr(operation_id,14,1)='-' AND substr(operation_id,19,1)='-' AND substr(operation_id,24,1)='-' AND length(replace(operation_id,'-','')) = 32 AND replace(operation_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            operation_index INTEGER NOT NULL CHECK(operation_index >= 0),
            operation_count INTEGER NOT NULL CHECK(operation_count > 0),
            protection_kind INTEGER NOT NULL CHECK(protection_kind IN (0, 1)),
            owner_kind INTEGER,
            owner_id TEXT,
            key_id TEXT,
            envelope_version INTEGER NOT NULL,
            payload_nonce BLOB,
            payload_ciphertext BLOB NOT NULL CHECK(typeof(payload_ciphertext) = 'blob'),
            payload_tag BLOB,
            UNIQUE(stream_id, stream_version),
            UNIQUE(operation_id, operation_index),
            FOREIGN KEY(stream_id) REFERENCES event_streams(stream_id),
            CHECK(operation_index < operation_count),
            CHECK(
                (protection_kind = 0
                    AND owner_kind IS NULL AND owner_id IS NULL AND key_id IS NULL
                    AND envelope_version = 0 AND payload_nonce IS NULL AND payload_tag IS NULL)
                OR
                (protection_kind = 1
                    AND owner_kind IS NOT NULL AND owner_kind IN (0, 1, 2, 3)
                    AND owner_id IS NOT NULL AND key_id IS NOT NULL
                    AND owner_id <> '00000000-0000-0000-0000-000000000000' AND length(owner_id) = 36 AND owner_id = lower(owner_id) AND substr(owner_id,9,1)='-' AND substr(owner_id,14,1)='-' AND substr(owner_id,19,1)='-' AND substr(owner_id,24,1)='-' AND length(replace(owner_id,'-','')) = 32 AND replace(owner_id,'-','') NOT GLOB '*[^0-9a-f]*'
                    AND key_id <> '00000000-0000-0000-0000-000000000000' AND length(key_id) = 36 AND key_id = lower(key_id) AND substr(key_id,9,1)='-' AND substr(key_id,14,1)='-' AND substr(key_id,19,1)='-' AND substr(key_id,24,1)='-' AND length(replace(key_id,'-','')) = 32 AND replace(key_id,'-','') NOT GLOB '*[^0-9a-f]*'
                    AND envelope_version = 1
                    AND payload_nonce IS NOT NULL AND typeof(payload_nonce) = 'blob'
                    AND payload_tag IS NOT NULL AND typeof(payload_tag) = 'blob'
                    AND (
                        (length(payload_nonce) = 12 AND length(payload_tag) = 16)
                        OR
                        (length(payload_nonce) = 0 AND length(payload_ciphertext) = 0
                            AND length(payload_tag) = 0)))
            )
        ) STRICT;
        INSERT INTO timeline_events(
            global_position,event_id,stream_id,stream_version,event_type,schema_version,
            recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,
            owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag)
        SELECT global_position,event_id,stream_id,stream_version,event_type,schema_version,
            recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,
            owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag
        FROM timeline_events_v4 ORDER BY global_position;
        DROP TABLE timeline_events_v4;
        CREATE INDEX timeline_events_stream_position_nocase
            ON timeline_events(CAST(stream_id AS TEXT) COLLATE NOCASE, global_position);
        CREATE INDEX timeline_events_operation_position
            ON timeline_events(operation_id COLLATE NOCASE, global_position);
        CREATE INDEX timeline_events_operation_representation
            ON timeline_events(CAST(operation_id AS TEXT) COLLATE NOCASE, global_position);
        CREATE TRIGGER timeline_events_immutable_update
        BEFORE UPDATE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        CREATE TRIGGER timeline_events_immutable_delete
        BEFORE DELETE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        CREATE TABLE managed_vault_copies(
            copy_id TEXT PRIMARY KEY CHECK(
                length(copy_id) = 32
                AND copy_id = lower(copy_id)
                AND copy_id NOT GLOB '*[^0-9a-f]*'
                AND copy_id <> '00000000000000000000000000000000')
        ) STRICT;
        CREATE TRIGGER managed_vault_copies_immutable_update
        BEFORE UPDATE ON managed_vault_copies
        BEGIN SELECT RAISE(ABORT, 'managed_vault_copies is immutable'); END;
        PRAGMA main.user_version = 5;
        """;

    private const string VersionSixOperationJournalSql = """
        CREATE TABLE operation_journal(
            operation_id TEXT PRIMARY KEY CHECK(operation_id <> '00000000-0000-0000-0000-000000000000' AND length(operation_id) = 36 AND operation_id = lower(operation_id) AND substr(operation_id,9,1)='-' AND substr(operation_id,14,1)='-' AND substr(operation_id,19,1)='-' AND substr(operation_id,24,1)='-' AND length(replace(operation_id,'-','')) = 32 AND replace(operation_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            operation_kind INTEGER NOT NULL CHECK(operation_kind IN (0, 1, 2, 3)),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)),
            revision INTEGER NOT NULL CHECK(revision > 0),
            source_health INTEGER NOT NULL CHECK(source_health IN (0, 1, 2, 3, 4, 5, 6)),
            owner_kind INTEGER NOT NULL CHECK(owner_kind IN (0, 1, 2, 3)),
            owner_id TEXT NOT NULL CHECK(owner_id <> '00000000-0000-0000-0000-000000000000' AND length(owner_id) = 36 AND owner_id = lower(owner_id) AND substr(owner_id,9,1)='-' AND substr(owner_id,14,1)='-' AND substr(owner_id,19,1)='-' AND substr(owner_id,24,1)='-' AND length(replace(owner_id,'-','')) = 32 AND replace(owner_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            key_id TEXT NOT NULL CHECK(key_id <> '00000000-0000-0000-0000-000000000000' AND length(key_id) = 36 AND key_id = lower(key_id) AND substr(key_id,9,1)='-' AND substr(key_id,14,1)='-' AND substr(key_id,19,1)='-' AND substr(key_id,24,1)='-' AND length(replace(key_id,'-','')) = 32 AND replace(key_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            envelope_version INTEGER NOT NULL CHECK(envelope_version = 1),
            payload_schema_version INTEGER NOT NULL CHECK(payload_schema_version > 0),
            payload_nonce BLOB NOT NULL CHECK(typeof(payload_nonce) = 'blob' AND length(payload_nonce) = 12),
            payload_ciphertext BLOB NOT NULL CHECK(typeof(payload_ciphertext) = 'blob' AND length(payload_ciphertext) > 0),
            payload_tag BLOB NOT NULL CHECK(typeof(payload_tag) = 'blob' AND length(payload_tag) = 16),
            created_at_utc TEXT NOT NULL CHECK(typeof(created_at_utc) = 'text' AND length(created_at_utc) = 28 AND substr(created_at_utc,5,1)='-' AND substr(created_at_utc,8,1)='-' AND substr(created_at_utc,11,1)='T' AND substr(created_at_utc,14,1)=':' AND substr(created_at_utc,17,1)=':' AND substr(created_at_utc,20,1)='.' AND substr(created_at_utc,28,1)='Z' AND substr(created_at_utc,1,4) NOT GLOB '*[^0-9]*' AND substr(created_at_utc,6,2) NOT GLOB '*[^0-9]*' AND substr(created_at_utc,9,2) NOT GLOB '*[^0-9]*' AND substr(created_at_utc,12,2) NOT GLOB '*[^0-9]*' AND substr(created_at_utc,15,2) NOT GLOB '*[^0-9]*' AND substr(created_at_utc,18,2) NOT GLOB '*[^0-9]*' AND substr(created_at_utc,21,7) NOT GLOB '*[^0-9]*' AND julianday(created_at_utc) IS NOT NULL),
            updated_at_utc TEXT NOT NULL CHECK(typeof(updated_at_utc) = 'text' AND length(updated_at_utc) = 28 AND substr(updated_at_utc,5,1)='-' AND substr(updated_at_utc,8,1)='-' AND substr(updated_at_utc,11,1)='T' AND substr(updated_at_utc,14,1)=':' AND substr(updated_at_utc,17,1)=':' AND substr(updated_at_utc,20,1)='.' AND substr(updated_at_utc,28,1)='Z' AND substr(updated_at_utc,1,4) NOT GLOB '*[^0-9]*' AND substr(updated_at_utc,6,2) NOT GLOB '*[^0-9]*' AND substr(updated_at_utc,9,2) NOT GLOB '*[^0-9]*' AND substr(updated_at_utc,12,2) NOT GLOB '*[^0-9]*' AND substr(updated_at_utc,15,2) NOT GLOB '*[^0-9]*' AND substr(updated_at_utc,18,2) NOT GLOB '*[^0-9]*' AND substr(updated_at_utc,21,7) NOT GLOB '*[^0-9]*' AND julianday(updated_at_utc) IS NOT NULL),
            CHECK(updated_at_utc >= created_at_utc)
        ) STRICT;
        CREATE TABLE operation_side_effects(
            operation_id TEXT NOT NULL CHECK(operation_id <> '00000000-0000-0000-0000-000000000000' AND length(operation_id) = 36 AND operation_id = lower(operation_id) AND substr(operation_id,9,1)='-' AND substr(operation_id,14,1)='-' AND substr(operation_id,19,1)='-' AND substr(operation_id,24,1)='-' AND length(replace(operation_id,'-','')) = 32 AND replace(operation_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            effect_index INTEGER NOT NULL CHECK(effect_index >= 0),
            effect_code TEXT NOT NULL CHECK(length(effect_code) BETWEEN 1 AND 64 AND effect_code = lower(effect_code) AND effect_code NOT GLOB '*[^a-z0-9-]*'),
            state INTEGER NOT NULL CHECK(state IN (0, 1)),
            PRIMARY KEY(operation_id, effect_index),
            FOREIGN KEY(operation_id) REFERENCES operation_journal(operation_id)
        ) STRICT;
        CREATE TABLE operation_usage_ledger(
            operation_id TEXT PRIMARY KEY CHECK(operation_id <> '00000000-0000-0000-0000-000000000000' AND length(operation_id) = 36 AND operation_id = lower(operation_id) AND substr(operation_id,9,1)='-' AND substr(operation_id,14,1)='-' AND substr(operation_id,19,1)='-' AND substr(operation_id,24,1)='-' AND length(replace(operation_id,'-','')) = 32 AND replace(operation_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            usage_code TEXT NOT NULL CHECK(length(usage_code) BETWEEN 1 AND 64 AND usage_code = lower(usage_code) AND usage_code NOT GLOB '*[^a-z0-9-]*'),
            units INTEGER NOT NULL CHECK(units > 0),
            FOREIGN KEY(operation_id) REFERENCES operation_journal(operation_id)
        ) STRICT;
        CREATE TRIGGER operation_journal_identity_immutable_update
        BEFORE UPDATE ON operation_journal
        WHEN NEW.operation_id IS NOT OLD.operation_id
          OR NEW.operation_kind IS NOT OLD.operation_kind
          OR NEW.owner_kind IS NOT OLD.owner_kind
          OR NEW.owner_id IS NOT OLD.owner_id
          OR NEW.key_id IS NOT OLD.key_id
          OR NEW.envelope_version IS NOT OLD.envelope_version
          OR NEW.payload_schema_version IS NOT OLD.payload_schema_version
          OR NEW.created_at_utc IS NOT OLD.created_at_utc
        BEGIN SELECT RAISE(ABORT, 'operation_journal identity is immutable'); END;
        CREATE TRIGGER operation_journal_update_guard
        BEFORE UPDATE ON operation_journal
        WHEN NEW.revision <> OLD.revision + 1
          OR NEW.updated_at_utc <= OLD.updated_at_utc
          OR NEW.payload_nonce = OLD.payload_nonce
          OR NOT (
            (OLD.operation_kind IN (0, 1) AND (
                (OLD.state = 0 AND NEW.state = 1)
                OR (OLD.state = 1 AND NEW.state = 2)
                OR (OLD.state = 2 AND NEW.state = 7)
                OR (OLD.state = 7 AND NEW.state = 8)
                OR (OLD.state = 8 AND NEW.state = 9)
                OR (OLD.state = 9 AND NEW.state = 10)))
            OR
            (OLD.operation_kind IN (2, 3) AND (
                (OLD.state = 0 AND NEW.state = 1)
                OR (OLD.state = 1 AND NEW.state = 3)
                OR (OLD.state = 3 AND NEW.state = 4)
                OR (OLD.state = 4 AND NEW.state = 5)
                OR (OLD.state = 5 AND NEW.state = 6)
                OR (OLD.state = 6 AND NEW.state = 7)
                OR (OLD.state = 7 AND NEW.state = 8)
                OR (OLD.state = 8 AND NEW.state = 9)
                OR (OLD.state = 9 AND NEW.state = 10)))
            OR (OLD.state BETWEEN 0 AND 9 AND NEW.state = 11)
        )
        BEGIN SELECT RAISE(ABORT, 'operation_journal transition is invalid'); END;
        CREATE TRIGGER operation_journal_immutable_delete
        BEFORE DELETE ON operation_journal
        BEGIN SELECT RAISE(ABORT, 'operation_journal is immutable'); END;
        CREATE TRIGGER operation_side_effects_state_only_update
        BEFORE UPDATE ON operation_side_effects
        WHEN NEW.operation_id IS NOT OLD.operation_id
          OR NEW.effect_index IS NOT OLD.effect_index
          OR NEW.effect_code IS NOT OLD.effect_code
          OR OLD.state <> 0
          OR NEW.state <> 1
        BEGIN SELECT RAISE(ABORT, 'operation_side_effects allow one state transition only'); END;
        CREATE TRIGGER operation_side_effects_immutable_delete
        BEFORE DELETE ON operation_side_effects
        BEGIN SELECT RAISE(ABORT, 'operation_side_effects are immutable'); END;
        CREATE TRIGGER operation_usage_ledger_immutable_update
        BEFORE UPDATE ON operation_usage_ledger
        BEGIN SELECT RAISE(ABORT, 'operation_usage_ledger is immutable'); END;
        CREATE TRIGGER operation_usage_ledger_immutable_delete
        BEFORE DELETE ON operation_usage_ledger
        BEGIN SELECT RAISE(ABORT, 'operation_usage_ledger is immutable'); END;
        PRAGMA main.user_version = 6;
        """;

    private const string VersionOneSql = """
        CREATE TABLE event_streams(
            stream_id TEXT PRIMARY KEY,
            head_version INTEGER NOT NULL CHECK(head_version >= 0)
        );
        CREATE TABLE timeline_events(
            global_position INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            stream_id TEXT NOT NULL,
            stream_version INTEGER NOT NULL CHECK(stream_version >= 0),
            event_type TEXT NOT NULL,
            schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
            recorded_at_utc TEXT NOT NULL,
            payload_json BLOB NOT NULL,
            UNIQUE(stream_id, stream_version),
            FOREIGN KEY(stream_id) REFERENCES event_streams(stream_id)
        );
        CREATE TABLE projection_checkpoints(
            projection_name TEXT PRIMARY KEY,
            last_global_position INTEGER NOT NULL CHECK(last_global_position >= 0)
        );
        CREATE TABLE event_operation_ids(
            event_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES timeline_events(event_id)
        );
        CREATE TRIGGER timeline_events_immutable_update
        BEFORE UPDATE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        CREATE TRIGGER timeline_events_immutable_delete
        BEFORE DELETE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        CREATE TRIGGER event_operation_ids_immutable_update
        BEFORE UPDATE ON event_operation_ids
        BEGIN SELECT RAISE(ABORT, 'event_operation_ids is immutable'); END;
        CREATE TRIGGER event_operation_ids_immutable_delete
        BEFORE DELETE ON event_operation_ids
        BEGIN SELECT RAISE(ABORT, 'event_operation_ids is immutable'); END;
        PRAGMA main.user_version = 1;
        """;

    public static async Task InitializeAsync(
        string connectionString,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        CancellationToken cancellationToken)
    {
        ValidateConnectionString(connectionString);
        ValidateVaultPath(connectionString, keyRing.MaintenanceGate);
        await using var lease = await keyRing.MaintenanceGate
            .AcquireMutationAsync(cancellationToken)
            .ConfigureAwait(false);
        await InitializeAsync(
            connectionString,
            projections,
            keyRing,
            lease,
            cancellationToken).ConfigureAwait(false);
    }

    internal static async Task InitializeAsync(
        string connectionString,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ValidateConnectionString(connectionString);
        ValidateVaultPath(connectionString, keyRing.MaintenanceGate);
        keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        VaultSchemaInspection inspection;
        inspection = await InspectBeforeMutationAsync(connectionString, cancellationToken);

        if (inspection.Kind == VaultSchemaKind.LegacyProjection)
        {
            throw new LegacyProjectionRecoveryRequiredException();
        }

        if (inspection.Kind == VaultSchemaKind.LegacyNonEmpty)
        {
            throw new LegacyPlaintextVaultRecoveryRequiredException();
        }

        if (inspection.Kind is VaultSchemaKind.Unknown or VaultSchemaKind.Malformed)
        {
            throw new VaultRecoveryRequiredException();
        }

        VaultKeyRing bootstrapRing;
        if (inspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1)
        {
            try
            {
                try { bootstrapRing = await keyRing.CreateAsync(lease, cancellationToken); }
                catch (VaultKeyRingPersistenceException) { bootstrapRing = await keyRing.OpenAsync(cancellationToken); }
            }
            catch (VaultKeyRingException exception)
            {
                throw new VaultRecoveryRequiredException(exception);
            }
            if (!IsEmpty(bootstrapRing)) throw new VaultRecoveryRequiredException();
        }
        else
        {
            try { bootstrapRing = await keyRing.OpenAsync(cancellationToken); }
            catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }
        }

        if (inspection.Kind is VaultSchemaKind.V6 or VaultSchemaKind.V5
            or VaultSchemaKind.V4 or VaultSchemaKind.V3
            or VaultSchemaKind.EligibleV2)
            RequireKeyRingIdentity(inspection.KeyRingIdentity, bootstrapRing.Identity);

        try { await keyRing.EnsureCurrentFormatAsync(lease, cancellationToken); }
        catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }
        VaultKeyRing ringBeforeDatabaseOpen;
        try { ringBeforeDatabaseOpen = await keyRing.OpenAsync(cancellationToken); }
        catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }
        RequireKeyRingIdentity(bootstrapRing.Identity, ringBeforeDatabaseOpen.Identity);
        if (inspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1
            && !IsEmpty(ringBeforeDatabaseOpen))
        {
            throw new VaultRecoveryRequiredException();
        }

        var preOpenInspection = await InspectBeforeMutationAsync(
            connectionString, cancellationToken);
        RequireCompatiblePreOpenInspection(
            inspection, preOpenInspection, ringBeforeDatabaseOpen.Identity);
        if (preOpenInspection.Kind is VaultSchemaKind.EligibleV2
            or VaultSchemaKind.V3
            or VaultSchemaKind.V4
            or VaultSchemaKind.V5
            or VaultSchemaKind.V6)
        {
            await ValidateSourceAndRecoverMigrationArtifactsAsync(
                connectionString,
                projections,
                keyRing,
                lease,
                ringBeforeDatabaseOpen,
                preOpenInspection.Kind,
                cancellationToken).ConfigureAwait(false);
        }
        if (preOpenInspection.Kind is VaultSchemaKind.EligibleV2
            or VaultSchemaKind.V3
            or VaultSchemaKind.V4)
        {
            await MigrateExistingVaultToVersionFiveAsync(
                connectionString,
                projections,
                keyRing,
                lease,
                ringBeforeDatabaseOpen,
                preOpenInspection.Kind,
                cancellationToken).ConfigureAwait(false);
            preOpenInspection = await InspectBeforeMutationAsync(
                connectionString,
                cancellationToken).ConfigureAwait(false);
            if (preOpenInspection.Kind != VaultSchemaKind.V6)
                throw new VaultRecoveryRequiredException();
            RequireKeyRingIdentity(
                preOpenInspection.KeyRingIdentity,
                ringBeforeDatabaseOpen.Identity);
        }

        await using var connection = await OpenConnectionAsync(
            connectionString, keyRing.MaintenanceGate, cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        try
        {
            var finalInspection = await InspectInsideTransactionAsync(connection, transaction, cancellationToken);
            if (finalInspection.Kind == VaultSchemaKind.LegacyProjection)
                throw new LegacyProjectionRecoveryRequiredException();
            if (finalInspection.Kind is VaultSchemaKind.Unknown or VaultSchemaKind.Malformed or VaultSchemaKind.LegacyNonEmpty)
                throw new VaultRecoveryRequiredException();
            RequireCompatibleFinalInspection(preOpenInspection, finalInspection);

            VaultKeyRing authoritativeRing;
            try { authoritativeRing = await keyRing.OpenAsync(cancellationToken); }
            catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }
            RequireKeyRingIdentity(ringBeforeDatabaseOpen.Identity, authoritativeRing.Identity);
            if (finalInspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1)
            {
                if (!IsEmpty(authoritativeRing)
                    || !bootstrapRing.Identity.FixedTimeEquals(authoritativeRing.Identity))
                {
                    throw new VaultRecoveryRequiredException();
                }
            }
            else
            {
                RequireKeyRingIdentity(finalInspection.KeyRingIdentity, authoritativeRing.Identity);
            }

            if (finalInspection.Kind == VaultSchemaKind.EmptyV1)
            {
                await DropVersionOneCoreAsync(connection, transaction, cancellationToken);
            }

            if (finalInspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1)
            {
                await ExecuteNonQueryAsync(connection, transaction, VersionTwoSql, cancellationToken);
                await ExecuteNonQueryAsync(
                    connection, transaction, VersionThreeProjectionSql, cancellationToken);
                await ExecuteNonQueryAsync(
                    connection, transaction, VersionFourDeletionSql, cancellationToken);
                await ExecuteNonQueryAsync(
                    connection, transaction, VersionFiveManagedCopiesSql, cancellationToken);
                await ExecuteNonQueryAsync(
                    connection, transaction, VersionSixOperationJournalSql, cancellationToken);
                await InsertKeyRingIdentityAsync(
                    connection, transaction, authoritativeRing.Identity, cancellationToken);
            }
            else if (finalInspection.Kind is VaultSchemaKind.EligibleV2
                or VaultSchemaKind.V3
                or VaultSchemaKind.V4)
                throw new VaultRecoveryRequiredException();
            else if (finalInspection.Kind == VaultSchemaKind.V5)
            {
                await ExecuteNonQueryAsync(
                    connection,
                    transaction,
                    VersionSixOperationJournalSql,
                    cancellationToken);
                await ValidateExistingVersionThreeAsync(
                    connection,
                    transaction,
                    cancellationToken);
            }
            else
            {
                await ValidateExistingVersionThreeAsync(connection, transaction, cancellationToken);
            }

            foreach (var registration in projections.Registrations)
            {
                var projection = registration.Projection;
                var compatibility = await SqliteProjectionAuthorizer.RunAsync(
                    connection,
                    registration,
                    projections.AllowsLegacyTestObjects,
                    () => projection.InitializeAsync(
                        SqliteProjectionContexts.CreateAdministrative(
                            connection,
                            transaction,
                            keyRing,
                            lease,
                            registration),
                        cancellationToken));
                if (!Enum.IsDefined(compatibility.Compatibility))
                    throw new VaultRecoveryRequiredException();
                if (compatibility.RequiresCheckpointInvalidation)
                {
                    await SqliteProjectionCheckpointStore.ClearAsync(
                        connection,
                        transaction,
                        [registration],
                        cancellationToken);
                }
            }

            await ValidateProjectionMembershipAsync(
                connection, transaction, projections, cancellationToken);

            await ValidateExistingVersionThreeAsync(connection, transaction, cancellationToken);
            await SqliteEventStore.ValidateAllOperationMetadataAsync(connection, transaction, cancellationToken);
            await ValidateCurrentKeyRingIdentityAsync(
                keyRing, authoritativeRing.Identity, cancellationToken);
            await ValidateKeyRingIdentityAsync(
                connection, transaction, authoritativeRing.Identity, cancellationToken);
            ValidateVaultPath(connectionString, keyRing.MaintenanceGate);
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await RollbackWithoutMaskingAsync(transaction);
            throw;
        }
    }

    private static bool IsEmpty(VaultKeyRing ring) =>
        ring.ActiveKeys.Count == 0 && ring.DestroyedReceipts.Count == 0;

    private static async Task ValidateSourceAndRecoverMigrationArtifactsAsync(
        string connectionString,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        VaultKeyRing authoritativeRing,
        VaultSchemaKind sourceKind,
        CancellationToken cancellationToken)
    {
        keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        var canonical = CanonicalizeConnectionString(connectionString);
        var path = Path.GetFullPath(
            new SqliteConnectionStringBuilder(canonical).DataSource);
        await using var source = await OpenConnectionAsync(
            canonical,
            keyRing.MaintenanceGate,
            cancellationToken).ConfigureAwait(false);
        await using var transaction = source.BeginTransaction(deferred: true);
        if (sourceKind == VaultSchemaKind.V6)
        {
            await ValidateExistingVersionThreeAsync(
                source,
                transaction,
                cancellationToken).ConfigureAwait(false);
        }
        else if (sourceKind == VaultSchemaKind.V5)
        {
            await ValidateLegacyVersionFiveAsync(
                source,
                transaction,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await ValidateLegacyMigrationSourceAsync(
                source,
                transaction,
                sourceKind,
                cancellationToken).ConfigureAwait(false);
        }
        await ValidateProjectionMembershipAsync(
            source,
            transaction,
            projections,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStore.ValidateAllOperationMetadataAsync(
            source,
            transaction,
            cancellationToken).ConfigureAwait(false);
        await ValidateKeyRingIdentityAsync(
            source,
            transaction,
            authoritativeRing.Identity,
            cancellationToken).ConfigureAwait(false);
        await ValidateCurrentKeyRingIdentityAsync(
            keyRing,
            authoritativeRing.Identity,
            cancellationToken).ConfigureAwait(false);
        await SqliteSecureCompactor.ValidateProtectedKeyStateAsync(
            source,
            transaction,
            authoritativeRing,
            cancellationToken,
            allowPendingReceipts: true).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        await source.DisposeAsync().ConfigureAwait(false);
        await RecoverMigrationArtifactsAsync(path, cancellationToken).ConfigureAwait(false);
    }

    private static async Task MigrateExistingVaultToVersionFiveAsync(
        string connectionString,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        VaultKeyRing authoritativeRing,
        VaultSchemaKind sourceKind,
        CancellationToken cancellationToken)
    {
        keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        if (sourceKind is not (VaultSchemaKind.EligibleV2
            or VaultSchemaKind.V3
            or VaultSchemaKind.V4))
        {
            throw new VaultRecoveryRequiredException();
        }

        var canonical = CanonicalizeConnectionString(connectionString);
        var path = Path.GetFullPath(
            new SqliteConnectionStringBuilder(canonical).DataSource);
        var artifact = Path.Combine(
            Path.GetDirectoryName(path)!,
            Path.GetFileName(path)
            + ".schema-migration-"
            + Guid.NewGuid().ToString("N")
            + ".tmp");
        WindowsVaultPathGuard.RequireSafeDatabaseSet(artifact);
        var published = false;
        try
        {
            await using var source = await OpenConnectionAsync(
                canonical,
                keyRing.MaintenanceGate,
                cancellationToken).ConfigureAwait(false);
            await using var sourceTransaction = source.BeginTransaction(deferred: true);
            await ValidateLegacyMigrationSourceAsync(
                source,
                sourceTransaction,
                sourceKind,
                cancellationToken).ConfigureAwait(false);
            await ValidateProjectionMembershipAsync(
                source,
                sourceTransaction,
                projections,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStore.ValidateAllOperationMetadataAsync(
                source,
                sourceTransaction,
                cancellationToken).ConfigureAwait(false);
            await ValidateKeyRingIdentityAsync(
                source,
                sourceTransaction,
                authoritativeRing.Identity,
                cancellationToken).ConfigureAwait(false);
            await ValidateCurrentKeyRingIdentityAsync(
                keyRing,
                authoritativeRing.Identity,
                cancellationToken).ConfigureAwait(false);
            await SqliteSecureCompactor.ValidateProtectedKeyStateAsync(
                source,
                sourceTransaction,
                authoritativeRing,
                cancellationToken,
                allowPendingReceipts: true).ConfigureAwait(false);

            await using (var reservation = new FileStream(
                artifact,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(
                    artifact,
                    reservation.SafeFileHandle);
                await reservation.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            {
                await using var destination = await OpenConnectionAsync(
                    ConnectionStringForPath(artifact),
                    maintenanceGate: null,
                    cancellationToken).ConfigureAwait(false);
                source.BackupDatabase(destination);
                await using var destinationTransaction =
                    destination.BeginTransaction(deferred: false);
                if (sourceKind == VaultSchemaKind.EligibleV2)
                {
                    await ExecuteNonQueryAsync(
                        destination,
                        destinationTransaction,
                        VersionThreeProjectionSql,
                        cancellationToken).ConfigureAwait(false);
                }
                if (sourceKind is VaultSchemaKind.EligibleV2 or VaultSchemaKind.V3)
                {
                    await ExecuteNonQueryAsync(
                        destination,
                        destinationTransaction,
                        VersionFourDeletionSql,
                        cancellationToken).ConfigureAwait(false);
                }
                await ExecuteNonQueryAsync(
                    destination,
                    destinationTransaction,
                    VersionFiveManagedCopiesSql,
                    cancellationToken).ConfigureAwait(false);
                await ExecuteNonQueryAsync(
                    destination,
                    destinationTransaction,
                    VersionSixOperationJournalSql,
                    cancellationToken).ConfigureAwait(false);
                await ValidateExistingVersionThreeAsync(
                    destination,
                    destinationTransaction,
                    cancellationToken).ConfigureAwait(false);
                await ValidateProjectionMembershipAsync(
                    destination,
                    destinationTransaction,
                    projections,
                    cancellationToken).ConfigureAwait(false);
                await SqliteEventStore.ValidateAllOperationMetadataAsync(
                    destination,
                    destinationTransaction,
                    cancellationToken).ConfigureAwait(false);
                await ValidateKeyRingIdentityAsync(
                    destination,
                    destinationTransaction,
                    authoritativeRing.Identity,
                    cancellationToken).ConfigureAwait(false);
                await RequireMigrationRowsEquivalentAsync(
                    source,
                    sourceTransaction,
                    destination,
                    destinationTransaction,
                    sourceKind,
                    cancellationToken).ConfigureAwait(false);
                await ProjectionRebuildWorkspace.RequireProjectionStateEquivalentAsync(
                    source,
                    sourceTransaction,
                    destination,
                    destinationTransaction,
                    projections,
                    keyRing,
                    lease,
                    cancellationToken).ConfigureAwait(false);
                await RequireForeignKeyIntegrityAsync(
                    destination,
                    destinationTransaction,
                    cancellationToken).ConfigureAwait(false);
                await destinationTransaction.CommitAsync(cancellationToken)
                    .ConfigureAwait(false);
                await sourceTransaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                await RequireCheckpointAsync(source, cancellationToken).ConfigureAwait(false);
                await RequireCheckpointAsync(destination, cancellationToken).ConfigureAwait(false);
                await RequireJournalModeAsync(
                    destination,
                    "delete",
                    cancellationToken).ConfigureAwait(false);
                await RequireIntegrityAsync(destination, cancellationToken).ConfigureAwait(false);
            }

            await sourceTransaction.DisposeAsync().ConfigureAwait(false);
            await source.DisposeAsync().ConfigureAwait(false);
            SqliteConnection.ClearAllPools();
            await RequireNoSidecarsAsync(path, cancellationToken).ConfigureAwait(false);
            await RequireNoSidecarsAsync(artifact, cancellationToken).ConfigureAwait(false);
            File.Replace(artifact, path, destinationBackupFileName: null);
            published = true;

            await using var verification = await OpenConnectionAsync(
                canonical,
                keyRing.MaintenanceGate,
                CancellationToken.None).ConfigureAwait(false);
            await using var verificationTransaction =
                verification.BeginTransaction(deferred: true);
            await ValidateExistingVersionThreeAsync(
                verification,
                verificationTransaction,
                CancellationToken.None).ConfigureAwait(false);
            await ValidateProjectionMembershipAsync(
                verification,
                verificationTransaction,
                projections,
                CancellationToken.None).ConfigureAwait(false);
            await SqliteEventStore.ValidateAllOperationMetadataAsync(
                verification,
                verificationTransaction,
                CancellationToken.None).ConfigureAwait(false);
            await ValidateKeyRingIdentityAsync(
                verification,
                verificationTransaction,
                authoritativeRing.Identity,
                CancellationToken.None).ConfigureAwait(false);
            await ValidateCurrentKeyRingIdentityAsync(
                keyRing,
                authoritativeRing.Identity,
                CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            if (!published)
            {
                SqliteConnection.ClearAllPools();
                await TrySecurelyDeleteDatabaseSetAsync(artifact).ConfigureAwait(false);
            }
            throw;
        }
    }

    private static async Task ValidateLegacyMigrationSourceAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultSchemaKind sourceKind,
        CancellationToken cancellationToken)
    {
        if (sourceKind == VaultSchemaKind.EligibleV2)
        {
            await ValidateEligibleVersionTwoAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            return;
        }
        if (sourceKind == VaultSchemaKind.V3)
        {
            await ValidateLegacyVersionThreeAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            return;
        }
        if (sourceKind == VaultSchemaKind.V4)
        {
            await ValidateLegacyVersionFourAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            return;
        }
        throw new VaultRecoveryRequiredException();
    }

    private static async Task RequireMigrationRowsEquivalentAsync(
        SqliteConnection source,
        SqliteTransaction sourceTransaction,
        SqliteConnection destination,
        SqliteTransaction destinationTransaction,
        VaultSchemaKind sourceKind,
        CancellationToken cancellationToken)
    {
        await RequireQueryEquivalentAsync(
            source,
            sourceTransaction,
            destination,
            destinationTransaction,
            "SELECT stream_id,head_version FROM main.event_streams ORDER BY stream_id COLLATE BINARY;",
            cancellationToken).ConfigureAwait(false);
        await RequireQueryEquivalentAsync(
            source,
            sourceTransaction,
            destination,
            destinationTransaction,
            """
            SELECT global_position,event_id,stream_id,stream_version,event_type,schema_version,
                   recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,
                   owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag
            FROM main.timeline_events ORDER BY global_position;
            """,
            cancellationToken).ConfigureAwait(false);
        if (sourceKind is VaultSchemaKind.V3 or VaultSchemaKind.V4)
        {
            await RequireQueryEquivalentAsync(
                source,
                sourceTransaction,
                destination,
                destinationTransaction,
                """
                SELECT projection_name,projection_schema_version,encryption_version,last_global_position
                FROM main.projection_checkpoints ORDER BY projection_name COLLATE BINARY;
                """,
                cancellationToken).ConfigureAwait(false);
        }
        if (sourceKind == VaultSchemaKind.V4)
        {
            await RequireQueryEquivalentAsync(
                source,
                sourceTransaction,
                destination,
                destinationTransaction,
                """
                SELECT owner_kind,owner_id,destroyed_key_id,stream_id,tombstone_stream_version,
                       operation_id,tombstone_event_id
                FROM main.secure_compaction_queue
                ORDER BY owner_kind,owner_id COLLATE BINARY;
                """,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task RequireQueryEquivalentAsync(
        SqliteConnection source,
        SqliteTransaction sourceTransaction,
        SqliteConnection destination,
        SqliteTransaction destinationTransaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var sourceCommand = source.CreateCommand();
        sourceCommand.Transaction = sourceTransaction;
        sourceCommand.CommandText = sql;
        await using var destinationCommand = destination.CreateCommand();
        destinationCommand.Transaction = destinationTransaction;
        destinationCommand.CommandText = sql;
        await using var sourceReader = await sourceCommand.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var destinationReader = await destinationCommand
            .ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (true)
        {
            var sourceHasRow = await sourceReader.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            var destinationHasRow = await destinationReader.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            if (sourceHasRow != destinationHasRow)
                throw new VaultRecoveryRequiredException();
            if (!sourceHasRow) break;
            if (sourceReader.FieldCount != destinationReader.FieldCount)
                throw new VaultRecoveryRequiredException();
            for (var index = 0; index < sourceReader.FieldCount; index++)
            {
                var left = sourceReader.GetValue(index);
                var right = destinationReader.GetValue(index);
                var equal = left is byte[] leftBytes && right is byte[] rightBytes
                    ? leftBytes.AsSpan().SequenceEqual(rightBytes)
                    : Equals(left, right);
                if (!equal) throw new VaultRecoveryRequiredException();
            }
        }
    }

    private static async Task RequireForeignKeyIntegrityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA main.foreign_key_check;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            throw new VaultRecoveryRequiredException();
    }

    private static async Task RequireIntegrityAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA main.integrity_check;";
        if (!string.Equals(
            await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string,
            "ok",
            StringComparison.Ordinal))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    internal static async Task RequireCheckpointAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA main.wal_checkpoint(TRUNCATE);";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            || reader.GetValue(0) is not long busy
            || busy != 0
            || await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    internal static async Task RequireJournalModeAsync(
        SqliteConnection connection,
        string expected,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA main.journal_mode={expected};";
        var actual = Convert.ToString(
            await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            System.Globalization.CultureInfo.InvariantCulture);
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            throw new VaultRecoveryRequiredException();
    }

    private static async Task RequireNoSidecarsAsync(
        string path,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 40; attempt++)
        {
            if (!File.Exists(path + "-wal") && !File.Exists(path + "-shm")) return;
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken)
                .ConfigureAwait(false);
        }
        throw new VaultRecoveryRequiredException();
    }

    private static async Task RecoverMigrationArtifactsAsync(
        string databasePath,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(databasePath)!;
        if (!Directory.Exists(directory)) return;
        var prefix = Path.GetFileName(databasePath) + ".schema-migration-";
        var entries = Directory.EnumerateFileSystemEntries(
                directory,
                prefix + "*",
                SearchOption.TopDirectoryOnly)
            .ToArray();
        var groups = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        try
        {
            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (Directory.Exists(entry))
                    throw new VaultRecoveryRequiredException();
                WindowsVaultPathGuard.RequireSafeForOpen(entry);
                var name = Path.GetFileName(entry);
                var sidecar = name.EndsWith("-journal", StringComparison.Ordinal)
                    ? "-journal"
                    : name.EndsWith("-wal", StringComparison.Ordinal)
                        ? "-wal"
                        : name.EndsWith("-shm", StringComparison.Ordinal)
                            ? "-shm"
                            : string.Empty;
                var core = sidecar.Length == 0
                    ? name
                    : name[..^sidecar.Length];
                if (!core.StartsWith(prefix, StringComparison.Ordinal)
                    || !core.EndsWith(".tmp", StringComparison.Ordinal)
                    || core.Length != prefix.Length + 32 + ".tmp".Length
                    || core.AsSpan(prefix.Length, 32).IndexOfAnyExcept(
                        "0123456789abcdef".AsSpan()) >= 0)
                {
                    throw new VaultRecoveryRequiredException();
                }
                var basePath = Path.Combine(directory, core);
                if (!groups.TryGetValue(basePath, out var suffixes))
                {
                    suffixes = new HashSet<string>(StringComparer.Ordinal);
                    groups.Add(basePath, suffixes);
                }
                if (!suffixes.Add(sidecar))
                    throw new VaultRecoveryRequiredException();
            }

            foreach (var (_, suffixes) in groups)
            {
                if (!suffixes.Contains(string.Empty)
                    || suffixes.Contains("-shm") && !suffixes.Contains("-wal")
                    || suffixes.Contains("-journal")
                        && (suffixes.Contains("-wal") || suffixes.Contains("-shm")))
                {
                    throw new VaultRecoveryRequiredException();
                }
            }

            foreach (var (basePath, suffixes) in groups)
            {
                foreach (var suffix in new[] { "-shm", "-wal", "-journal", string.Empty })
                {
                    if (!suffixes.Contains(suffix)) continue;
                    await SecurelyDeleteOwnedFileAsync(
                        basePath + suffix,
                        cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or NotSupportedException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static async Task SecurelyDeleteOwnedFileAsync(
        string path,
        CancellationToken cancellationToken)
    {
        WindowsVaultPathGuard.RequireSafeForOpen(path);
        await using (var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(
                path,
                stream.SafeFileHandle);
            var zeros = new byte[64 * 1024];
            var remaining = stream.Length;
            stream.Position = 0;
            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = (int)Math.Min(zeros.Length, remaining);
                await stream.WriteAsync(
                    zeros.AsMemory(0, count),
                    cancellationToken).ConfigureAwait(false);
                remaining -= count;
            }
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            stream.SetLength(0);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        File.Delete(path);
    }

    private static async Task TrySecurelyDeleteDatabaseSetAsync(string path)
    {
        foreach (var candidate in new[]
        {
            path + "-shm",
            path + "-wal",
            path + "-journal",
            path,
        })
        {
            try
            {
                if (File.Exists(candidate))
                {
                    await SecurelyDeleteOwnedFileAsync(
                        candidate,
                        CancellationToken.None).ConfigureAwait(false);
                }
            }
            catch
            {
            }
        }
    }

    private static string ConnectionStringForPath(string path) =>
        new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();

    private static void RequireCompatiblePreOpenInspection(
        VaultSchemaInspection original,
        VaultSchemaInspection current,
        VaultKeyRingIdentity authoritativeIdentity)
    {
        if (original.Kind is VaultSchemaKind.V6 or VaultSchemaKind.V5
            or VaultSchemaKind.V4 or VaultSchemaKind.V3
            or VaultSchemaKind.EligibleV2)
        {
            if (current.Kind != original.Kind)
                throw new VaultRecoveryRequiredException();
            RequireKeyRingIdentity(original.KeyRingIdentity, authoritativeIdentity);
            RequireKeyRingIdentity(current.KeyRingIdentity, authoritativeIdentity);
            return;
        }

        if (original.Kind is not (VaultSchemaKind.New or VaultSchemaKind.EmptyV1))
            throw new VaultRecoveryRequiredException();
        if (current.Kind == original.Kind) return;
        if (current.Kind == VaultSchemaKind.V6)
        {
            RequireKeyRingIdentity(current.KeyRingIdentity, authoritativeIdentity);
            return;
        }

        throw new VaultRecoveryRequiredException();
    }

    private static void RequireCompatibleFinalInspection(
        VaultSchemaInspection preOpen,
        VaultSchemaInspection final)
    {
        if (preOpen.Kind != final.Kind)
            throw new VaultRecoveryRequiredException();
        if (preOpen.Kind is VaultSchemaKind.V6 or VaultSchemaKind.V5
            or VaultSchemaKind.V4 or VaultSchemaKind.V3
            or VaultSchemaKind.EligibleV2)
            RequireKeyRingIdentity(preOpen.KeyRingIdentity, final.KeyRingIdentity!);
    }

    internal static string CanonicalizeConnectionString(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        try
        {
            var builder = new SqliteConnectionStringBuilder(connectionString);
            var source = builder.DataSource;
            if (string.IsNullOrWhiteSpace(source)
                || string.Equals(source, ":memory:", StringComparison.OrdinalIgnoreCase)
                || source.StartsWith("file:", StringComparison.OrdinalIgnoreCase)
                || source.Contains('|', StringComparison.Ordinal)
                || builder.Mode == SqliteOpenMode.Memory
                || builder.Cache == SqliteCacheMode.Shared)
            {
                throw new VaultRecoveryRequiredException();
            }

            var resolved = WindowsVaultPathGuard.NormalizeLocalDrivePath(source);
            builder.DataSource = resolved;
            builder.Pooling = false;
            return builder.ToString();
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException
            or PathTooLongException or System.Security.SecurityException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    public static async Task<SqliteConnection> OpenConnectionAsync(
        string connectionString,
        CancellationToken cancellationToken) =>
        await OpenConnectionAsync(connectionString, maintenanceGate: null, cancellationToken);

    internal static async Task<SqliteConnection> OpenConnectionAsync(
        string connectionString,
        VaultMaintenanceGate? maintenanceGate,
        CancellationToken cancellationToken)
    {
        ValidateConnectionString(connectionString);
        ValidateVaultPath(connectionString, maintenanceGate);
        var connection = new SqliteConnection(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            ValidateVaultPath(connectionString, maintenanceGate);
            await RequirePragmaAsync(connection, "foreign_keys = ON", "foreign_keys", "1", cancellationToken);
            await RequirePragmaAsync(connection, "main.secure_delete = ON", "main.secure_delete", "1", cancellationToken);
            await RequirePragmaAsync(connection, "main.journal_mode = WAL", "main.journal_mode", "wal", cancellationToken);
            await RequirePragmaAsync(connection, "synchronous = FULL", "synchronous", "2", cancellationToken);
            ValidateVaultPath(connectionString, maintenanceGate);

            return connection;
        }
        catch (Exception exception)
        {
            await connection.DisposeAsync();
            if (exception is VaultRecoveryRequiredException) throw;
            if (exception is SqliteException sqliteException && sqliteException.SqliteErrorCode is 5 or 6) throw;
            if (exception is SqliteException or InvalidCastException or FormatException or OverflowException)
                throw new VaultRecoveryRequiredException(exception);
            throw;
        }
    }

    internal static async Task<SqliteConnection> OpenHardenedPathAsync(
        string path,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        WindowsVaultPathGuard.RequireSafeDatabaseSet(fullPath);
        var connection = new SqliteConnection(ConnectionStringForPath(fullPath));
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            WindowsVaultPathGuard.RequireSafeDatabaseSet(fullPath);
            await RequirePragmaAsync(
                connection,
                "foreign_keys = ON",
                "foreign_keys",
                "1",
                cancellationToken).ConfigureAwait(false);
            await RequirePragmaAsync(
                connection,
                "main.secure_delete = ON",
                "main.secure_delete",
                "1",
                cancellationToken).ConfigureAwait(false);
            await RequirePragmaAsync(
                connection,
                "main.journal_mode = WAL",
                "main.journal_mode",
                "wal",
                cancellationToken).ConfigureAwait(false);
            await RequirePragmaAsync(
                connection,
                "synchronous = FULL",
                "synchronous",
                "2",
                cancellationToken).ConfigureAwait(false);
            WindowsVaultPathGuard.RequireSafeDatabaseSet(fullPath);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task<VaultSchemaInspection> InspectBeforeMutationAsync(string connectionString, CancellationToken cancellationToken)
    {
        var builder = new SqliteConnectionStringBuilder(connectionString);
        var path = Path.GetFullPath(builder.DataSource);
        WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
        if (HasDatabaseSidecar(path)) return new VaultSchemaInspection(VaultSchemaKind.Malformed);
        if (!File.Exists(path)) return new VaultSchemaInspection(VaultSchemaKind.New);
        if (new FileInfo(path).Length == 0) return new VaultSchemaInspection(VaultSchemaKind.New);

        VaultSchemaInspection inspection;
        try
        {
            builder.DataSource = new Uri(path).AbsoluteUri + "?immutable=1";
            builder.Mode = SqliteOpenMode.ReadOnly;
            builder.Cache = SqliteCacheMode.Private;
            builder.Pooling = false;
            await using (var connection = new SqliteConnection(builder.ToString()))
            {
                await connection.OpenAsync(cancellationToken);
                var version = Convert.ToInt32(await ExecuteScalarAsync(connection, null, "PRAGMA main.user_version;", cancellationToken));
                if (version == 0)
                {
                    inspection = await CountApplicationObjectsAsync(connection, null, cancellationToken) == 0
                        ? new VaultSchemaInspection(VaultSchemaKind.New)
                        : new VaultSchemaInspection(VaultSchemaKind.Malformed);
                }
                else if (version == 1)
                {
                    inspection = new VaultSchemaInspection(
                        await ClassifyExactVersionOneAsync(connection, null, cancellationToken));
                }
                else if (version == 2)
                {
                    try
                    {
                        await ValidateEligibleVersionTwoAsync(connection, null, cancellationToken);
                        inspection = new VaultSchemaInspection(
                            VaultSchemaKind.EligibleV2,
                            await ReadPersistedKeyRingIdentityAsync(connection, null, cancellationToken));
                    }
                    catch (LegacyProjectionRecoveryRequiredException)
                    {
                        inspection = new VaultSchemaInspection(VaultSchemaKind.LegacyProjection);
                    }
                }
                else if (version == 3)
                {
                    await ValidateLegacyVersionThreeAsync(connection, null, cancellationToken);
                    inspection = new VaultSchemaInspection(
                        VaultSchemaKind.V3,
                        await ReadPersistedKeyRingIdentityAsync(connection, null, cancellationToken));
                }
                else if (version == 4)
                {
                    await ValidateLegacyVersionFourAsync(connection, null, cancellationToken);
                    inspection = new VaultSchemaInspection(
                        VaultSchemaKind.V4,
                        await ReadPersistedKeyRingIdentityAsync(connection, null, cancellationToken));
                }
                else if (version == 5)
                {
                    await ValidateLegacyVersionFiveAsync(connection, null, cancellationToken);
                    inspection = new VaultSchemaInspection(
                        VaultSchemaKind.V5,
                        await ReadPersistedKeyRingIdentityAsync(connection, null, cancellationToken));
                }
                else if (version == CurrentVersion)
                {
                    await ValidateExistingVersionThreeAsync(connection, null, cancellationToken);
                    inspection = new VaultSchemaInspection(
                        VaultSchemaKind.V6,
                        await ReadPersistedKeyRingIdentityAsync(connection, null, cancellationToken));
                }
                else
                {
                    inspection = new VaultSchemaInspection(VaultSchemaKind.Unknown);
                }
            }
        }
        catch (VaultRecoveryRequiredException)
        {
            inspection = new VaultSchemaInspection(VaultSchemaKind.Malformed);
        }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException
            or FormatException or OverflowException or InvalidOperationException)
        {
            _ = exception;
            inspection = new VaultSchemaInspection(VaultSchemaKind.Malformed);
        }

        return HasDatabaseSidecar(path)
            ? new VaultSchemaInspection(VaultSchemaKind.Malformed)
            : inspection;
    }

    private static bool HasDatabaseSidecar(string path) =>
        WindowsVaultPathGuard.EntryExists(path + "-journal")
        || WindowsVaultPathGuard.EntryExists(path + "-wal")
        || WindowsVaultPathGuard.EntryExists(path + "-shm");

    internal static void ValidateVaultPath(string connectionString)
        => ValidateVaultPath(connectionString, maintenanceGate: null);

    internal static void ValidateVaultPath(
        string connectionString,
        VaultMaintenanceGate? maintenanceGate)
    {
        try
        {
            var path = new SqliteConnectionStringBuilder(connectionString).DataSource;
            if (maintenanceGate is null)
            {
                WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
            }
            else
            {
                WindowsVaultPathGuard.RequireSafeVaultSet(
                    path,
                    maintenanceGate.KeyRingPath,
                    maintenanceGate.LockPath);
            }
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException
            or InvalidOperationException
            or NotSupportedException)
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static async Task<VaultSchemaInspection> InspectInsideTransactionAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        var version = Convert.ToInt32(await ExecuteScalarAsync(connection, transaction, "PRAGMA main.user_version;", cancellationToken));
        if (version == 0 && await CountApplicationObjectsAsync(connection, transaction, cancellationToken) == 0)
            return new VaultSchemaInspection(VaultSchemaKind.New);
        if (version == 1)
        {
            return new VaultSchemaInspection(await ClassifyExactVersionOneAsync(connection, transaction, cancellationToken));
        }
        if (version == 2)
        {
            await ValidateEligibleVersionTwoAsync(connection, transaction, cancellationToken);
            return new VaultSchemaInspection(
                VaultSchemaKind.EligibleV2,
                await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken));
        }
        if (version == 3)
        {
            await ValidateLegacyVersionThreeAsync(connection, transaction, cancellationToken);
            return new VaultSchemaInspection(
                VaultSchemaKind.V3,
                await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken));
        }
        if (version == 4)
        {
            await ValidateLegacyVersionFourAsync(connection, transaction, cancellationToken);
            return new VaultSchemaInspection(
                VaultSchemaKind.V4,
                await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken));
        }
        if (version == 5)
        {
            await ValidateLegacyVersionFiveAsync(connection, transaction, cancellationToken);
            return new VaultSchemaInspection(
                VaultSchemaKind.V5,
                await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken));
        }
        if (version == CurrentVersion)
        {
            await ValidateExistingVersionThreeAsync(connection, transaction, cancellationToken);
            return new VaultSchemaInspection(
                VaultSchemaKind.V6,
                await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken));
        }

        return new VaultSchemaInspection(VaultSchemaKind.Unknown);
    }

    internal static Task ValidateExistingVersionThreeAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken) =>
        ValidateExistingSchemaAsync(
            connection,
            transaction,
            CurrentVersion,
            requireDeletionQueue: true,
            requireManagedCopies: true,
            requireOperationJournal: true,
            cancellationToken);

    internal static async Task ValidateRecoverableWalSchemaAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        var version = Convert.ToInt32(await ExecuteScalarAsync(
            connection,
            transaction,
            "PRAGMA main.user_version;",
            cancellationToken));
        if (version == 2)
        {
            await ValidateEligibleVersionTwoAsync(
                connection,
                transaction,
                cancellationToken);
            return;
        }
        if (version == CurrentVersion)
        {
            await ValidateExistingVersionThreeAsync(
                connection,
                transaction,
                cancellationToken);
            return;
        }
        if (version == 5)
        {
            await ValidateLegacyVersionFiveAsync(
                connection,
                transaction,
                cancellationToken);
            return;
        }
        if (version == 4)
        {
            await ValidateLegacyVersionFourAsync(
                connection,
                transaction,
                cancellationToken);
            return;
        }
        if (version == 3)
        {
            await ValidateLegacyVersionThreeAsync(
                connection,
                transaction,
                cancellationToken);
            return;
        }
        throw new VaultRecoveryRequiredException();
    }

    private static Task ValidateLegacyVersionFourAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken) =>
        ValidateExistingSchemaAsync(
            connection,
            transaction,
            expectedVersion: 4,
            requireDeletionQueue: true,
            requireManagedCopies: false,
            requireOperationJournal: false,
            cancellationToken);

    private static Task ValidateLegacyVersionFiveAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken) =>
        ValidateExistingSchemaAsync(
            connection,
            transaction,
            expectedVersion: 5,
            requireDeletionQueue: true,
            requireManagedCopies: true,
            requireOperationJournal: false,
            cancellationToken);

    private static Task ValidateLegacyVersionThreeAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken) =>
        ValidateExistingSchemaAsync(
            connection,
            transaction,
            expectedVersion: 3,
            requireDeletionQueue: false,
            requireManagedCopies: false,
            requireOperationJournal: false,
            cancellationToken);

    private static async Task ValidateExistingSchemaAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        int expectedVersion,
        bool requireDeletionQueue,
        bool requireManagedCopies,
        bool requireOperationJournal,
        CancellationToken cancellationToken)
    {
        try
        {
            var version = Convert.ToInt32(await ExecuteScalarAsync(connection, transaction, "PRAGMA main.user_version;", cancellationToken));
            if (version != expectedVersion) throw new VaultRecoveryRequiredException();

            await RequireExactObjectSqlAsync(connection, transaction, "table", "event_streams",
                ExtractExpectedStatement("CREATE TABLE event_streams("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "timeline_events",
                ExtractExpectedStatement(
                    requireManagedCopies ? VersionFiveManagedCopiesSql : VersionTwoSql,
                    "CREATE TABLE timeline_events("),
                cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "projection_checkpoints",
                ExtractExpectedStatement(
                    VersionThreeProjectionSql,
                    "CREATE TABLE projection_checkpoints("),
                cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "vault_metadata",
                ExtractExpectedStatement("CREATE TABLE vault_metadata("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "event_streams_stream_id_nocase",
                ExtractExpectedStatement("CREATE UNIQUE INDEX event_streams_stream_id_nocase"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_stream_position_nocase",
                ExtractExpectedStatement("CREATE INDEX timeline_events_stream_position_nocase"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_operation_position",
                ExtractExpectedStatement("CREATE INDEX timeline_events_operation_position"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_operation_representation",
                ExtractExpectedStatement("CREATE INDEX timeline_events_operation_representation"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_update",
                "CREATE TRIGGER timeline_events_immutable_update BEFORE UPDATE ON timeline_events BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_delete",
                "CREATE TRIGGER timeline_events_immutable_delete BEFORE DELETE ON timeline_events BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "vault_metadata_immutable_update",
                "CREATE TRIGGER vault_metadata_immutable_update BEFORE UPDATE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "vault_metadata_immutable_delete",
                "CREATE TRIGGER vault_metadata_immutable_delete BEFORE DELETE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END", cancellationToken);
            if (requireDeletionQueue)
            {
                await RequireExactObjectSqlAsync(
                    connection,
                    transaction,
                    "table",
                    "secure_compaction_queue",
                    ExtractExpectedStatement(
                        VersionFourDeletionSql,
                        "CREATE TABLE secure_compaction_queue("),
                    cancellationToken);
                await RequireExactObjectSqlAsync(
                    connection,
                    transaction,
                    "trigger",
                    "secure_compaction_queue_immutable_update",
                    ExtractExpectedStatement(
                        VersionFourDeletionSql,
                        "CREATE TRIGGER secure_compaction_queue_immutable_update"),
                    cancellationToken);
            }
            if (requireManagedCopies)
            {
                await RequireExactObjectSqlAsync(
                    connection,
                    transaction,
                    "table",
                    "managed_vault_copies",
                    ExtractExpectedStatement(
                        VersionFiveManagedCopiesSql,
                        "CREATE TABLE managed_vault_copies("),
                    cancellationToken);
                await RequireExactObjectSqlAsync(
                    connection,
                    transaction,
                    "trigger",
                    "managed_vault_copies_immutable_update",
                    ExtractExpectedStatement(
                        VersionFiveManagedCopiesSql,
                        "CREATE TRIGGER managed_vault_copies_immutable_update"),
                    cancellationToken);
            }
            if (requireOperationJournal)
            {
                foreach (var tableName in new[]
                {
                    "operation_journal",
                    "operation_side_effects",
                    "operation_usage_ledger",
                })
                {
                    await RequireExactObjectSqlAsync(
                        connection,
                        transaction,
                        "table",
                        tableName,
                        ExtractExpectedStatement(
                            VersionSixOperationJournalSql,
                            $"CREATE TABLE {tableName}("),
                        cancellationToken);
                }

                foreach (var triggerName in new[]
                {
                    "operation_journal_identity_immutable_update",
                    "operation_journal_update_guard",
                    "operation_journal_immutable_delete",
                    "operation_side_effects_state_only_update",
                    "operation_side_effects_immutable_delete",
                    "operation_usage_ledger_immutable_update",
                    "operation_usage_ledger_immutable_delete",
                })
                {
                    await RequireExactObjectSqlAsync(
                        connection,
                        transaction,
                        "trigger",
                        triggerName,
                        ExtractExpectedStatement(
                            VersionSixOperationJournalSql,
                            $"CREATE TRIGGER {triggerName}"),
                        cancellationToken);
                }
            }

            var deletionObjectCount = Convert.ToInt64(await ExecuteScalarAsync(
                connection,
                transaction,
                """
                SELECT COUNT(*) FROM main.sqlite_master
                WHERE lower(name) IN (
                    'secure_compaction_queue',
                    'secure_compaction_queue_immutable_update');
                """,
                cancellationToken));
            if (deletionObjectCount != (requireDeletionQueue ? 2 : 0))
                throw new VaultRecoveryRequiredException();
            var managedCopyObjectCount = Convert.ToInt64(await ExecuteScalarAsync(
                connection,
                transaction,
                """
                SELECT COUNT(*) FROM main.sqlite_master
                WHERE lower(name) IN (
                    'managed_vault_copies',
                    'managed_vault_copies_immutable_update');
                """,
                cancellationToken));
            if (managedCopyObjectCount != (requireManagedCopies ? 2 : 0))
                throw new VaultRecoveryRequiredException();
            var operationJournalObjectCount = Convert.ToInt64(await ExecuteScalarAsync(
                connection,
                transaction,
                """
                SELECT COUNT(*) FROM main.sqlite_master
                WHERE lower(name) IN (
                    'operation_journal',
                    'operation_side_effects',
                    'operation_usage_ledger',
                    'operation_journal_identity_immutable_update',
                    'operation_journal_update_guard',
                    'operation_journal_immutable_delete',
                    'operation_side_effects_state_only_update',
                    'operation_side_effects_immutable_delete',
                    'operation_usage_ledger_immutable_update',
                    'operation_usage_ledger_immutable_delete');
                """,
                cancellationToken));
            if (operationJournalObjectCount != (requireOperationJournal ? 10 : 0))
                throw new VaultRecoveryRequiredException();
            _ = await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken);

            await using var forbidden = connection.CreateCommand();
            forbidden.Transaction = transaction;
            forbidden.CommandText = """
                SELECT COUNT(*) FROM main.sqlite_master
                WHERE substr(lower(name), 1, 7) <> 'sqlite_'
                  AND (
                    lower(name) = 'payload_json'
                    OR lower(name) = 'event_operation_ids'
                    OR lower(name) GLOB 'event_operation_ids_*'
                    OR (lower(name) GLOB 'event_streams_*' AND lower(name) NOT IN (
                        'event_streams_stream_id_nocase'))
                    OR (lower(name) GLOB 'timeline_events_*' AND lower(name) NOT IN (
                        'timeline_events_stream_position_nocase',
                        'timeline_events_operation_position',
                        'timeline_events_operation_representation',
                        'timeline_events_immutable_update',
                        'timeline_events_immutable_delete'))
                    OR (lower(name) GLOB 'vault_metadata_*' AND lower(name) NOT IN (
                        'vault_metadata_immutable_update',
                        'vault_metadata_immutable_delete'))
                    OR (lower(name) GLOB 'secure_compaction_queue*' AND lower(name) NOT IN (
                        'secure_compaction_queue',
                        'secure_compaction_queue_immutable_update'))
                    OR (lower(name) GLOB 'managed_vault_copies*' AND lower(name) NOT IN (
                        'managed_vault_copies',
                        'managed_vault_copies_immutable_update'))
                    OR (lower(name) GLOB 'operation_journal*' AND lower(name) NOT IN (
                        'operation_journal',
                        'operation_journal_identity_immutable_update',
                        'operation_journal_update_guard',
                        'operation_journal_immutable_delete'))
                    OR (lower(name) GLOB 'operation_side_effects*' AND lower(name) NOT IN (
                        'operation_side_effects',
                        'operation_side_effects_state_only_update',
                        'operation_side_effects_immutable_delete'))
                    OR (lower(name) GLOB 'operation_usage_ledger*' AND lower(name) NOT IN (
                        'operation_usage_ledger',
                        'operation_usage_ledger_immutable_update',
                        'operation_usage_ledger_immutable_delete'))
                    OR (lower(tbl_name) IN (
                            'event_streams',
                            'timeline_events',
                            'projection_checkpoints',
                            'vault_metadata',
                            'secure_compaction_queue',
                            'managed_vault_copies',
                            'operation_journal',
                            'operation_side_effects',
                            'operation_usage_ledger')
                        AND lower(name) NOT IN (
                            'event_streams',
                            'timeline_events',
                            'projection_checkpoints',
                            'vault_metadata',
                            'secure_compaction_queue',
                            'managed_vault_copies',
                            'operation_journal',
                            'operation_side_effects',
                            'operation_usage_ledger',
                            'event_streams_stream_id_nocase',
                            'timeline_events_stream_position_nocase',
                            'timeline_events_operation_position',
                            'timeline_events_operation_representation',
                            'timeline_events_immutable_update',
                            'timeline_events_immutable_delete',
                            'vault_metadata_immutable_update',
                            'vault_metadata_immutable_delete',
                            'secure_compaction_queue_immutable_update',
                            'managed_vault_copies_immutable_update',
                            'operation_journal_identity_immutable_update',
                            'operation_journal_update_guard',
                            'operation_journal_immutable_delete',
                            'operation_side_effects_state_only_update',
                            'operation_side_effects_immutable_delete',
                            'operation_usage_ledger_immutable_update',
                            'operation_usage_ledger_immutable_delete'))
                  );
                """;
            if (Convert.ToInt64(await forbidden.ExecuteScalarAsync(cancellationToken)) != 0)
                throw new VaultRecoveryRequiredException();

            await using var forbiddenTemp = connection.CreateCommand();
            forbiddenTemp.Transaction = transaction;
            forbiddenTemp.CommandText = """
                SELECT COUNT(*) FROM temp.sqlite_master
                WHERE name COLLATE NOCASE IN (
                    'event_streams', 'timeline_events', 'projection_checkpoints',
                    'vault_metadata', 'event_streams_stream_id_nocase',
                    'secure_compaction_queue',
                    'managed_vault_copies',
                    'operation_journal',
                    'operation_side_effects',
                    'operation_usage_ledger',
                    'timeline_events_stream_position_nocase',
                    'timeline_events_operation_position',
                    'timeline_events_operation_representation',
                    'timeline_events_immutable_update',
                    'timeline_events_immutable_delete',
                    'vault_metadata_immutable_update',
                    'vault_metadata_immutable_delete',
                    'secure_compaction_queue_immutable_update',
                    'managed_vault_copies_immutable_update',
                    'operation_journal_identity_immutable_update',
                    'operation_journal_update_guard',
                    'operation_journal_immutable_delete',
                    'operation_side_effects_state_only_update',
                    'operation_side_effects_immutable_delete',
                    'operation_usage_ledger_immutable_update',
                    'operation_usage_ledger_immutable_delete')
                   OR tbl_name COLLATE NOCASE IN (
                    'event_streams', 'timeline_events', 'projection_checkpoints',
                    'vault_metadata', 'secure_compaction_queue',
                    'managed_vault_copies', 'operation_journal',
                    'operation_side_effects', 'operation_usage_ledger');
                """;
            if (Convert.ToInt64(await forbiddenTemp.ExecuteScalarAsync(cancellationToken)) != 0)
                throw new VaultRecoveryRequiredException();
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException or FormatException or OverflowException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static async Task ValidateEligibleVersionTwoAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            var version = Convert.ToInt32(await ExecuteScalarAsync(
                connection, transaction, "PRAGMA main.user_version;", cancellationToken));
            if (version != 2) throw new LegacyProjectionRecoveryRequiredException();

            await RequireExactObjectSqlAsync(connection, transaction, "table", "event_streams",
                ExtractExpectedStatement(VersionTwoSql, "CREATE TABLE event_streams("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "timeline_events",
                ExtractExpectedStatement(VersionTwoSql, "CREATE TABLE timeline_events("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "projection_checkpoints",
                ExtractExpectedStatement(VersionTwoSql, "CREATE TABLE projection_checkpoints("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "vault_metadata",
                ExtractExpectedStatement(VersionTwoSql, "CREATE TABLE vault_metadata("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "event_streams_stream_id_nocase",
                ExtractExpectedStatement(VersionTwoSql, "CREATE UNIQUE INDEX event_streams_stream_id_nocase"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_stream_position_nocase",
                ExtractExpectedStatement(VersionTwoSql, "CREATE INDEX timeline_events_stream_position_nocase"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_operation_position",
                ExtractExpectedStatement(VersionTwoSql, "CREATE INDEX timeline_events_operation_position"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_operation_representation",
                ExtractExpectedStatement(VersionTwoSql, "CREATE INDEX timeline_events_operation_representation"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_update",
                "CREATE TRIGGER timeline_events_immutable_update BEFORE UPDATE ON timeline_events BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_delete",
                "CREATE TRIGGER timeline_events_immutable_delete BEFORE DELETE ON timeline_events BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "vault_metadata_immutable_update",
                "CREATE TRIGGER vault_metadata_immutable_update BEFORE UPDATE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "vault_metadata_immutable_delete",
                "CREATE TRIGGER vault_metadata_immutable_delete BEFORE DELETE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END", cancellationToken);
            _ = await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken);

            if (Convert.ToInt64(await ExecuteScalarAsync(
                    connection,
                    transaction,
                    "SELECT COUNT(*) FROM main.projection_checkpoints;",
                    cancellationToken)) != 0
                || Convert.ToInt64(await ExecuteScalarAsync(
                    connection,
                    transaction,
                    "SELECT COUNT(*) FROM main.sqlite_master WHERE substr(lower(name),1,7) <> 'sqlite_';",
                    cancellationToken)) != 12)
            {
                throw new LegacyProjectionRecoveryRequiredException();
            }
        }
        catch (LegacyProjectionRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is VaultRecoveryRequiredException
            or SqliteException or InvalidCastException or FormatException or OverflowException)
        {
            throw new LegacyProjectionRecoveryRequiredException(exception);
        }
    }

    private static async Task ValidateProjectionObjectMembershipAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SqliteProjectionRegistry projections,
        CancellationToken cancellationToken)
    {
        if (projections.AllowsLegacyTestObjects) return;

        var coreObjects = new HashSet<string>(StringComparer.Ordinal)
        {
            "event_streams",
            "timeline_events",
            "projection_checkpoints",
            "vault_metadata",
            "secure_compaction_queue",
            "managed_vault_copies",
            "operation_journal",
            "operation_side_effects",
            "operation_usage_ledger",
            "event_streams_stream_id_nocase",
            "timeline_events_stream_position_nocase",
            "timeline_events_operation_position",
            "timeline_events_operation_representation",
            "timeline_events_immutable_update",
            "timeline_events_immutable_delete",
            "vault_metadata_immutable_update",
            "vault_metadata_immutable_delete",
            "secure_compaction_queue_immutable_update",
            "managed_vault_copies_immutable_update",
            "operation_journal_identity_immutable_update",
            "operation_journal_update_guard",
            "operation_journal_immutable_delete",
            "operation_side_effects_state_only_update",
            "operation_side_effects_immutable_delete",
            "operation_usage_ledger_immutable_update",
            "operation_usage_ledger_immutable_delete",
        };
        var registeredTables = projections.Registrations
            .SelectMany(registration => registration.OwnedTables)
            .Select(table => table.Name)
            .ToHashSet(StringComparer.Ordinal);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT type, name, tbl_name
            FROM main.sqlite_master
            WHERE substr(lower(name),1,7) <> 'sqlite_'
            ORDER BY type COLLATE BINARY, name COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (reader.GetValue(0) is not string type
                || reader.GetValue(1) is not string name
                || reader.GetValue(2) is not string tableName)
                throw new VaultRecoveryRequiredException();
            if (coreObjects.Contains(name)) continue;
            if (type == "table" && name == tableName && registeredTables.Contains(name)) continue;
            if (type is "index" or "trigger" && registeredTables.Contains(tableName)) continue;
            throw new VaultRecoveryRequiredException();
        }
    }

    internal static async Task ValidateProjectionMembershipAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SqliteProjectionRegistry projections,
        CancellationToken cancellationToken)
    {
        await SqliteProjectionCheckpointStore.ValidateMembershipAsync(
            connection, transaction, projections.Registrations, cancellationToken);
        await ValidateProjectionObjectMembershipAsync(
            connection, transaction, projections, cancellationToken);
    }

    internal static async Task<VaultKeyRingIdentity> ReadPersistedKeyRingIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "SELECT singleton, keyring_id FROM main.vault_metadata ORDER BY singleton;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)
                || reader.GetValue(0) is not long singleton
                || singleton != 1
                || reader.GetValue(1) is not byte[] identity
                || identity.Length != VaultKeyRingIdentity.Size
                || await reader.ReadAsync(cancellationToken))
            {
                throw new VaultRecoveryRequiredException();
            }

            return new VaultKeyRingIdentity(identity);
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException
            or FormatException or OverflowException or InvalidOperationException or NotSupportedException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    internal static async Task ValidateKeyRingIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        VaultKeyRingIdentity expectedIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        var persisted = await ReadPersistedKeyRingIdentityAsync(
            connection, transaction, cancellationToken);
        RequireKeyRingIdentity(persisted, expectedIdentity);
    }

    internal static async Task ValidateCurrentKeyRingIdentityAsync(
        VaultKeyRingStore keyRing,
        VaultKeyRingIdentity expectedIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        try
        {
            await keyRing.RequireCanonicalIdentityAsync(expectedIdentity, cancellationToken);
        }
        catch (VaultKeyRingException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static async Task InsertKeyRingIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRingIdentity identity,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO main.vault_metadata(singleton, keyring_id) VALUES(1, $keyring_id);";
        command.Parameters.Add("$keyring_id", SqliteType.Blob).Value = identity.Export();
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new VaultRecoveryRequiredException();
    }

    private static void RequireKeyRingIdentity(
        VaultKeyRingIdentity? persistedIdentity,
        VaultKeyRingIdentity authoritativeIdentity)
    {
        ArgumentNullException.ThrowIfNull(authoritativeIdentity);
        if (persistedIdentity is null || !authoritativeIdentity.FixedTimeEquals(persistedIdentity))
            throw new VaultRecoveryRequiredException();
    }

    private static async Task RequireExactObjectSqlAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string type,
        string name,
        string expectedSql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT sql FROM main.sqlite_master WHERE type = $type AND name = $name;";
        command.Parameters.AddWithValue("$type", type);
        command.Parameters.AddWithValue("$name", name);
        var actual = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken));
        if (actual is null || !string.Equals(NormalizeSql(actual), NormalizeSql(expectedSql), StringComparison.Ordinal))
            throw new VaultRecoveryRequiredException();
    }

    private static string ExtractExpectedStatement(string prefix)
        => ExtractExpectedStatement(VersionTwoSql, prefix);

    private static string ExtractExpectedStatement(string schemaSql, string prefix)
    {
        var start = schemaSql.IndexOf(prefix, StringComparison.Ordinal);
        if (start < 0) throw new InvalidOperationException("The canonical schema definition is incomplete.");
        if (prefix.StartsWith("CREATE TRIGGER", StringComparison.Ordinal))
        {
            var triggerEnd = schemaSql.IndexOf("END;", start, StringComparison.Ordinal);
            if (triggerEnd < 0) throw new InvalidOperationException("The canonical trigger is unterminated.");
            return schemaSql[start..(triggerEnd + "END".Length)];
        }
        var end = schemaSql.IndexOf(';', start);
        if (end < 0) throw new InvalidOperationException("The canonical schema statement is unterminated.");
        return schemaSql[start..end];
    }

    private static string NormalizeSql(string sql)
    {
        var normalized = new System.Text.StringBuilder(sql.Length);
        var inSingleQuote = false;
        var inDoubleQuote = false;
        for (var index = 0; index < sql.Length; index++)
        {
            var character = sql[index];
            if (character == '\'' && !inDoubleQuote)
            {
                normalized.Append(character);
                if (inSingleQuote && index + 1 < sql.Length && sql[index + 1] == '\'')
                {
                    normalized.Append(sql[++index]);
                }
                else
                {
                    inSingleQuote = !inSingleQuote;
                }
                continue;
            }

            if (character == '"' && !inSingleQuote)
            {
                normalized.Append(character);
                if (inDoubleQuote && index + 1 < sql.Length && sql[index + 1] == '"')
                {
                    normalized.Append(sql[++index]);
                }
                else
                {
                    inDoubleQuote = !inDoubleQuote;
                }
                continue;
            }

            if (!inSingleQuote && !inDoubleQuote)
            {
                if (char.IsWhiteSpace(character) || character == ';') continue;
                normalized.Append(char.ToLowerInvariant(character));
            }
            else
            {
                normalized.Append(character);
            }
        }

        return normalized.ToString();
    }

    private static async Task<VaultSchemaKind> ClassifyExactVersionOneAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await RequireExactObjectSqlAsync(connection, transaction, "table", "event_streams",
            ExtractExpectedStatement(VersionOneSql, "CREATE TABLE event_streams("), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "table", "timeline_events",
            ExtractExpectedStatement(VersionOneSql, "CREATE TABLE timeline_events("), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "table", "projection_checkpoints",
            ExtractExpectedStatement(VersionOneSql, "CREATE TABLE projection_checkpoints("), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "table", "event_operation_ids",
            ExtractExpectedStatement(VersionOneSql, "CREATE TABLE event_operation_ids("), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_update",
            ExtractExpectedStatement(VersionOneSql, "CREATE TRIGGER timeline_events_immutable_update"), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_delete",
            ExtractExpectedStatement(VersionOneSql, "CREATE TRIGGER timeline_events_immutable_delete"), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "trigger", "event_operation_ids_immutable_update",
            ExtractExpectedStatement(VersionOneSql, "CREATE TRIGGER event_operation_ids_immutable_update"), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "trigger", "event_operation_ids_immutable_delete",
            ExtractExpectedStatement(VersionOneSql, "CREATE TRIGGER event_operation_ids_immutable_delete"), cancellationToken);

        if (await CountApplicationObjectsAsync(connection, transaction, cancellationToken) != 8)
            throw new VaultRecoveryRequiredException();

        foreach (var table in new[] { "event_streams", "timeline_events", "projection_checkpoints", "event_operation_ids" })
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"SELECT EXISTS(SELECT 1 FROM main.\"{table}\" LIMIT 1);";
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) != 0)
                return VaultSchemaKind.LegacyNonEmpty;
        }

        return VaultSchemaKind.EmptyV1;
    }

    private static async Task<long> CountApplicationObjectsAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT COUNT(*)
            FROM main.sqlite_master
            WHERE substr(lower(name), 1, 7) <> 'sqlite_'
              AND type IN ('table', 'view', 'index', 'trigger');
            """;
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
    }

    private static async Task DropVersionOneCoreAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await ExecuteNonQueryAsync(connection, transaction, """
            DROP TRIGGER main.event_operation_ids_immutable_update;
            DROP TRIGGER main.event_operation_ids_immutable_delete;
            DROP TRIGGER main.timeline_events_immutable_update;
            DROP TRIGGER main.timeline_events_immutable_delete;
            DROP TABLE main.event_operation_ids;
            DROP TABLE main.timeline_events;
            DROP TABLE main.event_streams;
            DROP TABLE main.projection_checkpoints;
            """, cancellationToken);
    }

    private static void ValidateConnectionString(string connectionString)
    {
        var builder = new SqliteConnectionStringBuilder(connectionString);
        if (builder.Cache == SqliteCacheMode.Shared
            || builder.Mode == SqliteOpenMode.Memory
            || string.IsNullOrWhiteSpace(builder.DataSource)
            || string.Equals(builder.DataSource, ":memory:", StringComparison.OrdinalIgnoreCase)
            || builder.DataSource.StartsWith("file:", StringComparison.OrdinalIgnoreCase)
            || builder.DataSource.Contains('|', StringComparison.Ordinal)
            || !Path.IsPathFullyQualified(builder.DataSource))
            throw new VaultRecoveryRequiredException();
    }

    private static async Task RequirePragmaAsync(SqliteConnection connection, string set, string query, string expected, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA {set};";
        await command.ExecuteNonQueryAsync(cancellationToken);
        command.CommandText = $"PRAGMA {query};";
        var result = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken));
        if (!string.Equals(result, expected, StringComparison.OrdinalIgnoreCase)) throw new VaultRecoveryRequiredException();
    }

    private static async Task ExecuteNonQueryAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
    private static async Task<object?> ExecuteScalarAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = sql;
        return await command.ExecuteScalarAsync(cancellationToken);
    }
    private static async Task RollbackWithoutMaskingAsync(SqliteTransaction transaction) { try { await transaction.RollbackAsync(); } catch { } }
    private enum VaultSchemaKind
    {
        New,
        EmptyV1,
        LegacyNonEmpty,
        EligibleV2,
        V3,
        V4,
        V5,
        V6,
        LegacyProjection,
        Unknown,
        Malformed,
    }
    private sealed record VaultSchemaInspection(
        VaultSchemaKind Kind,
        VaultKeyRingIdentity? KeyRingIdentity = null);
}

public sealed class LegacyProjectionRecoveryRequiredException : InvalidOperationException
{
    public LegacyProjectionRecoveryRequiredException()
        : base("Legacy projection state requires explicit recovery before this Vault can be upgraded.")
    {
    }

    public LegacyProjectionRecoveryRequiredException(Exception innerException)
        : base("Legacy projection state requires explicit recovery before this Vault can be upgraded.", innerException)
    {
    }
}
