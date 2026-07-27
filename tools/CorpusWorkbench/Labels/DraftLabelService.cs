using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.CorpusEval;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Ingestion;
using LocalDocumentOrganizer.CorpusWorkbench.Rules;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using LocalDocumentOrganizer.Infrastructure.Windows.Documents;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

namespace LocalDocumentOrganizer.CorpusWorkbench.Labels;

public sealed class DraftLabelService
{
    private readonly CorpusVault _vault;
    private readonly CorpusWorkerPackageIdentity _workerIdentity;
    private readonly OfficialRuleCatalogSnapshot _rules;
    private readonly InvoiceDraftLabeler _labeler;
    private readonly Func<
        string,
        DocumentSourceDescriptor,
        CancellationToken,
        Task<DocumentExtractionResponse>> _extract;
    private readonly TimeProvider _timeProvider;
    private readonly Func<CancellationToken, Task> _verifyWorker;

    public DraftLabelService(
        CorpusVault vault,
        CorpusWorkerPackageWorkspace workerWorkspace,
        OfficialRuleCatalogSnapshot rules)
        : this(
            vault,
            workerWorkspace,
            rules,
            CreateExtractionDelegate(vault, workerWorkspace, rules),
            TimeProvider.System)
    {
    }

    internal DraftLabelService(
        CorpusVault vault,
        CorpusWorkerPackageWorkspace workerWorkspace,
        OfficialRuleCatalogSnapshot rules,
        Func<
            string,
            DocumentSourceDescriptor,
            CancellationToken,
            Task<DocumentExtractionResponse>> extract,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(workerWorkspace);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(extract);
        ArgumentNullException.ThrowIfNull(timeProvider);
        _vault = vault;
        _workerIdentity = workerWorkspace.Identity;
        _rules = rules;
        _extract = extract;
        _timeProvider = timeProvider;
        _verifyWorker = workerWorkspace.VerifyAsync;
        _labeler = new InvoiceDraftLabeler();
    }

    internal DraftLabelService(
        CorpusVault vault,
        OfficialRuleCatalogSnapshot rules,
        CorpusWorkerPackageIdentity workerIdentity,
        Func<
            string,
            DocumentSourceDescriptor,
            CancellationToken,
            Task<DocumentExtractionResponse>> extract,
        Func<CancellationToken, Task> verifyWorker,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(workerIdentity);
        ArgumentNullException.ThrowIfNull(extract);
        ArgumentNullException.ThrowIfNull(verifyWorker);
        ArgumentNullException.ThrowIfNull(timeProvider);
        _vault = vault;
        _workerIdentity = workerIdentity;
        _rules = rules;
        _extract = extract;
        _verifyWorker = verifyWorker;
        _timeProvider = timeProvider;
        _labeler = new InvoiceDraftLabeler();
    }

    public async Task<LabelRevision> CreateRevisionAsync(
        string documentId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(documentId);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var state = await _vault.Store.LoadLabelStateAsync(
                    documentId,
                    cancellationToken)
                .ConfigureAwait(false);
            RequireRuleBinding(state.Document, _rules);
            var descriptor = await CreateDescriptorAsync(
                    state.Document,
                    cancellationToken)
                .ConfigureAwait(false);
            var objectPath =
                _vault.GetObjectPathForExtraction(state.Document);
            var extraction = await ExtractWithAttestationAsync(
                    objectPath,
                    descriptor,
                    cancellationToken)
                .ConfigureAwait(false);
            if (extraction.Outcome
                    != DocumentExtractionOutcome.Success
                || extraction.FailureCode
                    != DocumentExtractionFailureCode.None)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.WorkerExecutionFailed);
            }

            var draft = _labeler.CreateDraft(
                state.Document,
                extraction,
                _rules);
            var createdAtUtc = _timeProvider.GetUtcNow()
                .ToUniversalTime();
            return await _vault.Store.PersistLabelRevisionAsync(
                    state,
                    draft,
                    _rules,
                    _workerIdentity,
                    createdAtUtc,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (CorpusWorkerAttestationException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch);
        }
        catch (DocumentExtractionException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerExecutionFailed);
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or CryptographicException
                or StableSourceBoundaryException
                or FileSystemBoundaryException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }
    }

    internal static LabelRevision CreateCanonicalRevision(
        WorkbenchDocument document,
        LabelDraft draft,
        OfficialRuleCatalogSnapshot rules,
        CorpusWorkerPackageIdentity workerIdentity,
        LabelRevision? previousRevision,
        DateTimeOffset createdAtUtc)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(draft);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(workerIdentity);
        var canonicalFields = CanonicalizeFields(draft, rules);
        if (createdAtUtc.Offset != TimeSpan.Zero
            || !IsLowerSha256(document.ContentSha256)
            || !IsLowerSha256(rules.CatalogSha256)
            || !CorpusWorkerPackageManifest
                .IsCanonicalExecutionIdentity(workerIdentity)
            || previousRevision is not null
            && (!string.Equals(
                    previousRevision.DocumentId,
                    document.DocumentId,
                    StringComparison.Ordinal)
                || !IsLowerSha256(
                    previousRevision.RevisionSha256)))
        {
            throw InvalidState();
        }

        var payload = SerializeRevisionPayload(
            document,
            canonicalFields,
            rules.CatalogSha256,
            workerIdentity,
            previousRevision?.RevisionId,
            previousRevision?.RevisionSha256,
            createdAtUtc);
        var revisionSha256 =
            Convert.ToHexStringLower(SHA256.HashData(payload));
        return new LabelRevision(
            "revision-" + revisionSha256,
            document.DocumentId,
            document.ContentSha256,
            document.MarketId,
            document.ContractId,
            previousRevision?.RevisionId,
            previousRevision?.RevisionSha256,
            rules.CatalogSha256,
            workerIdentity.ManifestId,
            workerIdentity.ManifestVersion,
            workerIdentity.Sha256,
            workerIdentity.ExecutableRelativePath,
            workerIdentity.ExecutableSha256,
            canonicalFields,
            revisionSha256,
            createdAtUtc);
    }

    internal static bool HasSameBinding(
        LabelRevision revision,
        WorkbenchDocument document,
        LabelDraft draft,
        OfficialRuleCatalogSnapshot rules,
        CorpusWorkerPackageIdentity workerIdentity)
    {
        var canonicalFields = CanonicalizeFields(draft, rules);
        return string.Equals(
                revision.DocumentId,
                document.DocumentId,
                StringComparison.Ordinal)
            && string.Equals(
                revision.DocumentSha256,
                document.ContentSha256,
                StringComparison.Ordinal)
            && string.Equals(
                revision.MarketId,
                document.MarketId,
                StringComparison.Ordinal)
            && string.Equals(
                revision.ContractId,
                document.ContractId,
                StringComparison.Ordinal)
            && string.Equals(
                revision.RuleCatalogSha256,
                rules.CatalogSha256,
                StringComparison.Ordinal)
            && string.Equals(
                revision.WorkerPackageManifestId,
                workerIdentity.ManifestId,
                StringComparison.Ordinal)
            && string.Equals(
                revision.WorkerPackageManifestVersion,
                workerIdentity.ManifestVersion,
                StringComparison.Ordinal)
            && string.Equals(
                revision.WorkerPackageSha256,
                workerIdentity.Sha256,
                StringComparison.Ordinal)
            && string.Equals(
                revision.WorkerExecutableRelativePath,
                workerIdentity.ExecutableRelativePath,
                StringComparison.Ordinal)
            && string.Equals(
                revision.WorkerExecutableSha256,
                workerIdentity.ExecutableSha256,
                StringComparison.Ordinal)
            && FieldsEqual(revision.Fields, canonicalFields);
    }

    internal static bool HasValidCanonicalHash(
        LabelRevision revision)
    {
        if (!IsLowerSha256(revision.RevisionSha256)
            || revision.CreatedAtUtc.Offset != TimeSpan.Zero)
        {
            return false;
        }

        var document = new WorkbenchDocument(
            revision.DocumentId,
            revision.DocumentSha256,
            string.Empty,
            revision.MarketId,
            revision.ContractId,
            string.Empty,
            null,
            string.Empty,
            string.Empty,
            default);
        var identity = new CorpusWorkerPackageIdentity(
            revision.WorkerPackageManifestId,
            revision.WorkerPackageManifestVersion,
            revision.WorkerPackageSha256,
            revision.WorkerExecutableRelativePath,
            revision.WorkerExecutableSha256);
        if (!CorpusWorkerPackageManifest
                .IsCanonicalExecutionIdentity(identity))
        {
            return false;
        }

        var payload = SerializeRevisionPayload(
            document,
            revision.Fields,
            revision.RuleCatalogSha256,
            identity,
            revision.PreviousRevisionId,
            revision.PreviousRevisionSha256,
            revision.CreatedAtUtc);
        var actual = SHA256.HashData(payload);
        var expected = Convert.FromHexString(
            revision.RevisionSha256);
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                actual,
                expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    private async Task<DocumentSourceDescriptor> CreateDescriptorAsync(
        WorkbenchDocument document,
        CancellationToken cancellationToken)
    {
        await using var source =
            _vault.TryOpenObject(document.ContentSha256)
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.ContentHashMismatch);
        _vault.RevalidateObject(source, document.ContentSha256);
        var hash = await source.ComputeSha256Async(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    hash,
                    Convert.FromHexString(document.ContentSha256)))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.ContentHashMismatch);
            }

            _vault.RevalidateObject(source, document.ContentSha256);
            return new DocumentSourceDescriptor(
                0,
                ContainerKind(document),
                MimeType(document),
                source.Length,
                ImmutableArray.CreateRange(hash));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private async Task<DocumentExtractionResponse>
        ExtractWithAttestationAsync(
        string objectPath,
        DocumentSourceDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        await _verifyWorker(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var extraction = await _extract(
                    objectPath,
                    descriptor,
                    cancellationToken)
                .ConfigureAwait(false);
            await _verifyWorker(cancellationToken)
                .ConfigureAwait(false);
            return extraction;
        }
        catch
        {
            try
            {
                await _verifyWorker(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (CorpusWorkerAttestationException)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.WorkerAttestationMismatch);
            }

            throw;
        }
    }

    private static Func<
        string,
        DocumentSourceDescriptor,
        CancellationToken,
        Task<DocumentExtractionResponse>> CreateExtractionDelegate(
        CorpusVault vault,
        CorpusWorkerPackageWorkspace workerWorkspace,
        OfficialRuleCatalogSnapshot rules)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(workerWorkspace);
        ArgumentNullException.ThrowIfNull(rules);
        var client = new DocumentExtractionClient(
            workerWorkspace.StagedExecutablePath,
            [rules.Document.MarketId],
            vault.ExtractionRootGuard);
        return client.ExtractAsync;
    }

    private static void RequireRuleBinding(
        WorkbenchDocument document,
        OfficialRuleCatalogSnapshot rules)
    {
        if (!string.Equals(
                document.MarketId,
                rules.Document.MarketId,
                StringComparison.Ordinal)
            || !string.Equals(
                document.ContractId,
                rules.Document.ContractId,
                StringComparison.Ordinal)
            || document.ContractId != PilotCatalog.ContractId)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.StaleRuleSet);
        }
    }

    private static ImmutableArray<LabeledField> CanonicalizeFields(
        LabelDraft draft,
        OfficialRuleCatalogSnapshot rules)
    {
        if (draft.Fields.IsDefault
            || draft.Fields.Length
                != PilotCatalog.RequiredFieldIds.Length)
        {
            throw InvalidState();
        }

        var byId = draft.Fields
            .GroupBy(static field => field.FieldId, StringComparer.Ordinal)
            .ToArray();
        if (byId.Any(static group => group.Count() != 1))
        {
            throw InvalidState();
        }

        var canonical = ImmutableArray.CreateBuilder<LabeledField>(
            PilotCatalog.RequiredFieldIds.Length);
        foreach (var fieldId in PilotCatalog.RequiredFieldIds)
        {
            var field = byId.SingleOrDefault(
                    group => string.Equals(
                        group.Key,
                        fieldId,
                        StringComparison.Ordinal))
                ?.Single()
                ?? throw InvalidState();
            var rule = rules.RulesByFieldId[fieldId];
            var isSentinel = field.NormalizedValue
                is InvoiceDraftLabeler.AbsentValue
                    or InvoiceDraftLabeler.UncertainValue;
            if (string.IsNullOrWhiteSpace(field.NormalizedValue)
                || !string.Equals(
                    field.RuleId,
                    rule.RuleId,
                    StringComparison.Ordinal)
                || field.Evidence.IsDefault
                || isSentinel && !field.Evidence.IsEmpty
                || !isSentinel && field.Evidence.IsEmpty
                || field.Evidence.Any(
                    static evidence =>
                        evidence.SourceIndex < 0
                        || !double.IsFinite(evidence.X)
                        || !double.IsFinite(evidence.Y)
                        || !double.IsFinite(evidence.Width)
                        || !double.IsFinite(evidence.Height)
                        || evidence.X < 0
                        || evidence.Y < 0
                        || evidence.Width <= 0
                        || evidence.Height <= 0))
            {
                throw InvalidState();
            }

            canonical.Add(
                field with
                {
                    NormalizedValue = field.NormalizedValue.Normalize(),
                    Evidence =
                    [
                        .. field.Evidence
                            .OrderBy(static evidence => evidence.SourceIndex)
                            .ThenBy(static evidence => evidence.Y)
                            .ThenBy(static evidence => evidence.X)
                            .ThenBy(static evidence => evidence.Width)
                            .ThenBy(static evidence => evidence.Height),
                    ],
                });
        }

        return canonical.MoveToImmutable();
    }

    private static bool FieldsEqual(
        ImmutableArray<LabeledField> left,
        ImmutableArray<LabeledField> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        for (var index = 0; index < left.Length; index++)
        {
            var leftField = left[index];
            var rightField = right[index];
            if (!string.Equals(
                    leftField.FieldId,
                    rightField.FieldId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    leftField.NormalizedValue,
                    rightField.NormalizedValue,
                    StringComparison.Ordinal)
                || !string.Equals(
                    leftField.RuleId,
                    rightField.RuleId,
                    StringComparison.Ordinal)
                || !leftField.Evidence.AsSpan().SequenceEqual(
                    rightField.Evidence.AsSpan()))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] SerializeRevisionPayload(
        WorkbenchDocument document,
        ImmutableArray<LabeledField> fields,
        string ruleCatalogSha256,
        CorpusWorkerPackageIdentity workerIdentity,
        string? previousRevisionId,
        string? previousRevisionSha256,
        DateTimeOffset createdAtUtc)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("documentId", document.DocumentId);
            writer.WriteString("documentSha256", document.ContentSha256);
            writer.WriteString("marketId", document.MarketId);
            writer.WriteString("contractId", document.ContractId);
            WriteNullableString(
                writer,
                "previousRevisionId",
                previousRevisionId);
            WriteNullableString(
                writer,
                "previousRevisionSha256",
                previousRevisionSha256);
            writer.WriteString(
                "ruleCatalogSha256",
                ruleCatalogSha256);
            writer.WriteString(
                "workerPackageManifestId",
                workerIdentity.ManifestId);
            writer.WriteString(
                "workerPackageManifestVersion",
                workerIdentity.ManifestVersion);
            writer.WriteString(
                "workerPackageSha256",
                workerIdentity.Sha256);
            writer.WriteString(
                "workerExecutableRelativePath",
                workerIdentity.ExecutableRelativePath);
            writer.WriteString(
                "workerExecutableSha256",
                workerIdentity.ExecutableSha256);
            writer.WritePropertyName("fields");
            writer.WriteStartArray();
            foreach (var field in fields)
            {
                writer.WriteStartObject();
                writer.WriteString("fieldId", field.FieldId);
                writer.WriteString(
                    "normalizedValue",
                    field.NormalizedValue);
                writer.WritePropertyName("evidence");
                writer.WriteStartArray();
                foreach (var evidence in field.Evidence)
                {
                    writer.WriteStartObject();
                    writer.WriteNumber(
                        "sourceIndex",
                        evidence.SourceIndex);
                    writer.WriteNumber("x", evidence.X);
                    writer.WriteNumber("y", evidence.Y);
                    writer.WriteNumber("width", evidence.Width);
                    writer.WriteNumber("height", evidence.Height);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteString("ruleId", field.RuleId);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteString(
                "createdAtUtc",
                createdAtUtc.UtcDateTime.ToString(
                    "O",
                    CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static void WriteNullableString(
        Utf8JsonWriter writer,
        string propertyName,
        string? value)
    {
        if (value is null)
        {
            writer.WriteNull(propertyName);
        }
        else
        {
            writer.WriteString(propertyName, value);
        }
    }

    private static DocumentContainerKind ContainerKind(
        WorkbenchDocument document) =>
        document.InputKind switch
        {
            CorpusIngestionService.ImagePdfInputKind =>
                DocumentContainerKind.Pdf,
            CorpusIngestionService.StandaloneRasterInputKind =>
                DocumentContainerKind.RasterImage,
            _ => throw new WorkbenchException(
                WorkbenchFailureCode.UnsupportedInput),
        };

    private static string MimeType(WorkbenchDocument document) =>
        document.InputKind == CorpusIngestionService.ImagePdfInputKind
            ? "application/pdf"
            : document.CodecId switch
            {
                CorpusIngestionService.JpegCodecId => "image/jpeg",
                CorpusIngestionService.PngCodecId => "image/png",
                CorpusIngestionService.TiffCodecId => "image/tiff",
                CorpusIngestionService.BmpCodecId => "image/bmp",
                _ => throw new WorkbenchException(
                    WorkbenchFailureCode.UnsupportedInput),
            };

    private static bool IsLowerSha256(string value) =>
        value is not null
        && value.Length == 64
        && value.All(
            static character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');

    private static WorkbenchException InvalidState() =>
        new(WorkbenchFailureCode.InvalidState);
}
