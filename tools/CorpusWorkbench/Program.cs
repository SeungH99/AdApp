using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Security.Principal;
using LocalDocumentOrganizer.CorpusEval;
using LocalDocumentOrganizer.CorpusWorkbench.Approval;
using LocalDocumentOrganizer.CorpusWorkbench.Commanding;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Ingestion;
using LocalDocumentOrganizer.CorpusWorkbench.Labels;
using LocalDocumentOrganizer.CorpusWorkbench.Persistence;
using LocalDocumentOrganizer.CorpusWorkbench.Rules;
using LocalDocumentOrganizer.CorpusWorkbench.Review;
using LocalDocumentOrganizer.CorpusWorkbench.Security;
using LocalDocumentOrganizer.CorpusWorkbench.Serialization;
using LocalDocumentOrganizer.CorpusWorkbench.Validation;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
using Microsoft.Data.Sqlite;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.CorpusWorkbench;

internal interface IWorkbenchCommandExecutor
{
    Task ExecuteAsync(
        WorkbenchCommand command,
        CancellationToken cancellationToken);
}

internal static class Program
{
    private const string ErrorPrefix = "corpus-workbench:";

    private static async Task<int> Main(string[] arguments)
    {
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler onCancel = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            try
            {
                cancellation.Cancel();
            }
            catch (ObjectDisposedException)
            {
            }
        };
        Console.CancelKeyPress += onCancel;
        try
        {
            return await RunAsync(
                    arguments,
                    Console.Error,
                    executor: null,
                    cancellation.Token)
                .ConfigureAwait(false);
        }
        finally
        {
            Console.CancelKeyPress -= onCancel;
        }
    }

    internal static async Task<int> RunAsync(
        string[] arguments,
        TextWriter standardError,
        IWorkbenchCommandExecutor? executor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(standardError);
        try
        {
            var command = WorkbenchCommandLine.Parse(arguments);
            cancellationToken.ThrowIfCancellationRequested();
            executor ??= new WorkbenchCommandExecutor();
            await executor.ExecuteAsync(command, cancellationToken)
                .ConfigureAwait(false);
            return 0;
        }
        catch (OperationCanceledException)
        {
            await WriteFailureAsync(standardError, "cancelled")
                .ConfigureAwait(false);
            return 3;
        }
        catch (WorkbenchException exception)
        {
            var mapped = MapFailure(exception.FailureCode);
            await WriteFailureAsync(standardError, mapped.Code)
                .ConfigureAwait(false);
            return mapped.ExitCode;
        }
        catch
        {
            await WriteFailureAsync(standardError, "invalid-state")
                .ConfigureAwait(false);
            return 3;
        }
    }

    private static (int ExitCode, string Code) MapFailure(
        WorkbenchFailureCode failureCode) =>
        failureCode switch
        {
            WorkbenchFailureCode.InvalidArguments =>
                (2, "invalid-arguments"),
            WorkbenchFailureCode.InvalidState =>
                (3, "invalid-state"),
            WorkbenchFailureCode.SourceUnverified =>
                (4, "source-unverified"),
            WorkbenchFailureCode.ReuseStatusUnknown =>
                (4, "reuse-status-unknown"),
            WorkbenchFailureCode.VaultBoundaryViolation =>
                (4, "vault-boundary-violation"),
            WorkbenchFailureCode.ContentHashMismatch =>
                (4, "content-hash-mismatch"),
            WorkbenchFailureCode.UnsupportedInput =>
                (4, "unsupported-input"),
            WorkbenchFailureCode.WorkerExecutionFailed =>
                (5, "worker-execution-failed"),
            WorkbenchFailureCode.WorkerAttestationMismatch =>
                (5, "worker-attestation-mismatch"),
            WorkbenchFailureCode.DuplicateContent =>
                (6, "duplicate-content"),
            WorkbenchFailureCode.SourceFamilyLeakage =>
                (6, "source-family-leakage"),
            WorkbenchFailureCode.MissingRequiredField =>
                (6, "missing-required-field"),
            WorkbenchFailureCode.MissingEvidence =>
                (6, "missing-evidence"),
            WorkbenchFailureCode.StaleRuleSet =>
                (6, "stale-rule-set"),
            WorkbenchFailureCode.CoverageIncomplete =>
                (6, "coverage-incomplete"),
            WorkbenchFailureCode.ReviewCoverageInsufficient =>
                (7, "review-coverage-insufficient"),
            WorkbenchFailureCode.InsufficientDirectReview =>
                (7, "insufficient-direct-review"),
            WorkbenchFailureCode.BatchApprovalMissing =>
                (7, "batch-approval-missing"),
            WorkbenchFailureCode.ApprovalChainInvalid =>
                (7, "approval-chain-invalid"),
            WorkbenchFailureCode.PrivacyLeakDetected =>
                (8, "privacy-leak-detected"),
            WorkbenchFailureCode.InvalidCheckpoint =>
                (3, "invalid-checkpoint"),
            _ => (3, "invalid-state"),
        };

    private static async ValueTask WriteFailureAsync(
        TextWriter standardError,
        string code)
    {
        try
        {
            await standardError.WriteLineAsync(ErrorPrefix + code)
                .ConfigureAwait(false);
        }
        catch
        {
            // A completed mutation must not become a retry signal because
            // its diagnostic pipe was closed.
        }
    }
}

internal sealed class WorkbenchCommandExecutor
    : IWorkbenchCommandExecutor
{
    private readonly Action<WorkbenchInitializationFaultPoint>?
        _injectInitializationFault;
    private readonly Action<WorkbenchPendingValidationPoint>?
        _observePendingValidation;
    private readonly Func<int, string>?
        _createInitializationQuarantineName;
    private const string ConfigurationFileName =
        "workbench.configuration.json";
    private const string WorkerBindingFileName =
        "worker.binding.json";
    private const int MaximumConfigurationBytes =
        AuthenticatedVaultEnvelope.MaximumEnvelopeBytes;
    private const int MaximumCatalogBytes = 128 * 1024;
    private const int MaximumReceiptBytes = 64 * 1024;
    private const int MaximumInitializationCleanupEntries = 13;
    private const long MaximumInitializationCleanupBytes =
        8L * 1024 * 1024;
    private const int MaximumInitializationQuarantineAttempts = 8;
    private static readonly TimeSpan
        MaximumInitializationCleanupDuration =
            TimeSpan.FromSeconds(10);
    private static readonly IReadOnlySet<string>
        InitializationCleanupFileNames =
            new HashSet<string>(StringComparer.Ordinal)
            {
                "workbench.db",
                "vault.keys",
                "vault.keys.admission.lock",
                "vault.keys.lock",
                "vault.keys.rebuild.lock",
                "vault.keys.writer-intent.lock",
                ConfigurationFileName,
            };
    private static readonly IReadOnlySet<string>
        InitializationCleanupDirectoryNames =
            new HashSet<string>(StringComparer.Ordinal)
            {
                "objects",
                Path.Combine("objects", ".staging"),
                Path.Combine("objects", "sha256"),
                "previews",
                Path.Combine("previews", ".staging"),
                "checkpoints",
            };
    private const string EmptyLedgerSha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";

    private static readonly byte[] PublicSchema =
        Encoding.UTF8.GetBytes(
            "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\","
            + "\"$id\":\"urn:local-document-organizer:corpus-workbench:"
            + "sanitized-pilot-report:v1\","
            + "\"schemaVersion\":\"1\","
            + "\"title\":\"Corpus Workbench Sanitized Pilot Report\","
            + "\"type\":\"object\",\"additionalProperties\":false,"
            + "\"required\":[\"schemaVersion\",\"catalogEpoch\","
            + "\"contractId\",\"ruleCatalogSha256\","
            + "\"workerValidationMode\",\"workerPackageSha256\","
            + "\"ledgerHeadSha256\","
            + "\"pilotComplete\",\"primaryFailureCode\","
            + "\"blockingReasons\",\"markets\",\"reportSha256\"],"
            + "\"properties\":{"
            + "\"schemaVersion\":{\"const\":\"1\"},"
            + "\"catalogEpoch\":{\"type\":\"string\"},"
            + "\"contractId\":{\"const\":\"invoice-explicit-due-date-v1\"},"
            + "\"ruleCatalogSha256\":{\"$ref\":\"#/$defs/sha256\"},"
            + "\"workerValidationMode\":{\"enum\":[\"bound\",\"pending\"]},"
            + "\"workerPackageSha256\":{\"anyOf\":[{\"$ref\":\"#/$defs/sha256\"},{\"type\":\"null\"}]},"
            + "\"ledgerHeadSha256\":{\"$ref\":\"#/$defs/sha256\"},"
            + "\"pilotComplete\":{\"type\":\"boolean\"},"
            + "\"primaryFailureCode\":{\"type\":[\"string\",\"null\"]},"
            + "\"blockingReasons\":{\"type\":\"array\","
            + "\"items\":{\"type\":\"string\"},\"uniqueItems\":true},"
            + "\"markets\":{\"type\":\"array\",\"items\":{\"type\":\"object\"}},"
            + "\"reportSha256\":{\"$ref\":\"#/$defs/sha256\"}},"
            + "\"$defs\":{\"sha256\":{\"type\":\"string\","
            + "\"pattern\":\"^[0-9a-f]{64}$\"}}}\n");
    private static readonly JsonSerializerOptions ConfigurationJson =
        new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling =
                JsonUnmappedMemberHandling.Disallow,
        };

    internal WorkbenchCommandExecutor(
        Action<WorkbenchInitializationFaultPoint>?
            injectInitializationFault = null,
        Action<WorkbenchPendingValidationPoint>?
            observePendingValidation = null,
        Func<int, string>?
            createInitializationQuarantineName = null)
    {
        _injectInitializationFault = injectInitializationFault;
        _observePendingValidation = observePendingValidation;
        _createInitializationQuarantineName =
            createInitializationQuarantineName;
    }

    public async Task ExecuteAsync(
        WorkbenchCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        switch (command)
        {
            case InitCommand initialize:
                await InitializeAsync(initialize, cancellationToken)
                    .ConfigureAwait(false);
                return;
            case ImportCommand import:
                await ImportAsync(import, cancellationToken)
                    .ConfigureAwait(false);
                return;
            case LabelCommand label:
                await LabelAsync(label, cancellationToken)
                    .ConfigureAwait(false);
                return;
            case ReviewCommand review:
                await ReviewAsync(review, cancellationToken)
                    .ConfigureAwait(false);
                return;
            case ApproveBatchCommand approve:
                await ApproveBatchAsync(approve, cancellationToken)
                    .ConfigureAwait(false);
                return;
            case ValidateCommand validate:
                await ValidateAsync(validate, cancellationToken)
                    .ConfigureAwait(false);
                return;
            case SchemaCommand schema:
                await PublishNoReplaceAsync(
                        schema.OutputPath,
                        PublicSchema,
                        "schema",
                        cancellationToken)
                    .ConfigureAwait(false);
                return;
            default:
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
        }
    }

    private static async Task ApproveBatchAsync(
        ApproveBatchCommand command,
        CancellationToken cancellationToken)
    {
        await using var vault = OpenInitializedVault(
            command.VaultPath);
        var configuration = await LoadConfigurationAsync(
                vault,
                cancellationToken)
            .ConfigureAwait(false);
        var ruleSet = await LoadEmbeddedRuleSetAsync(cancellationToken)
            .ConfigureAwait(false);
        RequireConfiguredRuleSet(configuration, ruleSet);

        var binding = await LoadWorkerBindingAsync(
                vault,
                configuration.AuthenticatedIdentitySha256,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        try
        {
            await using var workspace =
                await CorpusWorkerPackageWorkspace.OpenAsync(
                        binding.PackageRoot,
                        binding.WorkerPath,
                        binding.PackageSha256,
                        command.VaultPath,
                        cancellationToken)
                    .ConfigureAwait(false);
            RequireWorkspaceIdentity(binding, workspace.Identity);
            var approval = new ApprovalLedgerService(
                vault,
                CreateScope(configuration),
                ruleSet.Rules.Values,
                workspace);
            try
            {
                _ = await approval.RecordBatchApprovalAsync(
                        command.MarketId,
                        command.ReviewerId,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (WorkbenchException exception)
                when (exception.FailureCode
                    == WorkbenchFailureCode.InvalidState)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.BatchApprovalMissing,
                    exception);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (CorpusWorkerAttestationException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch,
                exception);
        }
    }

    private static async Task ReviewAsync(
        ReviewCommand command,
        CancellationToken cancellationToken)
    {
        WorkbenchConfiguration configuration;
        WorkerBinding binding;
        await using (var vault = OpenInitializedVault(
                         command.VaultPath))
        {
            configuration = await LoadConfigurationAsync(
                    vault,
                    cancellationToken)
                .ConfigureAwait(false);
            binding = await LoadWorkerBindingAsync(
                    vault,
                    configuration.AuthenticatedIdentitySha256,
                    cancellationToken)
                .ConfigureAwait(false)
                ?? throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
        }

        var ruleSet = await LoadEmbeddedRuleSetAsync(cancellationToken)
            .ConfigureAwait(false);
        RequireConfiguredRuleSet(configuration, ruleSet);
        await ReviewHost.RunAsync(
                new ReviewHostOptions(
                    command.VaultPath,
                    "local-owner",
                    OpenBrowser: true,
                    configuration.CatalogEpoch),
                binding.PackageRoot,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task LabelAsync(
        LabelCommand command,
        CancellationToken cancellationToken)
    {
        await using var vault = OpenInitializedVault(
            command.VaultPath);
        var configuration = await LoadConfigurationAsync(
                vault,
                cancellationToken)
            .ConfigureAwait(false);
        var ruleSet = await LoadEmbeddedRuleSetAsync(cancellationToken)
            .ConfigureAwait(false);
        RequireConfiguredRuleSet(configuration, ruleSet);

        var states = await vault.Store.LoadAllLabelStatesAsync(
                cancellationToken)
            .ConfigureAwait(false);
        if (states.Count == 0)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        }

        try
        {
            await using var workspace =
                await CorpusWorkerPackageWorkspace.OpenAsync(
                        command.WorkerPackageRoot,
                        command.WorkerPath,
                        command.WorkerPackageSha256,
                        command.VaultPath,
                        cancellationToken)
                    .ConfigureAwait(false);
            var binding = new WorkerBinding(
                "1",
                command.WorkerPackageRoot,
                command.WorkerPath,
                workspace.Identity.ManifestId,
                workspace.Identity.ManifestVersion,
                workspace.Identity.Sha256,
                workspace.Identity.ExecutableRelativePath,
                workspace.Identity.ExecutableSha256);
            foreach (var state in states)
            {
                if (state.PreviousRevision is { } previous
                    && !RevisionUsesIdentity(
                        previous,
                        workspace.Identity))
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode
                            .WorkerAttestationMismatch);
                }
            }

            await PersistWorkerBindingAsync(
                    vault,
                    configuration.AuthenticatedIdentitySha256,
                    binding,
                    cancellationToken)
                .ConfigureAwait(false);
            foreach (var state in states.OrderBy(
                         static item =>
                             item.Document.DocumentId,
                         StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!ruleSet.Rules.TryGetValue(
                        state.Document.MarketId,
                        out var rules))
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.StaleRuleSet);
                }

                var labels = new DraftLabelService(
                    vault,
                    workspace,
                    rules);
                _ = await labels.CreateRevisionAsync(
                        state.Document.DocumentId,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (CorpusWorkerAttestationException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch,
                exception);
        }
    }

    private static async Task PersistWorkerBindingAsync(
        CorpusVault vault,
        string configurationIdentitySha256,
        WorkerBinding binding,
        CancellationToken cancellationToken)
    {
        var existing = await LoadWorkerBindingAsync(
                vault,
                configurationIdentitySha256,
                cancellationToken)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            RequireSameWorkerBinding(existing, binding);
            return;
        }

        var payload = JsonSerializer.SerializeToUtf8Bytes(
            binding,
            ConfigurationJson);
        var bytes = await AuthenticatedVaultEnvelope.SealAsync(
                vault,
                new PilotAuthenticationService(vault),
                AuthenticatedVaultEnvelopeKind.WorkerBinding,
                payload,
                configurationIdentitySha256,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            await PublishNoReplaceAsync(
                    Path.Combine(
                        vault.ApprovedRoot,
                        WorkerBindingFileName),
                    bytes,
                    "worker-binding",
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (WorkbenchException exception)
            when (exception.FailureCode
                == WorkbenchFailureCode.InvalidState)
        {
            existing = await LoadWorkerBindingAsync(
                    vault,
                    configurationIdentitySha256,
                    cancellationToken)
                .ConfigureAwait(false);
            if (existing is null)
            {
                throw;
            }

            RequireSameWorkerBinding(existing, binding);
        }
    }

    private static async Task<WorkerBinding?> LoadWorkerBindingAsync(
        CorpusVault vault,
        string configurationIdentitySha256,
        CancellationToken cancellationToken)
    {
        var store = vault.PreviewFileStore;
        await using (var probe =
                     store.TryOpenExistingOwnedVerified(
                         WorkerBindingFileName))
        {
            if (probe is null)
            {
                return null;
            }

            store.RevalidateExisting(
                probe,
                WorkerBindingFileName);
        }

        var bytes = await ReadVaultFileAsync(
                vault,
                WorkerBindingFileName,
                MaximumConfigurationBytes,
                cancellationToken)
            .ConfigureAwait(false);
        var opened = await AuthenticatedVaultEnvelope.OpenAsync(
                vault,
                new PilotAuthenticationService(vault),
                AuthenticatedVaultEnvelopeKind.WorkerBinding,
                bytes,
                configurationIdentitySha256,
                cancellationToken)
            .ConfigureAwait(false);
        var binding = ParseWorkerBinding(opened.Payload);
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            binding,
            ConfigurationJson);
        if (!canonical.AsSpan().SequenceEqual(opened.Payload))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch);
        }

        return binding;
    }

    private static WorkerBinding ParseWorkerBinding(byte[] bytes)
    {
        try
        {
            var binding = JsonSerializer.Deserialize<WorkerBinding>(
                    bytes,
                    ConfigurationJson)
                ?? throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
            if (binding.SchemaVersion != "1"
                || !IsCanonicalLocalPath(binding.PackageRoot)
                || !IsCanonicalLocalPath(binding.WorkerPath)
                || !CorpusWorkerPackageManifest
                    .IsCanonicalExecutionIdentity(binding.Identity))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode
                        .WorkerAttestationMismatch);
            }

            return binding;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch,
                exception);
        }
    }

    private static void RequireSameWorkerBinding(
        WorkerBinding left,
        WorkerBinding right)
    {
        if (!string.Equals(
                left.PackageRoot,
                right.PackageRoot,
                StringComparison.Ordinal)
            || !string.Equals(
                left.WorkerPath,
                right.WorkerPath,
                StringComparison.Ordinal)
            || !string.Equals(
                left.ManifestId,
                right.ManifestId,
                StringComparison.Ordinal)
            || !string.Equals(
                left.ManifestVersion,
                right.ManifestVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                left.ExecutableRelativePath,
                right.ExecutableRelativePath,
                StringComparison.Ordinal)
            || !FixedHashEquals(left.PackageSha256, right.PackageSha256)
            || !FixedHashEquals(
                left.ExecutableSha256,
                right.ExecutableSha256))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch);
        }
    }

    private static void RequireWorkspaceIdentity(
        WorkerBinding binding,
        CorpusWorkerPackageIdentity actual)
    {
        var expected = binding.Identity;
        if (!string.Equals(
                expected.ManifestId,
                actual.ManifestId,
                StringComparison.Ordinal)
            || !string.Equals(
                expected.ManifestVersion,
                actual.ManifestVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                expected.ExecutableRelativePath,
                actual.ExecutableRelativePath,
                StringComparison.Ordinal)
            || !FixedHashEquals(expected.Sha256, actual.Sha256)
            || !FixedHashEquals(
                expected.ExecutableSha256,
                actual.ExecutableSha256))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch);
        }
    }

    private static bool RevisionUsesIdentity(
        LabelRevision revision,
        CorpusWorkerPackageIdentity identity) =>
        string.Equals(
            revision.WorkerPackageManifestId,
            identity.ManifestId,
            StringComparison.Ordinal)
        && string.Equals(
            revision.WorkerPackageManifestVersion,
            identity.ManifestVersion,
            StringComparison.Ordinal)
        && string.Equals(
            revision.WorkerExecutableRelativePath,
            identity.ExecutableRelativePath,
            StringComparison.Ordinal)
        && FixedHashEquals(
            revision.WorkerPackageSha256,
            identity.Sha256)
        && FixedHashEquals(
            revision.WorkerExecutableSha256,
            identity.ExecutableSha256);

    private static async Task ImportAsync(
        ImportCommand command,
        CancellationToken cancellationToken)
    {
        await using var vault = OpenInitializedVault(
            command.VaultPath);
        var configuration = await LoadConfigurationAsync(
                vault,
                cancellationToken)
            .ConfigureAwait(false);
        var ruleSet = await LoadEmbeddedRuleSetAsync(cancellationToken)
            .ConfigureAwait(false);
        RequireConfiguredRuleSet(configuration, ruleSet);

        var receiptBytes = await ReadStableFileAsync(
                command.ReceiptPath,
                MaximumReceiptBytes,
                cancellationToken)
            .ConfigureAwait(false);
        SourceReceipt receipt;
        try
        {
            receipt = WorkbenchJson.Parse(
                receiptBytes,
                WorkbenchJsonContext.Default.SourceReceipt);
        }
        catch (JsonException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments,
                exception);
        }

        var sourceRoot = Path.GetDirectoryName(command.SourcePath);
        if (string.IsNullOrEmpty(sourceRoot))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }

        var identity = new NtfsFileIdentityProvider(
            new ApprovedRootPathGuard(sourceRoot));
        var ingestion = new CorpusIngestionService(vault, identity);
        _ = await ingestion.ImportAsync(
                command.SourcePath,
                receipt,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task InitializeAsync(
        InitCommand command,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var ruleSet = await LoadEmbeddedRuleSetAsync(cancellationToken)
            .ConfigureAwait(false);
        var supplied = await LoadRuleCatalogAsync(
                command.CatalogPath,
                cancellationToken)
            .ConfigureAwait(false);
        if (!ruleSet.Rules.TryGetValue(
                supplied.Document.MarketId,
                out var official)
            || !FixedHashEquals(
                supplied.CatalogSha256,
                official.CatalogSha256))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }

        if (Directory.Exists(command.VaultPath)
            || File.Exists(command.VaultPath))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        }

        var parent = Path.GetDirectoryName(command.VaultPath);
        var leaf = Path.GetFileName(command.VaultPath);
        if (string.IsNullOrEmpty(parent)
            || string.IsNullOrEmpty(leaf)
            || !Directory.Exists(parent))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }

        using var parentStore = new ApprovedRootFileStore(
            new ApprovedRootPathGuard(parent));
        parentStore.Revalidate();
        var staging = Path.Combine(
            parent,
            $".{leaf}.initialize-{Guid.NewGuid():N}");
        CreatePrivateDirectory(staging);
        VerifiedDirectoryPromotion? stagingDirectory = null;
        var published = false;
        try
        {
            stagingDirectory =
                parentStore.OpenDirectoryPromotionVerified(
                    Path.GetFileName(staging));
            var configuration = new WorkbenchConfiguration(
                "1",
                command.Epoch,
                ruleSet.PilotSha256,
                supplied.Document.MarketId,
                supplied.CatalogSha256,
                "corpus-workbench-v1",
                PilotCatalog.ContractId,
                PilotCatalog.MarketIds,
                PilotCatalog.HeldOutTargetPerMarket,
                PilotCatalog.DirectReviewTargetPerMarket,
                ruleSet.Rules.ToImmutableSortedDictionary(
                    static pair => pair.Key,
                    static pair => pair.Value.CatalogSha256,
                    StringComparer.Ordinal));
            await using (var vault = CorpusVault.OpenExisting(staging))
            {
                var authentication =
                    new PilotAuthenticationService(vault);
                var proof = await authentication.SignCheckpointAsync(
                        "corpus-workbench-initialization-v1\n"u8
                            .ToArray(),
                        cancellationToken)
                    .ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(proof);
                var payload = JsonSerializer.SerializeToUtf8Bytes(
                    configuration,
                    ConfigurationJson);
                var bytes = await AuthenticatedVaultEnvelope.SealAsync(
                        vault,
                        authentication,
                        AuthenticatedVaultEnvelopeKind.Configuration,
                        payload,
                        configurationIdentitySha256: null,
                        cancellationToken,
                        vaultIdentityRoot: command.VaultPath)
                    .ConfigureAwait(false);
                await PublishNoReplaceAsync(
                        Path.Combine(staging, ConfigurationFileName),
                        bytes,
                        "configuration",
                        cancellationToken)
                    .ConfigureAwait(false);
                var readback = await LoadConfigurationAsync(
                        vault,
                        cancellationToken,
                        command.VaultPath)
                    .ConfigureAwait(false);
                RequireSameConfiguration(configuration, readback);
                _ = await vault.Store
                    .ReadPristinePilotSnapshotAsync(cancellationToken)
                    .ConfigureAwait(false);
            }

            _injectInitializationFault?.Invoke(
                WorkbenchInitializationFaultPoint
                    .BeforeStagingVerification);
            parentStore.RevalidateDirectoryPromotion(
                stagingDirectory);
            await VerifyInitializationContentAsync(
                    staging,
                    command.VaultPath,
                    configuration,
                    cancellationToken)
                .ConfigureAwait(false);
            VerifyInitializationStaging(staging);
            parentStore.RevalidateDirectoryPromotion(
                stagingDirectory);
            _injectInitializationFault?.Invoke(
                WorkbenchInitializationFaultPoint.BeforePublish);
            cancellationToken.ThrowIfCancellationRequested();
            parentStore.Revalidate();
            if (!parentStore.PromoteVerifiedDirectoryNoReplace(
                    stagingDirectory,
                    leaf))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
            }

            published = true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or StableSourceBoundaryException
                or IOException
                or UnauthorizedAccessException
                or CryptographicException
                or System.Security.SecurityException
                or ArgumentException
                or SqliteException
                or NotSupportedException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation,
                exception);
        }
        finally
        {
            if (!published && stagingDirectory is not null)
            {
                try
                {
                    CleanupFailedInitialization(
                        parentStore,
                        stagingDirectory,
                        leaf);
                }
                catch
                {
                    // The initialization failure remains primary.
                }
            }

            stagingDirectory?.Dispose();
        }
    }

    private void CleanupFailedInitialization(
        ApprovedRootFileStore parentStore,
        VerifiedDirectoryPromotion stagingDirectory,
        string vaultLeaf)
    {
        _injectInitializationFault?.Invoke(
            WorkbenchInitializationFaultPoint
                .BeforeCleanupGuardianAcquisition);
        using var cleanup =
            parentStore.OpenDirectoryCleanupGuardian(
                stagingDirectory);
        var quarantined = false;
        for (var attempt = 0;
             attempt < MaximumInitializationQuarantineAttempts;
             attempt++)
        {
            var quarantineName =
                _createInitializationQuarantineName?.Invoke(attempt)
                ?? $".{vaultLeaf}.cleanup-"
                + RandomNumberGenerator.GetHexString(
                    32,
                    lowercase: true);
            if (!quarantineName.StartsWith(
                    $".{vaultLeaf}.cleanup-",
                    StringComparison.Ordinal)
                || quarantineName.Contains(
                    Path.DirectorySeparatorChar)
                || quarantineName.Contains(
                    Path.AltDirectorySeparatorChar))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            }

            if (parentStore.QuarantineDirectoryNoReplace(
                    stagingDirectory,
                    cleanup,
                    quarantineName))
            {
                quarantined = true;
                break;
            }
        }

        if (!quarantined)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        _injectInitializationFault?.Invoke(
            WorkbenchInitializationFaultPoint
                .AfterCleanupQuarantine);
        parentStore.DeleteBoundedOwnedDirectoryTree(
            cleanup,
            InitializationCleanupFileNames,
            InitializationCleanupDirectoryNames,
            MaximumInitializationCleanupEntries,
            MaximumInitializationCleanupBytes,
            MaximumInitializationCleanupDuration);
    }

    private async Task ValidateAsync(
        ValidateCommand command,
        CancellationToken cancellationToken)
    {
        try
        {
            await ValidateCoreAsync(command, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (WorkbenchException exception)
            when (exception.FailureCode
                == WorkbenchFailureCode.InvalidState)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation,
                exception);
        }
        catch (SqliteException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation,
                exception);
        }
    }

    private async Task ValidateCoreAsync(
        ValidateCommand command,
        CancellationToken cancellationToken)
    {
        await using var vault = OpenInitializedVault(
            command.VaultPath);
        var configuration = await LoadConfigurationAsync(
                vault,
                cancellationToken)
            .ConfigureAwait(false);
        var ruleSet = await LoadEmbeddedRuleSetAsync(cancellationToken)
            .ConfigureAwait(false);
        RequireConfiguredRuleSet(configuration, ruleSet);

        var states = await vault.Store.LoadAllLabelStatesAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var scope = CreateScope(configuration);
        var binding = await LoadWorkerBindingAsync(
                vault,
                configuration.AuthenticatedIdentitySha256,
                cancellationToken)
            .ConfigureAwait(false);
        if (binding is null)
        {
            await ValidatePendingAndPublishAsync(
                    vault,
                    configuration,
                    scope,
                    ruleSet.PilotSha256,
                    command.OutputPath,
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        try
        {
            await using var workspace =
                await CorpusWorkerPackageWorkspace.OpenAsync(
                        binding.PackageRoot,
                        binding.WorkerPath,
                        binding.PackageSha256,
                        command.VaultPath,
                        cancellationToken)
                    .ConfigureAwait(false);
            RequireWorkspaceIdentity(binding, workspace.Identity);
            var approval = new ApprovalLedgerService(
                vault,
                scope,
                ruleSet.Rules.Values,
                workspace);
            await ValidateAndPublishAsync(
                    vault,
                    approval,
                    scope,
                    ruleSet.PilotSha256,
                    workspace.Identity.Sha256,
                    command.OutputPath,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (CorpusWorkerAttestationException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch,
                exception);
        }
    }

    private static async Task ValidateAndPublishAsync(
        CorpusVault vault,
        ApprovalLedgerService approval,
        PilotScope scope,
        string ruleCatalogSha256,
        string workerPackageSha256,
        string outputPath,
        CancellationToken cancellationToken)
    {
        var verification = await approval.VerifyAsync(
                cancellationToken)
            .ConfigureAwait(false);
        if (!verification.IsValid)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.ApprovalChainInvalid);
        }

        var request = new PilotValidationRequest(
            scope,
            ruleCatalogSha256,
            workerPackageSha256,
            verification.LedgerHeadSha256);
        var validator = new PilotValidator(vault, approval);
        var result = await validator.ValidateAsync(
                request,
                cancellationToken)
            .ConfigureAwait(false);
        var writer = new PilotReportWriter(vault);
        await writer.WriteAsync(
                result,
                outputPath,
                cancellationToken)
            .ConfigureAwait(false);
        if (!result.PilotComplete)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.CoverageIncomplete);
        }
    }

    private async Task ValidatePendingAndPublishAsync(
        CorpusVault vault,
        WorkbenchConfiguration configuration,
        PilotScope scope,
        string ruleCatalogSha256,
        string outputPath,
        CancellationToken cancellationToken)
    {
        _observePendingValidation?.Invoke(
            WorkbenchPendingValidationPoint.BeforeSnapshot);
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = await vault.Store
            .ReadPristinePilotSnapshotAsync(
                cancellationToken,
                point =>
                {
                    if (point
                        == PristinePilotReadPoint.AfterCountsRead)
                    {
                        _observePendingValidation?.Invoke(
                            WorkbenchPendingValidationPoint
                                .DuringSnapshotAfterCountsRead);
                    }
                })
            .ConfigureAwait(false);
        _observePendingValidation?.Invoke(
            WorkbenchPendingValidationPoint.AfterSnapshot);
        cancellationToken.ThrowIfCancellationRequested();
        if (await LoadWorkerBindingAsync(
                    vault,
                    configuration.AuthenticatedIdentitySha256,
                    cancellationToken)
                .ConfigureAwait(false)
            is not null)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch);
        }

        _observePendingValidation?.Invoke(
            WorkbenchPendingValidationPoint.AfterBindingCheck);
        cancellationToken.ThrowIfCancellationRequested();
        var summaries = scope.MarketIds
            .Order(StringComparer.Ordinal)
            .Select(static marketId => new PilotMarketSummary(
                marketId,
                0,
                0,
                0,
                0,
                0,
                0,
                BatchApproved: false,
                ImmutableDictionary<string, int>.Empty))
            .ToImmutableArray();
        var result = new PilotValidationResult(
            PilotComplete: false,
            WorkbenchFailureCode.CoverageIncomplete,
            [WorkbenchFailureCode.CoverageIncomplete],
            summaries,
            ruleCatalogSha256,
            WorkerPackageSha256: null,
            EmptyLedgerSha256)
        {
            WorkerValidationMode =
                PilotWorkerValidationMode.PendingUnassigned,
            Scope = scope with
            {
                MarketIds =
                [
                    .. scope.MarketIds.Order(StringComparer.Ordinal),
                ],
            },
            ValidationSnapshotSha256 = snapshot.SnapshotSha256,
            ConfigurationIdentitySha256 =
                configuration.AuthenticatedIdentitySha256,
        };
        result = await PilotResultAttestation.IssueAsync(
                result,
                new PilotAuthenticationService(vault),
                cancellationToken)
            .ConfigureAwait(false);
        var writer = new PilotReportWriter(vault);
        await writer.WriteAsync(
                result,
                outputPath,
                cancellationToken)
            .ConfigureAwait(false);
        throw new WorkbenchException(
            WorkbenchFailureCode.CoverageIncomplete);
    }

    private static PilotScope CreateScope(
        WorkbenchConfiguration configuration) =>
        new(
            PilotCatalog.SchemaVersion,
            configuration.CatalogEpoch,
            PilotCatalog.ContractId,
            PilotCatalog.MarketIds,
            PilotCatalog.HeldOutTargetPerMarket,
            PilotCatalog.DirectReviewTargetPerMarket);

    private static void RequireConfiguredRuleSet(
        WorkbenchConfiguration configuration,
        RuleSet ruleSet)
    {
        if (!FixedHashEquals(
                configuration.PilotRuleCatalogSha256,
                ruleSet.PilotSha256)
            || !ruleSet.Rules.TryGetValue(
                configuration.SeedMarketId,
                out var seed)
            || !FixedHashEquals(
                configuration.SeedCatalogSha256,
                seed.CatalogSha256)
            || configuration.RuleCatalogSha256ByMarket.Count
                != ruleSet.Rules.Count
            || ruleSet.Rules.Any(pair =>
                !configuration.RuleCatalogSha256ByMarket.TryGetValue(
                    pair.Key,
                    out var configured)
                || !FixedHashEquals(
                    configured,
                    pair.Value.CatalogSha256)))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.StaleRuleSet);
        }
    }

    private static async Task<WorkbenchConfiguration>
        LoadConfigurationAsync(
        CorpusVault vault,
        CancellationToken cancellationToken,
        string? vaultIdentityRoot = null)
    {
        var bytes = await ReadVaultFileAsync(
                vault,
                ConfigurationFileName,
                MaximumConfigurationBytes,
                cancellationToken)
            .ConfigureAwait(false);
        var opened = await AuthenticatedVaultEnvelope.OpenAsync(
                vault,
                new PilotAuthenticationService(vault),
                AuthenticatedVaultEnvelopeKind.Configuration,
                bytes,
                expectedConfigurationIdentitySha256: null,
                cancellationToken,
                vaultIdentityRoot)
            .ConfigureAwait(false);
        var configuration = ParseConfiguration(opened.Payload);
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            configuration,
            ConfigurationJson);
        if (!canonical.AsSpan().SequenceEqual(opened.Payload))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        return configuration with
        {
            AuthenticatedIdentitySha256 =
                opened.PayloadIdentitySha256,
        };
    }

    private static WorkbenchConfiguration ParseConfiguration(
        byte[] bytes)
    {
        try
        {
            var configuration =
                JsonSerializer.Deserialize<WorkbenchConfiguration>(
                    bytes,
                    ConfigurationJson)
                ?? throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
            if (configuration.SchemaVersion != "1"
                || !IsSafeToken(
                    configuration.CatalogEpoch,
                    maximumLength: 64)
                || !IsLowerSha256(
                    configuration.PilotRuleCatalogSha256)
                || configuration.SeedMarketId
                    is not ("ko-KR" or "en-US")
                || !IsLowerSha256(
                    configuration.SeedCatalogSha256)
                || !string.Equals(
                    configuration.ToolVersion,
                    "corpus-workbench-v1",
                    StringComparison.Ordinal)
                || !string.Equals(
                    configuration.ContractId,
                    PilotCatalog.ContractId,
                    StringComparison.Ordinal)
                || configuration.MarketIds.IsDefault
                || !configuration.MarketIds.AsSpan().SequenceEqual(
                    PilotCatalog.MarketIds.AsSpan())
                || configuration.HeldOutTargetPerMarket
                    != PilotCatalog.HeldOutTargetPerMarket
                || configuration.DirectReviewTargetPerMarket
                    != PilotCatalog.DirectReviewTargetPerMarket
                || configuration.RuleCatalogSha256ByMarket is null
                || configuration.RuleCatalogSha256ByMarket.Count
                    != PilotCatalog.MarketIds.Length
                || configuration.RuleCatalogSha256ByMarket.Any(
                    pair =>
                        !PilotCatalog.MarketIds.Contains(
                            pair.Key,
                            StringComparer.Ordinal)
                        || !IsLowerSha256(pair.Value)))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
            }

            return configuration;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState,
                exception);
        }
    }

    private static CorpusVault OpenInitializedVault(string vaultPath)
    {
        if (!Directory.Exists(vaultPath))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        }

        try
        {
            using var store = new ApprovedRootFileStore(
                new ApprovedRootPathGuard(vaultPath));
            using var configuration =
                store.OpenExistingVerified(ConfigurationFileName);
            store.RevalidateExisting(
                configuration,
                ConfigurationFileName);
            return CorpusVault.OpenExisting(vaultPath);
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or StableSourceBoundaryException
                or IOException
                or UnauthorizedAccessException
                or SqliteException
                or System.Security.SecurityException
                or ArgumentException
                or NotSupportedException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation,
                exception);
        }
    }

    private static async Task<byte[]> ReadVaultFileAsync(
        CorpusVault vault,
        string relativePath,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var store = vault.PreviewFileStore;
        await using var source = store.OpenExistingVerified(relativePath);
        if (source.Length <= 0 || source.Length > maximumBytes)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        using var output = new BoundedMemoryStream(maximumBytes);
        await source.CopyToAsync(output, cancellationToken)
            .ConfigureAwait(false);
        store.RevalidateExisting(source, relativePath);
        return output.ToArray();
    }

    private static async Task<RuleSet> LoadEmbeddedRuleSetAsync(
        CancellationToken cancellationToken)
    {
        var rules = ImmutableDictionary.CreateBuilder<
            string,
            OfficialRuleCatalogSnapshot>(StringComparer.Ordinal);
        foreach (var market in PilotCatalog.MarketIds)
        {
            var path = Path.GetFullPath(
                Path.Combine(
                    AppContext.BaseDirectory,
                    "catalog",
                    $"invoice-explicit-due-date-v1.{market}.json"));
            var snapshot = await LoadRuleCatalogAsync(
                    path,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(
                    snapshot.Document.MarketId,
                    market,
                    StringComparison.Ordinal)
                || !rules.TryAdd(market, snapshot))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
            }
        }

        var immutable = rules.ToImmutable();
        return new RuleSet(
            immutable,
            OfficialRuleCatalog.ComputePilotCatalogSha256(
                immutable.Values));
    }

    private static async Task<OfficialRuleCatalogSnapshot>
        LoadRuleCatalogAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadStableFileAsync(
                path,
                MaximumCatalogBytes,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var document = WorkbenchJson.Parse(
                bytes,
                WorkbenchJsonContext.Default
                    .OfficialRuleCatalogDocument);
            OfficialRuleCatalogValidator.Validate(document);
            var canonical = CanonicalRuleCatalog.Serialize(document);
            return new OfficialRuleCatalogSnapshot(
                document,
                Convert.ToHexStringLower(
                    SHA256.HashData(canonical)),
                document.Rules.ToFrozenDictionary(
                    static rule => rule.FieldId,
                    StringComparer.Ordinal));
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments,
                exception);
        }
    }

    private static async Task<byte[]> ReadStableFileAsync(
        string path,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var parent = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(parent))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }

        try
        {
            var guard = new ApprovedRootPathGuard(parent);
            await using var source =
                guard.OpenVerifiedSourceFromApprovedRoot(path);
            if (source.Length <= 0 || source.Length > maximumBytes)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidArguments);
            }

            using var output = new BoundedMemoryStream(maximumBytes);
            await source.CopyToAsync(output, cancellationToken)
                .ConfigureAwait(false);
            return output.ToArray();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or StableSourceBoundaryException
                or IOException
                or UnauthorizedAccessException
                or System.Security.SecurityException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation,
                exception);
        }
    }

    private static void CreatePrivateDirectory(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(
            new FileSystemAccessRule(
                user,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        new DirectoryInfo(path).Create(security);
    }

    private static void VerifyInitializationStaging(string staging)
    {
        var expectedFiles = new HashSet<string>(
            StringComparer.Ordinal)
        {
            "workbench.db",
            "vault.keys",
            "vault.keys.admission.lock",
            "vault.keys.lock",
            "vault.keys.rebuild.lock",
            "vault.keys.writer-intent.lock",
            ConfigurationFileName,
        };
        var expectedDirectories = new HashSet<string>(
            StringComparer.Ordinal)
        {
            "objects",
            "previews",
            "checkpoints",
        };
        var entries = Directory.EnumerateFileSystemEntries(
                staging,
                "*",
                SearchOption.TopDirectoryOnly)
            .Take(
                expectedFiles.Count
                + expectedDirectories.Count
                + 1)
            .Select(Path.GetFileName)
            .ToArray();
        if (entries.Length
                != expectedFiles.Count + expectedDirectories.Count
            || entries.Any(static name => string.IsNullOrEmpty(name))
            || entries.Any(name =>
                !expectedFiles.Contains(name!)
                && !expectedDirectories.Contains(name!)))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        var directory = new DirectoryInfo(staging);
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        var security = directory.GetAccessControl(
            AccessControlSections.Access
            | AccessControlSections.Owner);
        if (!security.AreAccessRulesProtected
            || security.GetOwner(typeof(SecurityIdentifier))
                is not SecurityIdentifier owner
            || !owner.Equals(user))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        if (rules.Length != 1
            || rules[0].IdentityReference
                is not SecurityIdentifier ruleIdentity
            || !ruleIdentity.Equals(user)
            || rules[0].AccessControlType
                != AccessControlType.Allow
            || (rules[0].FileSystemRights
                & FileSystemRights.FullControl)
                != FileSystemRights.FullControl
            || rules[0].InheritanceFlags
                != (InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit)
            || rules[0].PropagationFlags
                != PropagationFlags.None
            || rules[0].IsInherited)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        using var store = new ApprovedRootFileStore(
            new ApprovedRootPathGuard(staging));
        foreach (var file in expectedFiles)
        {
            using var verified = store.OpenExistingVerified(file);
            store.RevalidateExisting(verified, file);
        }

        foreach (var child in expectedDirectories)
        {
            store.RevalidateDirectoryVerified(child);
        }

        store.Revalidate();
    }

    private static async Task VerifyInitializationContentAsync(
        string staging,
        string finalVaultRoot,
        WorkbenchConfiguration expectedConfiguration,
        CancellationToken cancellationToken)
    {
        await using var vault = CorpusVault.OpenExisting(staging);
        var configuration = await LoadConfigurationAsync(
                vault,
                cancellationToken,
                finalVaultRoot)
            .ConfigureAwait(false);
        RequireSameConfiguration(
            expectedConfiguration,
            configuration);
        _ = await vault.Store
            .ReadPristinePilotSnapshotAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static void RequireSameConfiguration(
        WorkbenchConfiguration expected,
        WorkbenchConfiguration actual)
    {
        if (!string.Equals(
                expected.SchemaVersion,
                actual.SchemaVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                expected.CatalogEpoch,
                actual.CatalogEpoch,
                StringComparison.Ordinal)
            || !FixedHashEquals(
                expected.PilotRuleCatalogSha256,
                actual.PilotRuleCatalogSha256)
            || !string.Equals(
                expected.SeedMarketId,
                actual.SeedMarketId,
                StringComparison.Ordinal)
            || !FixedHashEquals(
                expected.SeedCatalogSha256,
                actual.SeedCatalogSha256)
            || !string.Equals(
                expected.ToolVersion,
                actual.ToolVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                expected.ContractId,
                actual.ContractId,
                StringComparison.Ordinal)
            || !expected.MarketIds.AsSpan()
                .SequenceEqual(actual.MarketIds.AsSpan())
            || expected.HeldOutTargetPerMarket
                != actual.HeldOutTargetPerMarket
            || expected.DirectReviewTargetPerMarket
                != actual.DirectReviewTargetPerMarket
            || expected.RuleCatalogSha256ByMarket.Count
                != actual.RuleCatalogSha256ByMarket.Count
            || expected.RuleCatalogSha256ByMarket.Any(pair =>
                !actual.RuleCatalogSha256ByMarket.TryGetValue(
                    pair.Key,
                    out var actualHash)
                || !FixedHashEquals(pair.Value, actualHash))
            || !IsLowerSha256(
                actual.AuthenticatedIdentitySha256))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }
    }

    private static bool IsSafeToken(
        string? value,
        int maximumLength) =>
        value is { Length: > 0 }
        && value.Length <= maximumLength
        && value.All(static character =>
            character is >= 'a' and <= 'z'
                or >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '-'
                or '_'
                or '.');

    private static bool IsCanonicalLocalPath(string? value)
        => CanonicalWindowsPath.IsAccepted(value);

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 }
        && value.All(static character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static bool FixedHashEquals(string? left, string? right)
    {
        if (!IsLowerSha256(left) || !IsLowerSha256(right))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left!),
            Convert.FromHexString(right!));
    }

    private static async Task PublishNoReplaceAsync(
        string outputPath,
        byte[] bytes,
        string stagingPrefix,
        CancellationToken cancellationToken)
    {
        var parent = Path.GetDirectoryName(outputPath);
        var fileName = Path.GetFileName(outputPath);
        if (string.IsNullOrEmpty(parent)
            || string.IsNullOrEmpty(fileName)
            || fileName.EndsWith(' ')
            || fileName.EndsWith('.'))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }

        try
        {
            var guard = new ApprovedRootPathGuard(parent);
            using var store = new ApprovedRootFileStore(guard);
            SafeFileHandle? staged = null;
            string? stagedName = null;
            var ownership = new FilePromotionOwnership();
            try
            {
                for (var attempt = 0; attempt < 16; attempt++)
                {
                    stagedName = $".corpus-{stagingPrefix}-"
                        + Guid.NewGuid().ToString("N")
                        + ".tmp";
                    try
                    {
                        staged = store.CreateNewPromotableVerified(
                            stagedName,
                            bytes.Length);
                        break;
                    }
                    catch (FileStoreEntryAlreadyExistsException)
                    {
                    }
                }

                if (staged is null || stagedName is null)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidState);
                }

                await RandomAccess.WriteAsync(
                        staged,
                        bytes,
                        fileOffset: 0,
                        cancellationToken)
                    .ConfigureAwait(false);
                RandomAccess.FlushToDisk(staged);
                store.RevalidateCreated(
                    staged,
                    stagedName,
                    bytes.Length);
                cancellationToken.ThrowIfCancellationRequested();
                if (!store.PromoteCreatedNoReplace(
                        staged,
                        stagedName,
                        fileName,
                        bytes.Length,
                        ownership))
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidState);
                }
            }
            finally
            {
                if (staged is not null
                    && stagedName is not null
                    && !ownership.IsTransferred)
                {
                    try
                    {
                        store.DeleteOwnedOnClose(
                            staged,
                            stagedName,
                            bytes.Length);
                    }
                    catch
                    {
                    }
                }

                staged?.Dispose();
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or IOException
                or UnauthorizedAccessException
                or System.Security.SecurityException
                or ArgumentException
                or NotSupportedException
                or PathTooLongException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation,
                exception);
        }
    }
}

internal sealed record WorkbenchConfiguration(
    string SchemaVersion,
    string CatalogEpoch,
    string PilotRuleCatalogSha256,
    string SeedMarketId,
    string SeedCatalogSha256,
    string ToolVersion,
    string ContractId,
    ImmutableArray<string> MarketIds,
    int HeldOutTargetPerMarket,
    int DirectReviewTargetPerMarket,
    ImmutableSortedDictionary<string, string>
        RuleCatalogSha256ByMarket)
{
    [JsonIgnore]
    internal string AuthenticatedIdentitySha256 { get; init; } =
        string.Empty;
}

internal sealed record WorkerBinding(
    string SchemaVersion,
    string PackageRoot,
    string WorkerPath,
    string ManifestId,
    string ManifestVersion,
    string PackageSha256,
    string ExecutableRelativePath,
    string ExecutableSha256)
{
    internal CorpusWorkerPackageIdentity Identity =>
        new(
            ManifestId,
            ManifestVersion,
            PackageSha256,
            ExecutableRelativePath,
            ExecutableSha256);
}

internal sealed record RuleSet(
    ImmutableDictionary<string, OfficialRuleCatalogSnapshot> Rules,
    string PilotSha256);

internal enum WorkbenchInitializationFaultPoint
{
    BeforeStagingVerification = 0,
    BeforePublish = 1,
    AfterCleanupQuarantine = 2,
    BeforeCleanupGuardianAcquisition = 3,
}

internal enum WorkbenchPendingValidationPoint
{
    BeforeSnapshot = 0,
    DuringSnapshotAfterCountsRead = 1,
    AfterSnapshot = 2,
    AfterBindingCheck = 3,
}
