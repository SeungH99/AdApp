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
using LocalDocumentOrganizer.CorpusWorkbench.Rules;
using LocalDocumentOrganizer.CorpusWorkbench.Review;
using LocalDocumentOrganizer.CorpusWorkbench.Security;
using LocalDocumentOrganizer.CorpusWorkbench.Serialization;
using LocalDocumentOrganizer.CorpusWorkbench.Validation;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
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
    private const string ConfigurationFileName =
        "workbench.configuration.json";
    private const string WorkerBindingFileName =
        "worker.binding.json";
    private const int MaximumConfigurationBytes = 16 * 1024;
    private const int MaximumCatalogBytes = 128 * 1024;
    private const int MaximumReceiptBytes = 64 * 1024;
    private const string PendingWorkerPackageDomain =
        "corpus-workbench-pending-worker-package-v1\n";
    private const string PendingWorkerExecutableDomain =
        "corpus-workbench-pending-worker-executable-v1\n";
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
            + "\"workerPackageSha256\",\"ledgerHeadSha256\","
            + "\"pilotComplete\",\"primaryFailureCode\","
            + "\"blockingReasons\",\"markets\",\"reportSha256\"],"
            + "\"properties\":{"
            + "\"schemaVersion\":{\"const\":\"1\"},"
            + "\"catalogEpoch\":{\"type\":\"string\"},"
            + "\"contractId\":{\"const\":\"invoice-explicit-due-date-v1\"},"
            + "\"ruleCatalogSha256\":{\"$ref\":\"#/$defs/sha256\"},"
            + "\"workerPackageSha256\":{\"$ref\":\"#/$defs/sha256\"},"
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
        var configuration =
            await LoadConfigurationFromRootAsync(
                    command.VaultPath,
                    cancellationToken)
                .ConfigureAwait(false);
        var ruleSet = await LoadEmbeddedRuleSetAsync(cancellationToken)
            .ConfigureAwait(false);
        RequireConfiguredRuleSet(configuration, ruleSet);

        var binding = await LoadWorkerBindingFromRootAsync(
                command.VaultPath,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
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
        WorkerBinding binding,
        CancellationToken cancellationToken)
    {
        var existing = await LoadWorkerBindingAsync(
                vault,
                cancellationToken)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            RequireSameWorkerBinding(existing, binding);
            return;
        }

        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            binding,
            ConfigurationJson);
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
        return ParseWorkerBinding(bytes);
    }

    private static async Task<WorkerBinding?>
        LoadWorkerBindingFromRootAsync(
        string vaultPath,
        CancellationToken cancellationToken)
    {
        var path = Path.Combine(vaultPath, WorkerBindingFileName);
        if (!File.Exists(path))
        {
            return null;
        }

        var bytes = await ReadStableFileAsync(
                path,
                MaximumConfigurationBytes,
                cancellationToken)
            .ConfigureAwait(false);
        return ParseWorkerBinding(bytes);
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

    private static async Task InitializeAsync(
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

        using (var parentStore = new ApprovedRootFileStore(
                   new ApprovedRootPathGuard(parent)))
        {
            parentStore.Revalidate();
        }
        var staging = Path.Combine(
            parent,
            $".{leaf}.initialize-{Guid.NewGuid():N}");
        CreatePrivateDirectory(staging);
        var published = false;
        try
        {
            var configuration = new WorkbenchConfiguration(
                "1",
                command.Epoch,
                ruleSet.PilotSha256,
                supplied.Document.MarketId,
                supplied.CatalogSha256);
            await using (var vault = CorpusVault.OpenExisting(staging))
            {
                var bytes = JsonSerializer.SerializeToUtf8Bytes(
                    configuration,
                    ConfigurationJson);
                await PublishNoReplaceAsync(
                        Path.Combine(staging, ConfigurationFileName),
                        bytes,
                        "configuration",
                        cancellationToken)
                    .ConfigureAwait(false);
                var authentication =
                    new PilotAuthenticationService(vault);
                var proof = await authentication.SignCheckpointAsync(
                        "corpus-workbench-initialization-v1\n"u8
                            .ToArray(),
                        cancellationToken)
                    .ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(proof);
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (Directory.Exists(command.VaultPath)
                || File.Exists(command.VaultPath))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
            }

            Directory.Move(staging, command.VaultPath);
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
                or NotSupportedException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation,
                exception);
        }
        finally
        {
            if (!published && Directory.Exists(staging))
            {
                try
                {
                    DeletePrivateStagingDirectory(parent, staging);
                }
                catch
                {
                    // The initialization failure remains primary.
                }
            }
        }
    }

    private static async Task ValidateAsync(
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
                cancellationToken)
            .ConfigureAwait(false);
        if (binding is null)
        {
            if (states.Count != 0)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode
                        .WorkerAttestationMismatch);
            }

            var pending = CreatePendingWorkerIdentity();
            var pendingApproval = new ApprovalLedgerService(
                vault,
                scope,
                ruleSet.Rules.Values,
                pending,
                TimeProvider.System,
                injectFault: null);
            await ValidateAndPublishAsync(
                    vault,
                    pendingApproval,
                    scope,
                    ruleSet.PilotSha256,
                    pending.Sha256,
                    command.OutputPath,
                    requirePristinePending: true,
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
                    requirePristinePending: false,
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
        bool requirePristinePending,
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

        if (requirePristinePending
            && !FixedHashEquals(
                verification.LedgerHeadSha256,
                EmptyLedgerSha256))
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
        if (requirePristinePending
            && (result.PilotComplete
            || !result.BlockingReasons.Contains(
                WorkbenchFailureCode.CoverageIncomplete))
            )
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        }

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
                seed.CatalogSha256))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.StaleRuleSet);
        }
    }

    private static CorpusWorkerPackageIdentity
        CreatePendingWorkerIdentity() =>
        new(
            CorpusWorkerPackageIdentity.CanonicalManifestId,
            CorpusWorkerPackageIdentity.CanonicalManifestVersion,
            Convert.ToHexStringLower(
                SHA256.HashData(
                    Encoding.UTF8.GetBytes(
                        PendingWorkerPackageDomain))),
            "pending/unassigned-worker.exe",
            Convert.ToHexStringLower(
                SHA256.HashData(
                    Encoding.UTF8.GetBytes(
                        PendingWorkerExecutableDomain))));

    private static async Task<WorkbenchConfiguration>
        LoadConfigurationAsync(
        CorpusVault vault,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadVaultFileAsync(
                vault,
                ConfigurationFileName,
                MaximumConfigurationBytes,
                cancellationToken)
            .ConfigureAwait(false);
        return ParseConfiguration(bytes);
    }

    private static async Task<WorkbenchConfiguration>
        LoadConfigurationFromRootAsync(
        string vaultPath,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(vaultPath))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        }

        var bytes = await ReadStableFileAsync(
                Path.Combine(vaultPath, ConfigurationFileName),
                MaximumConfigurationBytes,
                cancellationToken)
            .ConfigureAwait(false);
        return ParseConfiguration(bytes);
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
                    configuration.SeedCatalogSha256))
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
        Directory.CreateDirectory(path);
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
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static void DeletePrivateStagingDirectory(
        string expectedParent,
        string staging)
    {
        var parent = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(expectedParent));
        var candidate = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(staging));
        var relative = Path.GetRelativePath(parent, candidate);
        if (relative.StartsWith(".", StringComparison.Ordinal)
            && relative.Contains(".initialize-", StringComparison.Ordinal)
            && !relative.Contains(Path.DirectorySeparatorChar)
            && !relative.Contains(Path.AltDirectorySeparatorChar))
        {
            Directory.Delete(candidate, recursive: true);
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
    {
        if (value is not { Length: >= 3 and <= 1024 }
            || !Path.IsPathFullyQualified(value)
            || value.StartsWith(@"\\", StringComparison.Ordinal)
            || !char.IsAsciiLetter(value[0])
            || value[1] != ':'
            || value[2] != Path.DirectorySeparatorChar)
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(value),
                value,
                StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

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
    string SeedCatalogSha256);

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
