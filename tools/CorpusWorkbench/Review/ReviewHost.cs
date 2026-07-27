using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LocalDocumentOrganizer.CorpusEval;
using LocalDocumentOrganizer.CorpusWorkbench.Approval;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Labels;
using LocalDocumentOrganizer.CorpusWorkbench.Persistence;
using LocalDocumentOrganizer.CorpusWorkbench.Rules;
using LocalDocumentOrganizer.CorpusWorkbench.Sampling;
using LocalDocumentOrganizer.CorpusWorkbench.Serialization;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LocalDocumentOrganizer.CorpusWorkbench.Review;

public sealed record ReviewHostOptions(
    string VaultRoot,
    string ReviewerId,
    bool OpenBrowser,
    string CatalogEpoch = "local-review-v1");

[JsonConverter(typeof(StrictReviewDecisionKindConverter))]
public enum ReviewDecisionKind
{
    ApproveExact,
    CorrectAndApprove,
    RejectDocument,
    Defer,
}

public sealed class StrictReviewDecisionKindConverter :
    JsonConverter<ReviewDecisionKind>
{
    public override ReviewDecisionKind Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.String
            ? reader.GetString() switch
            {
                "approveExact" =>
                    ReviewDecisionKind.ApproveExact,
                "correctAndApprove" =>
                    ReviewDecisionKind.CorrectAndApprove,
                "rejectDocument" =>
                    ReviewDecisionKind.RejectDocument,
                "defer" => ReviewDecisionKind.Defer,
                _ => throw new JsonException(),
            }
            : throw new JsonException();

    public override void Write(
        Utf8JsonWriter writer,
        ReviewDecisionKind value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(
            value switch
            {
                ReviewDecisionKind.ApproveExact =>
                    "approveExact",
                ReviewDecisionKind.CorrectAndApprove =>
                    "correctAndApprove",
                ReviewDecisionKind.RejectDocument =>
                    "rejectDocument",
                ReviewDecisionKind.Defer => "defer",
                _ => throw new JsonException(),
            });
}

public sealed record ReviewDecisionRequest(
    string LabelRevisionSha256,
    ReviewDecisionKind Decision,
    ImmutableArray<LabeledField> CorrectedFields);

public sealed record ReviewItemView(
    string Market,
    int Position,
    int Total,
    bool LocalOnly,
    string DocumentId,
    int PageCount,
    ImmutableArray<LabeledField> Fields,
    string OfficialRuleLink,
    string OfficialRuleVersion,
    string OfficialRuleSha256,
    string LabelRevisionSha256);

public sealed record ReviewDecisionOutcome(
    bool Stale,
    string LabelRevisionSha256);

public sealed record ReviewError(string Error);

public sealed record ReviewDecisionCheckpoint(
    string SchemaVersion,
    string DocumentId,
    string ExpectedRevisionSha256,
    string RequestSha256,
    ReviewDecisionKind Decision,
    string OutcomeRevisionSha256,
    DateTimeOffset RecordedAtUtc,
    bool Completed = true);

internal interface IReviewDataSource : IAsyncDisposable
{
    Task<ReviewItemView?> GetNextAsync(
        CancellationToken cancellationToken);

    Task<DocumentPreview> GetPreviewAsync(
        string documentId,
        int pageIndex,
        CancellationToken cancellationToken);

    Task<ReviewDecisionOutcome> DecideAsync(
        string documentId,
        ReviewDecisionRequest request,
        CancellationToken cancellationToken);
}

internal interface IReviewHostRunSession : IAsyncDisposable
{
    Uri NavigationUri { get; }

    Task WaitForShutdownAsync(
        CancellationToken cancellationToken);
}

internal interface IReviewHostRunner
{
    Task<IReviewHostRunSession> StartAsync(
        ReviewHostOptions options,
        IReviewDataSource dataSource,
        CancellationToken cancellationToken);
}

public static class ReviewHost
{
    internal const string SessionHeaderName =
        "X-Corpus-Session";
    internal const int MaximumDecisionBodyBytes = 32 * 1024;

    private const string ContentSecurityPolicy =
        "default-src 'self'; img-src 'self' blob:; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
    private const string PermissionsPolicy =
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=()";

    public static Task PrepareReviewSamplesAsync(
        ReviewHostOptions options,
        IReadOnlyDictionary<
            string,
            IReadOnlyList<ReviewCandidate>> candidatesByMarket,
        CancellationToken cancellationToken) =>
        PrepareReviewSamplesAsync(
            options,
            candidatesByMarket,
            cancellationToken,
            workerPackageRoot: null);

    internal static async Task PrepareReviewSamplesAsync(
        ReviewHostOptions options,
        IReadOnlyDictionary<
            string,
            IReadOnlyList<ReviewCandidate>> candidatesByMarket,
        CancellationToken cancellationToken,
        string? workerPackageRoot)
    {
        await using var dataSource =
            await CorpusReviewDataSource.ComposeAsync(
                    options,
                    candidatesByMarket,
                    cancellationToken,
                    workerPackageRoot: workerPackageRoot)
                .ConfigureAwait(false);
    }

    public static async Task RunAsync(
        ReviewHostOptions options,
        CancellationToken cancellationToken) =>
        await RunAsync(
                options,
                workerPackageRoot: null,
                cancellationToken)
            .ConfigureAwait(false);

    internal static async Task RunAsync(
        ReviewHostOptions options,
        string? workerPackageRoot,
        CancellationToken cancellationToken) =>
        await RunAsync(
                options,
                workerPackageRoot,
                new ProductionReviewHostRunner(),
                cancellationToken)
            .ConfigureAwait(false);

    internal static async Task RunAsync(
        ReviewHostOptions options,
        string? workerPackageRoot,
        IReviewHostRunner runner,
        CancellationToken cancellationToken)
    {
        try
        {
            ValidateOptions(options);
            ArgumentNullException.ThrowIfNull(runner);
            var dataSource =
                await CorpusReviewDataSource.OpenAsync(
                        options,
                        cancellationToken,
                        workerPackageRoot: workerPackageRoot)
                    .ConfigureAwait(false);
            await RunOwnedDataSourceAsync(
                    options,
                    dataSource,
                    runner,
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
        catch
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        }
    }

    internal static async Task RunOwnedDataSourceAsync(
        ReviewHostOptions options,
        IReviewDataSource dataSource,
        IReviewHostRunner runner,
        CancellationToken cancellationToken,
        Action<Uri>? openBrowser = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(dataSource);
        ArgumentNullException.ThrowIfNull(runner);
        IReviewHostRunSession session;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            session = await runner.StartAsync(
                    options,
                    dataSource,
                    cancellationToken)
                .ConfigureAwait(false)
                ?? throw new InvalidOperationException();
        }
        catch
        {
            try
            {
                await dataSource.DisposeAsync()
                    .ConfigureAwait(false);
            }
            catch
            {
                // Preserve the runner start failure.
            }

            throw;
        }

        await using (session.ConfigureAwait(false))
        {
            if (options.OpenBrowser)
            {
                (openBrowser ?? OpenBrowser)(
                    session.NavigationUri);
            }

            await session.WaitForShutdownAsync(cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private sealed class ProductionReviewHostRunner
        : IReviewHostRunner
    {
        public async Task<IReviewHostRunSession> StartAsync(
            ReviewHostOptions options,
            IReviewDataSource dataSource,
            CancellationToken cancellationToken) =>
            await ReviewHost.StartAsync(
                    options,
                    dataSource,
                    cancellationToken)
                .ConfigureAwait(false);
    }

    internal static async Task<ReviewHostSession> StartAsync(
        ReviewHostOptions options,
        IReviewDataSource dataSource,
        CancellationToken cancellationToken)
    {
        ValidateOptions(options);
        ArgumentNullException.ThrowIfNull(dataSource);
        var sessionState = new ReviewSessionState(
            RandomNumberGenerator.GetBytes(32));
        WebApplication? application = null;
        try
        {
            var builder = WebApplication.CreateSlimBuilder(
                new WebApplicationOptions
                {
                    ApplicationName =
                        typeof(ReviewHost).Assembly.FullName,
                    ContentRootPath = AppContext.BaseDirectory,
                });
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(kestrel =>
            {
                kestrel.AddServerHeader = false;
                // The endpoint performs the smaller streaming bound itself so
                // oversized chunked bodies receive the same hardened response.
                kestrel.Limits.MaxRequestBodySize = null;
                kestrel.Limits.RequestHeadersTimeout =
                    TimeSpan.FromSeconds(10);
                kestrel.Limits.KeepAliveTimeout =
                    TimeSpan.FromSeconds(30);
                kestrel.Listen(
                    IPAddress.Loopback,
                    0,
                    listen => listen.Protocols =
                        HttpProtocols.Http1);
            });
            application = builder.Build();
            string? origin = null;
            string? expectedHost = null;

            application.UseRouting();
            application.Use(async (context, next) =>
            {
                ApplySecurityHeaders(context.Response);
                try
                {
                    await next(context).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                    when (context.RequestAborted.IsCancellationRequested)
                {
                }
                catch
                {
                    if (!context.Response.HasStarted)
                    {
                        context.Response.Clear();
                        ApplySecurityHeaders(context.Response);
                        context.Response.StatusCode =
                            StatusCodes.Status500InternalServerError;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                    }
                }
            });

            application.Use(async (context, next) =>
            {
                if (expectedHost is null
                    || !HasExactHeader(
                        context.Request.Headers,
                        "Host",
                        expectedHost))
                {
                    context.Response.StatusCode =
                        StatusCodes.Status400BadRequest;
                    await WriteErrorAsync(context.Response)
                        .ConfigureAwait(false);
                    return;
                }

                await next(context).ConfigureAwait(false);
            });

            application.Use(async (context, next) =>
            {
                var policy = context.GetEndpoint()?.Metadata
                    .GetMetadata<ReviewApiPolicy>();
                if (policy is null)
                {
                    await next(context).ConfigureAwait(false);
                    return;
                }

                if (!HasExactSession(
                        context.Request.Headers,
                        sessionState))
                {
                    context.Response.StatusCode =
                        StatusCodes.Status401Unauthorized;
                    await WriteErrorAsync(context.Response)
                        .ConfigureAwait(false);
                    return;
                }

                if (policy.RequiresOrigin
                    && (origin is null
                        || !HasExactHeader(
                            context.Request.Headers,
                            "Origin",
                            origin)))
                {
                    context.Response.StatusCode =
                        StatusCodes.Status403Forbidden;
                    await WriteErrorAsync(context.Response)
                        .ConfigureAwait(false);
                    return;
                }

                await next(context).ConfigureAwait(false);
            });

            MapStaticAssets(application);
            application.MapGet(
                "/api/review/next",
                async context =>
                {
                    var item = await dataSource.GetNextAsync(
                            context.RequestAborted)
                        .ConfigureAwait(false);
                    if (item is null)
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status204NoContent;
                        return;
                    }

                    await WriteJsonAsync(
                            context.Response,
                            item,
                            WorkbenchJsonContext.Default.ReviewItemView,
                            context.RequestAborted)
                        .ConfigureAwait(false);
                })
                .WithMetadata(ReviewApiPolicy.ReadOnly);
            application.MapGet(
                "/api/documents/{id}/pages/{index}.png",
                async context =>
                {
                    var id = context.Request.RouteValues["id"]
                        as string;
                    var indexText =
                        context.Request.RouteValues["index"]
                            as string;
                    if (id is null
                        || !int.TryParse(
                            indexText,
                            NumberStyles.None,
                            CultureInfo.InvariantCulture,
                            out var pageIndex))
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status404NotFound;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                        return;
                    }

                    if (context.Request.Headers.ContainsKey(
                            "Range"))
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status400BadRequest;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                        return;
                    }

                    try
                    {
                        var preview =
                            await dataSource.GetPreviewAsync(
                                    id,
                                    pageIndex,
                                    context.RequestAborted)
                                .ConfigureAwait(false);
                        context.Response.StatusCode =
                            StatusCodes.Status200OK;
                        context.Response.ContentType = "image/png";
                        context.Response.ContentLength =
                            preview.PngBytes.Length;
                        await context.Response.Body.WriteAsync(
                                preview.PngBytes,
                                context.RequestAborted)
                            .ConfigureAwait(false);
                    }
                    catch (WorkbenchException)
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status404NotFound;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                    }
                })
                .WithMetadata(ReviewApiPolicy.ReadOnly);
            application.MapPost(
                "/api/documents/{id}/decisions",
                async context =>
                {
                    var id = context.Request.RouteValues["id"]
                        as string;
                    if (id is null)
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status404NotFound;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                        return;
                    }

                    if (!string.Equals(
                            context.Request.ContentType,
                            "application/json",
                            StringComparison.Ordinal)
                        || context.Request.ContentLength
                            is > MaximumDecisionBodyBytes)
                    {
                        context.Response.StatusCode =
                            context.Request.ContentLength
                                is > MaximumDecisionBodyBytes
                                ? StatusCodes
                                    .Status413PayloadTooLarge
                                : StatusCodes
                                    .Status415UnsupportedMediaType;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                        return;
                    }

                    ReviewDecisionRequest request;
                    try
                    {
                        var body = await ReadBoundedBodyAsync(
                                context.Request,
                                context.RequestAborted)
                            .ConfigureAwait(false);
                        request = WorkbenchJson.Parse(
                            body,
                            WorkbenchJsonContext.Default
                                .ReviewDecisionRequest);
                    }
                    catch (RequestBodyTooLargeException)
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status413PayloadTooLarge;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                        return;
                    }
                    catch (Exception exception) when (
                        exception is JsonException
                            or NotSupportedException)
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status400BadRequest;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                        return;
                    }

                    try
                    {
                        var outcome = await dataSource.DecideAsync(
                                id,
                                request,
                                context.RequestAborted)
                            .ConfigureAwait(false);
                        context.Response.StatusCode = outcome.Stale
                            ? StatusCodes.Status409Conflict
                            : StatusCodes.Status200OK;
                        await WriteJsonAsync(
                                context.Response,
                                outcome,
                                WorkbenchJsonContext.Default
                                    .ReviewDecisionOutcome,
                                context.RequestAborted)
                            .ConfigureAwait(false);
                    }
                    catch (ReviewDecisionConflictException)
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status409Conflict;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                    }
                    catch (WorkbenchException)
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status400BadRequest;
                        await WriteErrorAsync(context.Response)
                            .ConfigureAwait(false);
                    }
                })
                .WithMetadata(ReviewApiPolicy.Mutating);
            MapUnsupportedApiMethods(application);

            await application.StartAsync(cancellationToken)
                .ConfigureAwait(false);
            var addresses = application.Services
                .GetRequiredService<IServer>()
                .Features
                .Get<IServerAddressesFeature>()
                ?.Addresses
                ?? throw new InvalidOperationException();
            var bound = addresses
                .Select(static value => new Uri(value))
                .Single(uri =>
                    IPAddress.TryParse(
                        uri.Host,
                        out var address)
                    && address.Equals(IPAddress.Loopback));
            origin =
                $"http://localhost:{bound.Port.ToString(CultureInfo.InvariantCulture)}";
            expectedHost =
                $"localhost:{bound.Port.ToString(CultureInfo.InvariantCulture)}";
            sessionState.Activate();
            var token = sessionState.GetNavigationToken();
            var navigation = new Uri(origin + "/#" + token);
            return new ReviewHostSession(
                application,
                dataSource,
                sessionState,
                IPAddress.Loopback,
                origin,
                navigation);
        }
        catch
        {
            sessionState.Deactivate();
            if (application is not null)
            {
                await application.DisposeAsync()
                    .ConfigureAwait(false);
            }

            sessionState.ZeroSecret();
            throw;
        }
    }

    private static void MapStaticAssets(
        WebApplication application)
    {
        MapStaticAsset(application, "/", "index.html", "text/html; charset=utf-8");
        MapStaticAsset(
            application,
            "/index.html",
            "index.html",
            "text/html; charset=utf-8");
        MapStaticAsset(
            application,
            "/review.css",
            "review.css",
            "text/css; charset=utf-8");
        MapStaticAsset(
            application,
            "/review.js",
            "review.js",
            "text/javascript; charset=utf-8");
        MapStaticAsset(
            application,
            "/preview-request-state.js",
            "preview-request-state.js",
            "text/javascript; charset=utf-8");
    }

    private static void MapUnsupportedApiMethods(
        WebApplication application)
    {
        string[] apiMethods =
        [
            HttpMethods.Get,
            HttpMethods.Post,
            HttpMethods.Head,
            HttpMethods.Put,
            HttpMethods.Delete,
            HttpMethods.Patch,
            HttpMethods.Options,
            HttpMethods.Trace,
            HttpMethods.Connect,
        ];
        foreach (var (route, supportedMethods) in new[]
                 {
                     ("/api/review/next", new[] { HttpMethods.Get }),
                     (
                         "/api/documents/{id}/pages/{index}.png",
                         new[] { HttpMethods.Get }),
                     (
                         "/api/documents/{id}/decisions",
                         new[] { HttpMethods.Post }),
                 })
        {
            var unsupportedMethods = apiMethods
                .Except(supportedMethods, StringComparer.Ordinal)
                .ToArray();
            application.MapMethods(
                    route,
                    unsupportedMethods,
                    static context =>
                    {
                        context.Response.StatusCode =
                            StatusCodes.Status405MethodNotAllowed;
                        return Task.CompletedTask;
                    })
                .WithMetadata(ReviewApiPolicy.ReadOnly);
        }
    }

    private static void MapStaticAsset(
        WebApplication application,
        string route,
        string fileName,
        string contentType) =>
        application.MapGet(
            route,
            async context =>
            {
                var root = Path.Combine(
                    AppContext.BaseDirectory,
                    "Review",
                    "wwwroot");
                var path = Path.Combine(root, fileName);
                byte[] bytes;
                try
                {
                    bytes = await File.ReadAllBytesAsync(
                            path,
                            context.RequestAborted)
                        .ConfigureAwait(false);
                }
                catch
                {
                    context.Response.StatusCode =
                        StatusCodes.Status404NotFound;
                    await WriteErrorAsync(context.Response)
                        .ConfigureAwait(false);
                    return;
                }

                context.Response.ContentType = contentType;
                context.Response.ContentLength = bytes.Length;
                await context.Response.Body.WriteAsync(
                        bytes,
                        context.RequestAborted)
                    .ConfigureAwait(false);
            });

    private static bool HasExactSession(
        IHeaderDictionary headers,
        ReviewSessionState sessionState)
    {
        if (!headers.TryGetValue(
                SessionHeaderName,
                out var values)
            || values.Count != 1
            || values[0] is not { Length: 64 } value
            || value.Any(static character =>
                character is not (>= '0' and <= '9')
                    and not (>= 'a' and <= 'f')))
        {
            return false;
        }

        var supplied = Convert.FromHexString(value);
        try
        {
            return sessionState.HasExactToken(supplied);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(supplied);
        }
    }

    private static bool HasExactHeader(
        IHeaderDictionary headers,
        string name,
        string expected) =>
        headers.TryGetValue(name, out var values)
        && values.Count == 1
        && string.Equals(
            values[0],
            expected,
            StringComparison.Ordinal);

    private static async Task<byte[]> ReadBoundedBodyAsync(
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await request.Body.ReadAsync(
                    buffer,
                    cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (stream.Length + read
                > MaximumDecisionBodyBytes)
            {
                throw new RequestBodyTooLargeException();
            }

            stream.Write(buffer, 0, read);
        }

        return stream.ToArray();
    }

    private static async Task WriteJsonAsync<T>(
        HttpResponse response,
        T value,
        System.Text.Json.Serialization.Metadata.JsonTypeInfo<T>
            typeInfo,
        CancellationToken cancellationToken)
    {
        response.ContentType = "application/json; charset=utf-8";
        await JsonSerializer.SerializeAsync(
                response.Body,
                value,
                typeInfo,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static Task WriteErrorAsync(
        HttpResponse response)
    {
        response.ContentType = "application/json; charset=utf-8";
        return JsonSerializer.SerializeAsync(
            response.Body,
            new ReviewError("request_failed"),
            WorkbenchJsonContext.Default.ReviewError,
            CancellationToken.None);
    }

    private static void ApplySecurityHeaders(
        HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        response.Headers.XContentTypeOptions = "nosniff";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["Content-Security-Policy"] =
            ContentSecurityPolicy;
        response.Headers["Permissions-Policy"] =
            PermissionsPolicy;
        response.Headers["Cross-Origin-Opener-Policy"] =
            "same-origin";
        response.Headers["Cross-Origin-Resource-Policy"] =
            "same-origin";
        response.Headers["X-Frame-Options"] = "DENY";
    }

    private static void ValidateOptions(
        ReviewHostOptions? options)
    {
        if (options is null
            || !Path.IsPathFullyQualified(options.VaultRoot)
            || !IsNormalizedIdentifier(options.ReviewerId)
            || !IsNormalizedIdentifier(options.CatalogEpoch))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }
    }

    private static bool IsNormalizedIdentifier(string value) =>
        value is not null
        && value.Length is > 0 and <= 128
        && value.IsNormalized(NormalizationForm.FormC)
        && value.All(static character =>
            character is >= 'a' and <= 'z'
                or >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '-'
                or '_'
                or '.');

    private static void OpenBrowser(Uri navigation)
    {
        try
        {
            using var process = Process.Start(
                new ProcessStartInfo(navigation.AbsoluteUri)
                {
                    UseShellExecute = true,
                });
        }
        catch
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        }
    }

    private sealed class RequestBodyTooLargeException : Exception;
}

internal sealed class ReviewHostSession :
    IReviewHostRunSession
{
    private WebApplication? _application;
    private IReviewDataSource? _dataSource;
    private ReviewSessionState? _sessionState;

    internal ReviewHostSession(
        WebApplication application,
        IReviewDataSource dataSource,
        ReviewSessionState sessionState,
        IPAddress boundAddress,
        string origin,
        Uri navigationUri)
    {
        _application = application;
        _dataSource = dataSource;
        _sessionState = sessionState;
        BoundAddress = boundAddress;
        Origin = origin;
        NavigationUri = navigationUri;
    }

    internal IPAddress BoundAddress { get; }

    internal string Origin { get; }

    internal Uri NavigationUri { get; }

    Uri IReviewHostRunSession.NavigationUri => NavigationUri;

    internal async Task WaitForShutdownAsync(
        CancellationToken cancellationToken)
    {
        var application = _application
            ?? throw new ObjectDisposedException(
                nameof(ReviewHostSession));
        await application.WaitForShutdownAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    Task IReviewHostRunSession.WaitForShutdownAsync(
        CancellationToken cancellationToken) =>
        WaitForShutdownAsync(cancellationToken);

    internal void BeginShutdown() =>
        Volatile.Read(ref _sessionState)?.Deactivate();

    public async ValueTask DisposeAsync()
    {
        BeginShutdown();
        var application = Interlocked.Exchange(
            ref _application,
            null);
        var dataSource = Interlocked.Exchange(
            ref _dataSource,
            null);
        var sessionState = Interlocked.Exchange(
            ref _sessionState,
            null);
        sessionState?.Deactivate();

        try
        {
            if (application is not null)
            {
                using var timeout =
                    new CancellationTokenSource(
                        TimeSpan.FromSeconds(5));
                try
                {
                    await application.StopAsync(timeout.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }

                await application.DisposeAsync()
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            if (dataSource is not null)
            {
                await dataSource.DisposeAsync()
                    .ConfigureAwait(false);
            }

            sessionState?.ZeroSecret();
        }
    }
}

internal sealed record ReviewApiPolicy(bool RequiresOrigin)
{
    internal static ReviewApiPolicy ReadOnly { get; } = new(false);

    internal static ReviewApiPolicy Mutating { get; } = new(true);
}

internal enum ReviewDecisionFaultPoint
{
    AfterPendingCheckpoint,
    AfterCorrectionPersisted,
    AfterApprovalRecorded,
}

internal sealed class ReviewSessionState
{
    private byte[]? _secret;
    private int _active;

    internal ReviewSessionState(byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length != 32)
        {
            throw new ArgumentException(nameof(secret));
        }

        _secret = secret;
    }

    internal void Activate() => Volatile.Write(ref _active, 1);

    internal void Deactivate() => Interlocked.Exchange(ref _active, 0);

    internal bool HasExactToken(ReadOnlySpan<byte> supplied)
    {
        if (Volatile.Read(ref _active) == 0)
        {
            return false;
        }

        var secret = Volatile.Read(ref _secret);
        return secret is { Length: 32 }
            && supplied.Length == secret.Length
            && CryptographicOperations.FixedTimeEquals(
                supplied,
                secret)
            && Volatile.Read(ref _active) != 0;
    }

    internal string GetNavigationToken()
    {
        var secret = Volatile.Read(ref _secret)
            ?? throw new ObjectDisposedException(
                nameof(ReviewSessionState));
        return Convert.ToHexStringLower(secret);
    }

    internal void ZeroSecret()
    {
        Deactivate();
        var secret = Interlocked.Exchange(ref _secret, null);
        if (secret is not null)
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}

internal sealed class CorpusReviewDataSource : IReviewDataSource
{
    private readonly SemaphoreSlim _mutation = new(1, 1);
    private readonly ApprovalLedgerService _approval;
    private readonly string _reviewerId;
    private readonly ImmutableDictionary<
        string,
        OfficialRuleCatalogSnapshot> _rules;
    private CorpusWorkerPackageWorkspace? _workerWorkspace;
    private readonly CorpusWorkerPackageIdentity _workerIdentity;
    private readonly ImmutableDictionary<
        string,
        ImmutableArray<string>> _sampleIdsByMarket;
    private readonly Action<ReviewDecisionFaultPoint>? _injectFault;
    private CorpusVault? _vault;
    private DocumentPreviewService? _preview;

    private CorpusReviewDataSource(
        CorpusVault vault,
        string reviewerId,
        ImmutableDictionary<
            string,
            OfficialRuleCatalogSnapshot> rules,
        CorpusWorkerPackageWorkspace workerWorkspace,
        CorpusWorkerPackageIdentity workerIdentity,
        ApprovalLedgerService approval,
        ImmutableDictionary<
            string,
            ImmutableArray<string>> sampleIdsByMarket,
        Action<ReviewDecisionFaultPoint>? injectFault)
    {
        _vault = vault;
        _reviewerId = reviewerId;
        _rules = rules;
        _workerWorkspace = workerWorkspace;
        _workerIdentity = workerIdentity;
        _approval = approval;
        _sampleIdsByMarket = sampleIdsByMarket;
        _injectFault = injectFault;
        _preview = new DocumentPreviewService(vault);
    }

    internal static async Task<CorpusReviewDataSource> OpenAsync(
        ReviewHostOptions options,
        CancellationToken cancellationToken,
        Action<ReviewDecisionFaultPoint>? injectFault = null,
        string? workerPackageRoot = null)
    {
        var vault = CorpusVault.OpenExisting(options.VaultRoot);
        try
        {
            var rules = await LoadRulesAsync(cancellationToken)
                .ConfigureAwait(false);
            var states = await vault.Store.LoadAllLabelStatesAsync(
                    cancellationToken)
                .ConfigureAwait(false);
            var revisions = states
                .Select(static state => state.PreviousRevision)
                .WhereNotNull()
                .ToArray();
            if (revisions.Length == 0)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
            }

            var identity = IdentityFrom(revisions[0]);
            if (revisions.Any(revision =>
                    IdentityFrom(revision) != identity))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.WorkerAttestationMismatch);
            }

            var scope = CreateScope(options.CatalogEpoch);
            var sampleIdsByMarket = await LoadAndValidateSamplesAsync(
                    vault,
                    scope,
                    states,
                    rules,
                    cancellationToken)
                .ConfigureAwait(false);
            var packageRoot = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(
                    workerPackageRoot
                    ?? AppContext.BaseDirectory));
            var executablePath = Path.GetFullPath(
                Path.Combine(
                    packageRoot,
                    identity.ExecutableRelativePath.Replace(
                        '/',
                        Path.DirectorySeparatorChar)));
            var relativeExecutable = Path.GetRelativePath(
                packageRoot,
                executablePath);
            if (relativeExecutable.StartsWith(
                    "..",
                    StringComparison.Ordinal)
                || Path.IsPathFullyQualified(relativeExecutable))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.WorkerAttestationMismatch);
            }

            var workerWorkspace =
                await CorpusWorkerPackageWorkspace.OpenAsync(
                        packageRoot,
                        executablePath,
                        identity.Sha256,
                        options.VaultRoot,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (workerWorkspace.Identity != identity)
            {
                await workerWorkspace.DisposeAsync()
                    .ConfigureAwait(false);
                throw new WorkbenchException(
                    WorkbenchFailureCode.WorkerAttestationMismatch);
            }

            try
            {
                var approval = new ApprovalLedgerService(
                    vault,
                    scope,
                    rules.Values,
                    workerWorkspace);
                return new CorpusReviewDataSource(
                    vault,
                    options.ReviewerId.Normalize(),
                    rules,
                    workerWorkspace,
                    identity,
                    approval,
                    sampleIdsByMarket,
                    injectFault);
            }
            catch
            {
                await workerWorkspace.DisposeAsync()
                    .ConfigureAwait(false);
                throw;
            }
        }
        catch (CorpusWorkerAttestationException)
        {
            await vault.DisposeAsync().ConfigureAwait(false);
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch);
        }
        catch
        {
            await vault.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal static async Task<CorpusReviewDataSource> ComposeAsync(
        ReviewHostOptions options,
        IReadOnlyDictionary<
            string,
            IReadOnlyList<ReviewCandidate>> candidatesByMarket,
        CancellationToken cancellationToken,
        Action<ReviewDecisionFaultPoint>? injectFault = null,
        string? workerPackageRoot = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(candidatesByMarket);
        var vault = CorpusVault.OpenExisting(options.VaultRoot);
        try
        {
            var rules = await LoadRulesAsync(cancellationToken)
                .ConfigureAwait(false);
            var states = await vault.Store.LoadAllLabelStatesAsync(
                    cancellationToken)
                .ConfigureAwait(false);
            if (candidatesByMarket.Count
                    != PilotCatalog.MarketIds.Length
                || candidatesByMarket.Keys.Any(market =>
                    !PilotCatalog.MarketIds.Contains(
                        market,
                        StringComparer.Ordinal)))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidArguments);
            }

            var scope = CreateScope(options.CatalogEpoch);
            var proofs = new List<ReviewSampleProof>(
                PilotCatalog.MarketIds.Length);
            foreach (var marketId in PilotCatalog.MarketIds)
            {
                if (!candidatesByMarket.TryGetValue(
                        marketId,
                        out var candidates)
                    || candidates is null)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidArguments);
                }

                var statesById = states
                    .Where(state =>
                        state.PreviousRevision is not null
                        && string.Equals(
                            state.Document.MarketId,
                            marketId,
                            StringComparison.Ordinal))
                    .ToDictionary(
                        static state => state.Document.DocumentId,
                        StringComparer.Ordinal);
                if (statesById.Count != candidates.Count)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidCheckpoint);
                }

                var revisionHashes =
                    ImmutableDictionary.CreateBuilder<
                        string,
                        string>(StringComparer.Ordinal);
                foreach (var candidate in candidates)
                {
                    if (!statesById.TryGetValue(
                            candidate.DocumentId,
                            out var state)
                        || !string.Equals(
                            candidate.ContentSha256,
                            state.Document.ContentSha256,
                            StringComparison.Ordinal)
                        || !string.Equals(
                            candidate.SourceFamilyId,
                            state.Document.SourceFamilyId,
                            StringComparison.Ordinal)
                        || !string.Equals(
                            candidate.InputKind,
                            state.Document.InputKind,
                            StringComparison.Ordinal))
                    {
                        throw new WorkbenchException(
                            WorkbenchFailureCode.InvalidCheckpoint);
                    }

                    var revision = state.PreviousRevision!;
                    if (!FixedHashEquals(
                            revision.RuleCatalogSha256,
                            rules[marketId].CatalogSha256))
                    {
                        throw new WorkbenchException(
                            WorkbenchFailureCode.InvalidCheckpoint);
                    }

                    revisionHashes.Add(
                        candidate.DocumentId,
                        revision.RevisionSha256);
                }

                var proof = ReviewSampleProof.Create(
                    scope,
                    marketId,
                    rules[marketId].CatalogSha256,
                    candidates,
                    revisionHashes.ToImmutable());
                _ = proof.Validate(
                    scope,
                    rules[marketId].CatalogSha256,
                    candidates,
                    revisionHashes.ToImmutable());
                proofs.Add(proof);
            }

            foreach (var proof in proofs)
            {
                await vault.Store.SaveReviewSampleProofAsync(
                        proof,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            await vault.DisposeAsync().ConfigureAwait(false);
        }

        return await OpenAsync(
                options,
                cancellationToken,
                injectFault,
                workerPackageRoot)
            .ConfigureAwait(false);
    }

    internal ImmutableArray<string>
        GetReviewSampleDocumentIds(string marketId)
    {
        if (!PilotCatalog.MarketIds.Contains(
                marketId,
                StringComparer.Ordinal)
            || !_sampleIdsByMarket.TryGetValue(
                marketId,
                out var documentIds))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }

        return documentIds;
    }

    public async Task<ReviewItemView?> GetNextAsync(
        CancellationToken cancellationToken)
    {
        var vault = RequireVault();
        var preview = RequirePreview();
        var states = await vault.Store.LoadAllLabelStatesAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var approved = await _approval.GetOwnerApprovalViewAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var decisions = await vault.Store
            .LoadReviewDecisionCheckpointsAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var schedules = await vault.Store
            .LoadReviewScheduleCheckpointsAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var approvedIds = approved.Documents
            .Select(static item => item.DocumentId)
            .ToHashSet(StringComparer.Ordinal);
        var currentDecisionByDocument = decisions
            .GroupBy(
                static item => item.DocumentId,
                StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => group
                    .OrderByDescending(
                        static item => item.RecordedAtUtc)
                    .First(),
                StringComparer.Ordinal);
        var currentScheduleByDocument = schedules
            .GroupBy(
                static item => item.DocumentId,
                StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => group.Single(),
                StringComparer.Ordinal);
        var stateById = states.ToDictionary(
            static state => state.Document.DocumentId,
            StringComparer.Ordinal);
        var sample = PilotCatalog.MarketIds
            .SelectMany(market =>
                _sampleIdsByMarket[market])
            .Select(documentId =>
                stateById.TryGetValue(documentId, out var state)
                    ? state
                    : throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidCheckpoint))
            .ToArray();
        var pending = sample
            .Where(state =>
            {
                if (approvedIds.Contains(
                        state.Document.DocumentId))
                {
                    return false;
                }

                if (!currentDecisionByDocument.TryGetValue(
                        state.Document.DocumentId,
                        out var decision)
                    || state.PreviousRevision is null
                    || !FixedHashEquals(
                        state.PreviousRevision.RevisionSha256,
                        decision.OutcomeRevisionSha256))
                {
                    return true;
                }

                return decision.Decision
                    != ReviewDecisionKind.RejectDocument;
            })
            .OrderBy(state =>
                IsCurrentDefer(
                    state,
                    currentScheduleByDocument))
            .ThenBy(state => Array.IndexOf(sample, state))
            .ToArray();
        if (pending.Length == 0)
        {
            return null;
        }

        var selected = pending[0];
        var marketItems = sample
            .Where(state => string.Equals(
                state.Document.MarketId,
                selected.Document.MarketId,
                StringComparison.Ordinal))
            .ToArray();
        var position = Array.FindIndex(
            marketItems,
            item => string.Equals(
                item.Document.DocumentId,
                selected.Document.DocumentId,
                StringComparison.Ordinal)) + 1;
        var revision = selected.PreviousRevision!;
        var pageCount = await preview.GetPageCountAsync(
                selected.Document.DocumentId,
                cancellationToken)
            .ConfigureAwait(false);
        var rules = _rules[selected.Document.MarketId];
        CurrentRevisionValidator.Validate(
            selected.Document,
            revision,
            rules,
            _workerIdentity,
            pageCount);

        var source = SelectOfficialSource(rules);
        return new ReviewItemView(
            selected.Document.MarketId,
            position,
            PilotCatalog.DirectReviewTargetPerMarket,
            true,
            selected.Document.DocumentId,
            pageCount,
            revision.Fields,
            source.Uri,
            rules.Document.SchemaVersion,
            rules.CatalogSha256,
            revision.RevisionSha256);
    }

    public Task<DocumentPreview> GetPreviewAsync(
        string documentId,
        int pageIndex,
        CancellationToken cancellationToken) =>
        RequirePreview().RenderAsync(
            documentId,
            pageIndex,
            cancellationToken);

    public async Task<ReviewDecisionOutcome> DecideAsync(
        string documentId,
        ReviewDecisionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        DocumentPreviewService.ValidateRequest(documentId, 0);
        ValidateRevisionHash(request.LabelRevisionSha256);
        ValidateDecisionShape(request);
        var requestHash = DecisionHash(documentId, request);
        await _mutation.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var store = RequireVault().Store;
            var replayKey = await store
                    .LoadReviewDecisionCheckpointAsync(
                        request.LabelRevisionSha256,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (replayKey is not null)
            {
                RequireMatchingReplay(replayKey, requestHash);
                if (!replayKey.Completed)
                {
                    var recovered =
                        await CompletePendingDecisionAsync(
                                documentId,
                                request,
                                replayKey,
                                cancellationToken)
                            .ConfigureAwait(false);
                    await store.SaveReviewDecisionCheckpointAsync(
                            replayKey with
                            {
                                OutcomeRevisionSha256 =
                                    recovered
                                        .LabelRevisionSha256,
                                Completed = true,
                            },
                            cancellationToken)
                        .ConfigureAwait(false);
                    return recovered;
                }

                await RequireCompletedApprovalAsync(
                        replayKey,
                        cancellationToken)
                    .ConfigureAwait(false);
                return new ReviewDecisionOutcome(
                    false,
                    replayKey.OutcomeRevisionSha256);
            }

            if (request.Decision == ReviewDecisionKind.Defer)
            {
                replayKey = await store
                    .LoadReviewScheduleCheckpointAsync(
                        request.LabelRevisionSha256,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (replayKey is not null)
                {
                    RequireMatchingReplay(replayKey, requestHash);
                    return new ReviewDecisionOutcome(
                        false,
                        replayKey.OutcomeRevisionSha256);
                }
            }

            var state = await store.LoadLabelStateAsync(
                    documentId,
                    cancellationToken)
                .ConfigureAwait(false);
            var current = state.PreviousRevision
                ?? throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidState);
            var pageCount = await RequirePreview()
                .GetPageCountAsync(
                    documentId,
                    cancellationToken)
                .ConfigureAwait(false);
            CurrentRevisionValidator.Validate(
                state.Document,
                current,
                _rules[state.Document.MarketId],
                _workerIdentity,
                pageCount);
            if (!FixedHashEquals(
                    current.RevisionSha256,
                    request.LabelRevisionSha256))
            {
                return new ReviewDecisionOutcome(
                    true,
                    current.RevisionSha256);
            }

            var acceptedAtUtc = TimeProvider.System.GetUtcNow()
                .ToUniversalTime();
            if (acceptedAtUtc < current.CreatedAtUtc)
            {
                acceptedAtUtc = current.CreatedAtUtc;
            }

            var pending = await store
                .SaveReviewDecisionCheckpointAsync(
                    new ReviewDecisionCheckpoint(
                        PilotCatalog.SchemaVersion,
                        documentId,
                        request.LabelRevisionSha256,
                        requestHash,
                        request.Decision,
                        current.RevisionSha256,
                        acceptedAtUtc,
                        Completed:
                            request.Decision
                                == ReviewDecisionKind.Defer),
                    cancellationToken)
                .ConfigureAwait(false);
            if (request.Decision == ReviewDecisionKind.Defer)
            {
                return new ReviewDecisionOutcome(
                    false,
                    current.RevisionSha256);
            }

            _injectFault?.Invoke(
                ReviewDecisionFaultPoint.AfterPendingCheckpoint);
            var outcome = await CompletePendingDecisionAsync(
                    documentId,
                    request,
                    pending,
                    cancellationToken)
                .ConfigureAwait(false);
            await store.SaveReviewDecisionCheckpointAsync(
                    pending with
                    {
                        OutcomeRevisionSha256 =
                            outcome.LabelRevisionSha256,
                        Completed = true,
                    },
                    cancellationToken)
                .ConfigureAwait(false);
            return outcome;
        }
        finally
        {
            _mutation.Release();
        }
    }

    private async Task<ReviewDecisionOutcome>
        CompletePendingDecisionAsync(
        string documentId,
        ReviewDecisionRequest request,
        ReviewDecisionCheckpoint checkpoint,
        CancellationToken cancellationToken)
    {
        var state = await RequireVault().Store.LoadLabelStateAsync(
                documentId,
                cancellationToken)
            .ConfigureAwait(false);
        var current = state.PreviousRevision
            ?? throw new ReviewDecisionConflictException();
        var pageCount = await RequirePreview().GetPageCountAsync(
                documentId,
                cancellationToken)
            .ConfigureAwait(false);
        CurrentRevisionValidator.Validate(
            state.Document,
            current,
            _rules[state.Document.MarketId],
            _workerIdentity,
            pageCount);

        LabelRevision outcomeRevision;
        switch (checkpoint.Decision)
        {
            case ReviewDecisionKind.ApproveExact:
                if (!FixedHashEquals(
                        current.RevisionSha256,
                        checkpoint.ExpectedRevisionSha256))
                {
                    throw new ReviewDecisionConflictException();
                }

                outcomeRevision = current;
                await RecordReviewAsync(
                        outcomeRevision,
                        checkpoint.RecordedAtUtc,
                        cancellationToken)
                    .ConfigureAwait(false);
                _injectFault?.Invoke(
                    ReviewDecisionFaultPoint.AfterApprovalRecorded);
                break;
            case ReviewDecisionKind.CorrectAndApprove:
                if (FixedHashEquals(
                        current.RevisionSha256,
                        checkpoint.ExpectedRevisionSha256))
                {
                    outcomeRevision = await CorrectAsync(
                            state,
                            request.CorrectedFields,
                            checkpoint.RecordedAtUtc,
                            cancellationToken)
                        .ConfigureAwait(false);
                    _injectFault?.Invoke(
                        ReviewDecisionFaultPoint
                            .AfterCorrectionPersisted);
                }
                else if (string.Equals(
                             current.PreviousRevisionSha256,
                             checkpoint.ExpectedRevisionSha256,
                             StringComparison.Ordinal)
                         && FieldsEqual(
                             current.Fields,
                             request.CorrectedFields))
                {
                    outcomeRevision = current;
                }
                else
                {
                    throw new ReviewDecisionConflictException();
                }

                CurrentRevisionValidator.Validate(
                    state.Document,
                    outcomeRevision,
                    _rules[state.Document.MarketId],
                    _workerIdentity,
                    pageCount);
                await RecordReviewAsync(
                        outcomeRevision,
                        checkpoint.RecordedAtUtc,
                        cancellationToken)
                    .ConfigureAwait(false);
                _injectFault?.Invoke(
                    ReviewDecisionFaultPoint.AfterApprovalRecorded);
                break;
            case ReviewDecisionKind.RejectDocument:
                if (!FixedHashEquals(
                        current.RevisionSha256,
                        checkpoint.ExpectedRevisionSha256))
                {
                    throw new ReviewDecisionConflictException();
                }

                outcomeRevision = current;
                break;
            default:
                throw new ReviewDecisionConflictException();
        }

        return new ReviewDecisionOutcome(
            false,
            outcomeRevision.RevisionSha256);
    }

    private async Task RequireCompletedApprovalAsync(
        ReviewDecisionCheckpoint checkpoint,
        CancellationToken cancellationToken)
    {
        if (checkpoint.Decision is not (
                ReviewDecisionKind.ApproveExact
                or ReviewDecisionKind.CorrectAndApprove))
        {
            return;
        }

        var approved = await _approval.GetOwnerApprovalViewAsync(
                cancellationToken)
            .ConfigureAwait(false);
        if (!approved.Documents.Any(item =>
                string.Equals(
                    item.DocumentId,
                    checkpoint.DocumentId,
                    StringComparison.Ordinal)
                && string.Equals(
                    item.LabelRevisionId,
                    "revision-"
                        + checkpoint.OutcomeRevisionSha256,
                    StringComparison.Ordinal)))
        {
            throw new ReviewDecisionConflictException();
        }
    }

    private static void RequireMatchingReplay(
        ReviewDecisionCheckpoint checkpoint,
        string requestHash)
    {
        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(checkpoint.RequestSha256),
                Convert.FromHexString(requestHash)))
        {
            throw new ReviewDecisionConflictException();
        }
    }

    public async ValueTask DisposeAsync()
    {
        var vault = Interlocked.Exchange(ref _vault, null);
        var workerWorkspace = Interlocked.Exchange(
            ref _workerWorkspace,
            null);
        Interlocked.Exchange(ref _preview, null);
        _mutation.Dispose();
        try
        {
            if (workerWorkspace is not null)
            {
                await workerWorkspace.DisposeAsync()
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            if (vault is not null)
            {
                await vault.DisposeAsync()
                    .ConfigureAwait(false);
            }
        }
    }

    private async Task<LabelRevision> CorrectAsync(
        LabelDraftState state,
        ImmutableArray<LabeledField> correctedFields,
        DateTimeOffset createdAtUtc,
        CancellationToken cancellationToken)
    {
        var current = state.PreviousRevision
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        RequireCurrentEvidence(
            current.Fields,
            correctedFields);
        var rules = _rules[state.Document.MarketId];
        return await RequireVault().Store.PersistLabelRevisionAsync(
                state,
                new LabelDraft(correctedFields),
                rules,
                _workerIdentity,
                createdAtUtc,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private Task<ApprovalEntry> RecordReviewAsync(
        LabelRevision revision,
        DateTimeOffset approvedAtUtc,
        CancellationToken cancellationToken)
    {
        return _approval.RecordDirectReviewAsync(
            new DirectReviewDecision(
                revision.DocumentId,
                revision.RevisionId,
                _reviewerId,
                approvedAtUtc),
            cancellationToken);
    }

    internal static async Task<ImmutableDictionary<
        string,
        OfficialRuleCatalogSnapshot>> LoadRulesAsync(
        CancellationToken cancellationToken)
    {
        var builder = ImmutableDictionary.CreateBuilder<
            string,
            OfficialRuleCatalogSnapshot>(
                StringComparer.Ordinal);
        foreach (var market in PilotCatalog.MarketIds)
        {
            var path = Path.Combine(
                AppContext.BaseDirectory,
                "catalog",
                "invoice-explicit-due-date-v1."
                    + market
                    + ".json");
            var rules = await OfficialRuleCatalog.LoadAsync(
                    path,
                    cancellationToken)
                .ConfigureAwait(false);
            builder.Add(market, rules);
        }

        return builder.ToImmutable();
    }

    private static async Task<ImmutableDictionary<
        string,
        ImmutableArray<string>>> LoadAndValidateSamplesAsync(
        CorpusVault vault,
        PilotScope scope,
        IReadOnlyList<LabelDraftState> states,
        IReadOnlyDictionary<
            string,
            OfficialRuleCatalogSnapshot> rules,
        CancellationToken cancellationToken)
    {
        var result = ImmutableDictionary.CreateBuilder<
            string,
            ImmutableArray<string>>(StringComparer.Ordinal);
        foreach (var marketId in PilotCatalog.MarketIds)
        {
            var proof = await vault.Store
                .LoadReviewSampleProofAsync(
                    marketId,
                    cancellationToken)
                .ConfigureAwait(false)
                ?? throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidCheckpoint);
            var candidatesById = proof.Candidates.ToDictionary(
                static candidate => candidate.DocumentId,
                StringComparer.Ordinal);
            var marketStates = states.Where(state =>
                    state.PreviousRevision is not null
                    && string.Equals(
                        state.Document.MarketId,
                        marketId,
                        StringComparison.Ordinal))
                .OrderBy(
                    static state => state.Document.DocumentId,
                    StringComparer.Ordinal)
                .ToArray();
            if (marketStates.Length != proof.Candidates.Length)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidCheckpoint);
            }

            var currentCandidates = ImmutableArray
                .CreateBuilder<ReviewCandidate>(
                    marketStates.Length);
            var revisionHashes =
                ImmutableDictionary.CreateBuilder<
                    string,
                    string>(StringComparer.Ordinal);
            foreach (var state in marketStates)
            {
                if (!candidatesById.TryGetValue(
                        state.Document.DocumentId,
                        out var persisted))
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidCheckpoint);
                }

                currentCandidates.Add(
                    persisted with
                    {
                        ContentSha256 =
                            state.Document.ContentSha256,
                        SourceFamilyId =
                            state.Document.SourceFamilyId,
                        InputKind = state.Document.InputKind,
                    });
                var revision = state.PreviousRevision!;
                if (!FixedHashEquals(
                        revision.RuleCatalogSha256,
                        rules[marketId].CatalogSha256))
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidCheckpoint);
                }

                if (!proof
                        .CandidateRevisionSha256ByDocument
                        .TryGetValue(
                            state.Document.DocumentId,
                            out var selectedRevisionSha256))
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidCheckpoint);
                }

                if (!FixedHashEquals(
                        revision.RevisionSha256,
                        selectedRevisionSha256))
                {
                    var checkpoint = await vault.Store
                        .LoadReviewDecisionCheckpointAsync(
                            selectedRevisionSha256,
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (checkpoint is null
                        || checkpoint.Decision
                            != ReviewDecisionKind
                                .CorrectAndApprove
                        || !string.Equals(
                            revision.PreviousRevisionSha256,
                            selectedRevisionSha256,
                            StringComparison.Ordinal)
                        || !FixedHashEquals(
                            checkpoint.RequestSha256,
                            DecisionHash(
                                state.Document.DocumentId,
                                new ReviewDecisionRequest(
                                    selectedRevisionSha256,
                                    ReviewDecisionKind
                                        .CorrectAndApprove,
                                    revision.Fields)))
                        || checkpoint.Completed
                            && !FixedHashEquals(
                                checkpoint
                                    .OutcomeRevisionSha256,
                                revision.RevisionSha256))
                    {
                        throw new WorkbenchException(
                            WorkbenchFailureCode.InvalidCheckpoint);
                    }
                }

                revisionHashes.Add(
                    state.Document.DocumentId,
                    selectedRevisionSha256);
            }

            var sample = proof.Validate(
                scope,
                rules[marketId].CatalogSha256,
                currentCandidates.MoveToImmutable(),
                revisionHashes.ToImmutable());
            result.Add(marketId, sample.DocumentIds);
        }

        return result.ToImmutable();
    }

    private static PilotScope CreateScope(string catalogEpoch) =>
        new(
            PilotCatalog.SchemaVersion,
            catalogEpoch,
            PilotCatalog.ContractId,
            PilotCatalog.MarketIds,
            PilotCatalog.HeldOutTargetPerMarket,
            PilotCatalog.DirectReviewTargetPerMarket);

    private static CorpusWorkerPackageIdentity IdentityFrom(
        LabelRevision revision) =>
        new(
            revision.WorkerPackageManifestId,
            revision.WorkerPackageManifestVersion,
            revision.WorkerPackageSha256,
            revision.WorkerExecutableRelativePath,
            revision.WorkerExecutableSha256);

    private static OfficialRuleSource SelectOfficialSource(
        OfficialRuleCatalogSnapshot rules)
    {
        var dueRule =
            rules.RulesByFieldId["payment_due_date"];
        var sourceId = dueRule.SourceIds[0];
        return rules.Document.Sources.Single(
            source => string.Equals(
                source.Id,
                sourceId,
                StringComparison.Ordinal));
    }

    internal static void ValidateDecisionShape(
        ReviewDecisionRequest request)
    {
        if (request.CorrectedFields.IsDefault
            || request.Decision
                == ReviewDecisionKind.ApproveExact
                && !request.CorrectedFields.IsEmpty
            || request.Decision
                is ReviewDecisionKind.RejectDocument
                    or ReviewDecisionKind.Defer
                && !request.CorrectedFields.IsEmpty
            || request.Decision
                == ReviewDecisionKind.CorrectAndApprove
                && request.CorrectedFields.Length
                    != PilotCatalog.RequiredFieldIds.Length
            || request.CorrectedFields.Any(field =>
                field.NormalizedValue is null
                || field.NormalizedValue.Length
                    is 0 or > 1024
                || !field.NormalizedValue.IsNormalized(
                    NormalizationForm.FormC)
                || field.NormalizedValue
                    != field.NormalizedValue.Trim()
                || field.NormalizedValue.Any(
                    static character =>
                        char.IsControl(character)
                        || char.IsSurrogate(character))))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }
    }

    private static void RequireCurrentEvidence(
        ImmutableArray<LabeledField> current,
        ImmutableArray<LabeledField> corrected)
    {
        if (corrected.Length != current.Length)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.MissingRequiredField);
        }

        for (var index = 0; index < current.Length; index++)
        {
            var expected = current[index];
            var actual = corrected[index];
            if (!string.Equals(
                    expected.FieldId,
                    actual.FieldId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    expected.RuleId,
                    actual.RuleId,
                    StringComparison.Ordinal)
                || !expected.Evidence.AsSpan()
                    .SequenceEqual(actual.Evidence.AsSpan()))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.MissingEvidence);
            }
        }
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
                || !leftField.Evidence.AsSpan()
                    .SequenceEqual(rightField.Evidence.AsSpan()))
            {
                return false;
            }
        }

        return true;
    }

    private static string DecisionHash(
        string documentId,
        ReviewDecisionRequest request)
    {
        using var stream = new MemoryStream();
        stream.Write("corpus-review-decision-v1\n"u8);
        stream.Write(Encoding.UTF8.GetBytes(documentId));
        stream.WriteByte((byte)'\n');
        stream.Write(
            WorkbenchJson.Serialize(
                request,
                WorkbenchJsonContext.Default
                    .ReviewDecisionRequest));
        return Convert.ToHexStringLower(
            SHA256.HashData(stream.ToArray()));
    }

    internal static void ValidateRevisionHash(string hash)
    {
        if (hash is null
            || hash.Length != 64
            || hash.Any(static character =>
                character is not (>= '0' and <= '9')
                    and not (>= 'a' and <= 'f')))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }
    }

    private static bool IsCurrentDefer(
        LabelDraftState state,
        IReadOnlyDictionary<string, ReviewDecisionCheckpoint>
            decisions) =>
        state.PreviousRevision is not null
        && decisions.TryGetValue(
            state.Document.DocumentId,
            out var decision)
        && decision.Decision == ReviewDecisionKind.Defer
        && FixedHashEquals(
            state.PreviousRevision.RevisionSha256,
            decision.OutcomeRevisionSha256);

    private static bool FixedHashEquals(
        string left,
        string right) =>
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left),
            Convert.FromHexString(right));

    private CorpusVault RequireVault() =>
        _vault
        ?? throw new ObjectDisposedException(
            nameof(CorpusReviewDataSource));

    private DocumentPreviewService RequirePreview() =>
        _preview
        ?? throw new ObjectDisposedException(
            nameof(CorpusReviewDataSource));

}

internal sealed class ReviewDecisionConflictException : Exception;

internal static class ReviewEnumerableExtensions
{
    internal static IEnumerable<T> WhereNotNull<T>(
        this IEnumerable<T?> source)
        where T : class =>
        source.Where(static value => value is not null)!;
}
