using System.Collections.Immutable;

namespace LocalDocumentOrganizer.Core.Documents;

public static class DocumentExtractionProtocol
{
    public const int CurrentVersion = 1;

    public static ReadOnlySpan<byte> WorkerReadinessPreamble =>
        "LDOX-READY/1\n"u8;
}

public static class DocumentExtractionLimits
{
    public const int MaxEncodedInputBytes = 20 * 1024 * 1024;

    public const int MaxPdfPages = 20;

    public const int MaxRasterDimensionPixels = 16_384;

    public const long MaxDecodedPixels = 100_000_000;

    public const int MaxSerializedResponseBytes = 5 * 1024 * 1024;

    public const int ExtractionTimeoutMilliseconds = 15_000;

    public const long MaxWorkerCommitMemoryBytes = 512L * 1024 * 1024;
}

[Flags]
public enum ExtractionCapability
{
    EmbeddedText = 1,
    Ocr = 2,
}

public enum DocumentContainerKind
{
    Pdf = 1,
    RasterImage = 2,
}

public enum EvidenceCoordinateSystem
{
    PdfPagePoints = 1,
    OrientedRasterPixels = 2,
}

public enum DocumentExtractionFailureCode
{
    None = 0,
    ProtocolVersionMismatch = 1,
    InvalidJobId = 2,
    InvalidSourceHandle = 3,
    InvalidSourceFingerprint = 4,
    InvalidSourceLength = 5,
    InputTooLarge = 6,
    ContainerMimeTypeMismatch = 7,
    UnsupportedMimeType = 8,
    InvalidRequestedCapabilities = 9,
    InvalidLanguageTag = 10,
    DuplicateLanguageTag = 11,
    ResponseProtocolVersionMismatch = 12,
    ResponseJobMismatch = 13,
    InvalidOutcome = 14,
    MissingTextFragments = 15,
    UnexpectedTextFragments = 16,
    InvalidEvidenceRectangle = 17,
    EvidenceOutOfBounds = 18,
    InvalidSourceIndex = 19,
    MissingDecoderVersion = 20,
    MissingOcrVersion = 21,
    InvalidOrientationTransform = 22,
    ResponseTooLarge = 23,
    InvalidSourceMetadata = 24,
    InvalidRuntimeMetadata = 25,
    InvalidTextFragment = 26,
    InvalidFragmentCapability = 27,
    ResponseFailureCodeMismatch = 28,
    InvalidElapsedTime = 29,
    UnsupportedDocument = 30,
    CorruptDocument = 31,
    EncryptedDocument = 32,
    UnsupportedLanguage = 33,
    DecoderFailure = 34,
    OcrFailure = 35,
    ExtractionCancelled = 36,
    ExtractionTimedOut = 37,
    WorkerMemoryLimitExceeded = 38,
    WorkerTerminated = 39,
    InternalFailure = 40,
    InvalidFraming = 41,
    NoAdapterAvailable = 42,
}

public readonly record struct DocumentContractValidationResult(
    bool IsValid,
    DocumentExtractionFailureCode FailureCode);

public sealed record DocumentSourceDescriptor(
    ulong InheritedHandle,
    DocumentContainerKind ContainerKind,
    string DeclaredMimeType,
    long DeclaredLength,
    ImmutableArray<byte> Sha256);

public sealed record DocumentExtractionRequest(
    int ProtocolVersion,
    Guid JobId,
    DocumentSourceDescriptor Source,
    ExtractionCapability RequestedCapabilities,
    ImmutableArray<string> RequestedLanguages);

public enum DocumentExtractionOutcome
{
    Success = 1,
    Failure = 2,
}

public sealed record EvidenceRectangle(
    double X,
    double Y,
    double Width,
    double Height);

public sealed record OrientationTransform(
    double M11,
    double M12,
    double M21,
    double M22,
    double OffsetX,
    double OffsetY);

public sealed record DocumentSourcePage(
    int SourceIndex,
    double Width,
    double Height,
    EvidenceCoordinateSystem CoordinateSystem);

public sealed record ExtractionRuntimeMetadata(
    string AdapterId,
    string AdapterVersion,
    string DecoderVersion,
    string? OcrVersion);

public sealed record TextFragment(
    string Text,
    int SourceIndex,
    EvidenceCoordinateSystem CoordinateSystem,
    EvidenceRectangle Evidence,
    OrientationTransform AppliedOrientation,
    ExtractionCapability ExtractionCapability,
    string DecoderVersion,
    string? OcrVersion);

public sealed record DocumentExtractionResponse(
    int ProtocolVersion,
    Guid JobId,
    DocumentExtractionOutcome Outcome,
    ImmutableArray<TextFragment> Fragments,
    ImmutableArray<DocumentSourcePage> SourcePages,
    ExtractionRuntimeMetadata RuntimeMetadata,
    long ElapsedMilliseconds,
    DocumentExtractionFailureCode FailureCode);
