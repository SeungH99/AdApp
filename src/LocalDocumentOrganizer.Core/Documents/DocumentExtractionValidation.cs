using System.Globalization;
using System.Text.Json;

namespace LocalDocumentOrganizer.Core.Documents;

public static class DocumentExtractionValidator
{
    private const ExtractionCapability AllCapabilities =
        ExtractionCapability.EmbeddedText | ExtractionCapability.Ocr;

    public static DocumentContractValidationResult ValidateRequest(
        DocumentExtractionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.ProtocolVersion != DocumentExtractionProtocol.CurrentVersion)
        {
            return Invalid(DocumentExtractionFailureCode.ProtocolVersionMismatch);
        }

        if (request.JobId == Guid.Empty)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidJobId);
        }

        if (request.Source is null || request.Source.InheritedHandle == 0)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidSourceHandle);
        }

        if (request.Source.Sha256.IsDefaultOrEmpty || request.Source.Sha256.Length != 32)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidSourceFingerprint);
        }

        if (request.Source.DeclaredLength < 0)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidSourceLength);
        }

        if (request.Source.DeclaredLength > DocumentExtractionLimits.MaxEncodedInputBytes)
        {
            return Invalid(DocumentExtractionFailureCode.InputTooLarge);
        }

        if (!IsSupportedMimeType(request.Source.DeclaredMimeType))
        {
            return Invalid(DocumentExtractionFailureCode.UnsupportedMimeType);
        }

        if (!MimeTypeMatchesContainer(
                request.Source.DeclaredMimeType,
                request.Source.ContainerKind))
        {
            return Invalid(DocumentExtractionFailureCode.ContainerMimeTypeMismatch);
        }

        if (request.RequestedCapabilities == 0
            || (request.RequestedCapabilities & ~AllCapabilities) != 0)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidRequestedCapabilities);
        }

        if (request.RequestedLanguages.IsDefault)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidLanguageTag);
        }

        var languages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var language in request.RequestedLanguages)
        {
            if (!IsValidLanguageTag(language))
            {
                return Invalid(DocumentExtractionFailureCode.InvalidLanguageTag);
            }

            if (!languages.Add(language))
            {
                return Invalid(DocumentExtractionFailureCode.DuplicateLanguageTag);
            }
        }

        return new DocumentContractValidationResult(true, DocumentExtractionFailureCode.None);
    }

    public static DocumentContractValidationResult ValidateResponse(
        DocumentExtractionRequest request,
        DocumentExtractionResponse response)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);

        if (response.ProtocolVersion != request.ProtocolVersion
            || response.ProtocolVersion != DocumentExtractionProtocol.CurrentVersion)
        {
            return Invalid(DocumentExtractionFailureCode.ResponseProtocolVersionMismatch);
        }

        if (response.JobId == Guid.Empty || response.JobId != request.JobId)
        {
            return Invalid(DocumentExtractionFailureCode.ResponseJobMismatch);
        }

        if (!Enum.IsDefined(response.Outcome))
        {
            return Invalid(DocumentExtractionFailureCode.InvalidOutcome);
        }

        if (response.Fragments.IsDefault)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidTextFragment);
        }

        if (response.Outcome == DocumentExtractionOutcome.Success)
        {
            if (response.Fragments.IsEmpty)
            {
                return Invalid(DocumentExtractionFailureCode.MissingTextFragments);
            }

            if (response.FailureCode != DocumentExtractionFailureCode.None)
            {
                return Invalid(DocumentExtractionFailureCode.ResponseFailureCodeMismatch);
            }
        }
        else
        {
            if (!response.Fragments.IsEmpty)
            {
                return Invalid(DocumentExtractionFailureCode.UnexpectedTextFragments);
            }

            if (response.FailureCode == DocumentExtractionFailureCode.None
                || !Enum.IsDefined(response.FailureCode))
            {
                return Invalid(DocumentExtractionFailureCode.ResponseFailureCodeMismatch);
            }
        }

        if (response.ElapsedMilliseconds < 0)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidElapsedTime);
        }

        if (!IsValidRuntimeMetadata(response.RuntimeMetadata, response.Outcome))
        {
            return Invalid(DocumentExtractionFailureCode.InvalidRuntimeMetadata);
        }

        var sourcePagesResult = ValidateSourcePages(
            response.SourcePages,
            response.Outcome,
            request.Source.ContainerKind,
            out var sourcePages);
        if (!sourcePagesResult.IsValid)
        {
            return sourcePagesResult;
        }

        foreach (var fragment in response.Fragments)
        {
            var fragmentResult = ValidateFragment(
                fragment,
                response.RuntimeMetadata,
                request.RequestedCapabilities,
                sourcePages);
            if (!fragmentResult.IsValid)
            {
                return fragmentResult;
            }
        }

        var serialized = JsonSerializer.SerializeToUtf8Bytes(
            response,
            DocumentExtractionJsonContext.Default.DocumentExtractionResponse);
        if (serialized.Length > DocumentExtractionLimits.MaxSerializedResponseBytes)
        {
            return Invalid(DocumentExtractionFailureCode.ResponseTooLarge);
        }

        return new DocumentContractValidationResult(true, DocumentExtractionFailureCode.None);
    }

    private static bool IsSupportedMimeType(string? mimeType) =>
        mimeType is "application/pdf"
            or "image/jpeg"
            or "image/png"
            or "image/tiff"
            or "image/bmp";

    private static bool MimeTypeMatchesContainer(
        string mimeType,
        DocumentContainerKind containerKind) =>
        containerKind switch
        {
            DocumentContainerKind.Pdf => mimeType == "application/pdf",
            DocumentContainerKind.RasterImage => mimeType is
                "image/jpeg" or "image/png" or "image/tiff" or "image/bmp",
            _ => false,
        };

    private static bool IsValidLanguageTag(string? language)
    {
        if (string.IsNullOrWhiteSpace(language)
            || language.Length > 63
            || language[0] == '-'
            || language[^1] == '-'
            || language.Contains("--", StringComparison.Ordinal)
            || language.Any(character =>
                character != '-' && !char.IsAsciiLetterOrDigit(character)))
        {
            return false;
        }

        try
        {
            _ = CultureInfo.GetCultureInfo(language);
            return true;
        }
        catch (CultureNotFoundException)
        {
            return false;
        }
    }

    private static bool IsValidRuntimeMetadata(
        ExtractionRuntimeMetadata? metadata,
        DocumentExtractionOutcome outcome) =>
        metadata is not null
        && !string.IsNullOrWhiteSpace(metadata.AdapterId)
        && !string.IsNullOrWhiteSpace(metadata.AdapterVersion)
        && (outcome == DocumentExtractionOutcome.Failure
            || !string.IsNullOrWhiteSpace(metadata.DecoderVersion));

    private static DocumentContractValidationResult ValidateSourcePages(
        System.Collections.Immutable.ImmutableArray<DocumentSourcePage> sourcePages,
        DocumentExtractionOutcome outcome,
        DocumentContainerKind containerKind,
        out Dictionary<int, DocumentSourcePage> indexedPages)
    {
        indexedPages = [];
        if (sourcePages.IsDefault
            || (outcome == DocumentExtractionOutcome.Success && sourcePages.IsEmpty))
        {
            return Invalid(DocumentExtractionFailureCode.InvalidSourceMetadata);
        }

        var maximumSourceIndex = containerKind == DocumentContainerKind.Pdf
            ? DocumentExtractionLimits.MaxPdfPages - 1
            : 0;
        var expectedCoordinateSystem = containerKind == DocumentContainerKind.Pdf
            ? EvidenceCoordinateSystem.PdfPagePoints
            : EvidenceCoordinateSystem.OrientedRasterPixels;

        foreach (var sourcePage in sourcePages)
        {
            if (sourcePage is null)
            {
                return Invalid(DocumentExtractionFailureCode.InvalidSourceMetadata);
            }

            if (sourcePage.SourceIndex < 0
                || sourcePage.SourceIndex > maximumSourceIndex)
            {
                return Invalid(DocumentExtractionFailureCode.InvalidSourceIndex);
            }

            if (!Enum.IsDefined(sourcePage.CoordinateSystem)
                || sourcePage.CoordinateSystem != expectedCoordinateSystem
                || !IsFinitePositive(sourcePage.Width)
                || !IsFinitePositive(sourcePage.Height)
                || !indexedPages.TryAdd(sourcePage.SourceIndex, sourcePage))
            {
                return Invalid(DocumentExtractionFailureCode.InvalidSourceMetadata);
            }
        }

        return new DocumentContractValidationResult(true, DocumentExtractionFailureCode.None);
    }

    private static DocumentContractValidationResult ValidateFragment(
        TextFragment? fragment,
        ExtractionRuntimeMetadata runtimeMetadata,
        ExtractionCapability requestedCapabilities,
        IReadOnlyDictionary<int, DocumentSourcePage> sourcePages)
    {
        if (fragment is null
            || string.IsNullOrWhiteSpace(fragment.Text)
            || fragment.Evidence is null
            || fragment.AppliedOrientation is null)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidTextFragment);
        }

        if (!sourcePages.TryGetValue(fragment.SourceIndex, out var sourcePage)
            || !Enum.IsDefined(fragment.CoordinateSystem)
            || fragment.CoordinateSystem != sourcePage.CoordinateSystem)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidSourceIndex);
        }

        if (!IsValidRectangle(fragment.Evidence))
        {
            return Invalid(DocumentExtractionFailureCode.InvalidEvidenceRectangle);
        }

        if (fragment.Evidence.X > sourcePage.Width - fragment.Evidence.Width
            || fragment.Evidence.Y > sourcePage.Height - fragment.Evidence.Height)
        {
            return Invalid(DocumentExtractionFailureCode.EvidenceOutOfBounds);
        }

        if (!IsNormalizedOrientation(fragment.AppliedOrientation))
        {
            return Invalid(DocumentExtractionFailureCode.InvalidOrientationTransform);
        }

        if (fragment.ExtractionCapability is not (
                ExtractionCapability.EmbeddedText or ExtractionCapability.Ocr)
            || (requestedCapabilities & fragment.ExtractionCapability)
                != fragment.ExtractionCapability)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidFragmentCapability);
        }

        if (string.IsNullOrWhiteSpace(fragment.DecoderVersion)
            || !string.Equals(
                fragment.DecoderVersion,
                runtimeMetadata.DecoderVersion,
                StringComparison.Ordinal))
        {
            return Invalid(DocumentExtractionFailureCode.MissingDecoderVersion);
        }

        if (fragment.ExtractionCapability == ExtractionCapability.Ocr
            && (string.IsNullOrWhiteSpace(fragment.OcrVersion)
                || string.IsNullOrWhiteSpace(runtimeMetadata.OcrVersion)
                || !string.Equals(
                    fragment.OcrVersion,
                    runtimeMetadata.OcrVersion,
                    StringComparison.Ordinal)))
        {
            return Invalid(DocumentExtractionFailureCode.MissingOcrVersion);
        }

        return new DocumentContractValidationResult(true, DocumentExtractionFailureCode.None);
    }

    private static bool IsValidRectangle(EvidenceRectangle rectangle) =>
        double.IsFinite(rectangle.X)
        && double.IsFinite(rectangle.Y)
        && double.IsFinite(rectangle.Width)
        && double.IsFinite(rectangle.Height)
        && rectangle.X >= 0
        && rectangle.Y >= 0
        && rectangle.Width > 0
        && rectangle.Height > 0;

    private static bool IsNormalizedOrientation(OrientationTransform transform)
    {
        if (!double.IsFinite(transform.M11)
            || !double.IsFinite(transform.M12)
            || !double.IsFinite(transform.M21)
            || !double.IsFinite(transform.M22)
            || !double.IsFinite(transform.OffsetX)
            || !double.IsFinite(transform.OffsetY))
        {
            return false;
        }

        const double tolerance = 1e-9;
        var firstAxisLengthSquared =
            transform.M11 * transform.M11 + transform.M12 * transform.M12;
        var secondAxisLengthSquared =
            transform.M21 * transform.M21 + transform.M22 * transform.M22;
        var dotProduct =
            transform.M11 * transform.M21 + transform.M12 * transform.M22;
        var determinant =
            transform.M11 * transform.M22 - transform.M12 * transform.M21;

        return Math.Abs(firstAxisLengthSquared - 1) <= tolerance
            && Math.Abs(secondAxisLengthSquared - 1) <= tolerance
            && Math.Abs(dotProduct) <= tolerance
            && Math.Abs(Math.Abs(determinant) - 1) <= tolerance;
    }

    private static bool IsFinitePositive(double value) =>
        double.IsFinite(value) && value > 0;

    private static DocumentContractValidationResult Invalid(
        DocumentExtractionFailureCode failureCode) =>
        new(false, failureCode);
}
