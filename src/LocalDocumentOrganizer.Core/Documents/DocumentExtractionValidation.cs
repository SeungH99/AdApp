using System.Text.Json;

namespace LocalDocumentOrganizer.Core.Documents;

public static class DocumentExtractionValidator
{
    private const ExtractionCapability AllCapabilities =
        ExtractionCapability.EmbeddedText | ExtractionCapability.Ocr;

    private static readonly string[] GrandfatheredLanguageTags =
    [
        "art-lojban",
        "cel-gaulish",
        "en-GB-oed",
        "i-ami",
        "i-bnn",
        "i-default",
        "i-enochian",
        "i-hak",
        "i-klingon",
        "i-lux",
        "i-mingo",
        "i-navajo",
        "i-pwn",
        "i-tao",
        "i-tay",
        "i-tsu",
        "no-bok",
        "no-nyn",
        "sgn-BE-FR",
        "sgn-BE-NL",
        "sgn-CH-DE",
        "zh-guoyu",
        "zh-hakka",
        "zh-min",
        "zh-min-nan",
        "zh-xiang",
    ];

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

        var languageValidation =
            ValidateRequestedLanguages(request.RequestedLanguages);
        if (!languageValidation.IsValid)
        {
            return languageValidation;
        }

        return new DocumentContractValidationResult(true, DocumentExtractionFailureCode.None);
    }

    public static DocumentContractValidationResult ValidateRequestedLanguages(
        System.Collections.Immutable.ImmutableArray<string> requestedLanguages)
    {
        if (requestedLanguages.IsDefault)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidLanguageTag);
        }

        var languages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var language in requestedLanguages)
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

        return new DocumentContractValidationResult(
            true,
            DocumentExtractionFailureCode.None);
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
        if (string.IsNullOrEmpty(language))
        {
            return false;
        }

        var subtags = language.Split('-');
        if (GrandfatheredLanguageTags.Contains(language, StringComparer.Ordinal))
        {
            return true;
        }

        if (subtags[0] == "x")
        {
            return ValidatePrivateUse(subtags, 1);
        }

        var index = 0;
        if (IsLowerAsciiLetters(subtags[index], 2, 3))
        {
            index++;
            for (var extlangCount = 0;
                 extlangCount < 3
                 && index < subtags.Length
                 && IsLowerAsciiLetters(subtags[index], 3, 3);
                 extlangCount++)
            {
                index++;
            }
        }
        else if (IsLowerAsciiLetters(subtags[index], 4, 8))
        {
            index++;
        }
        else
        {
            return false;
        }

        if (index < subtags.Length && subtags[index].Length == 4)
        {
            if (!IsNormalizedScript(subtags[index]))
            {
                return false;
            }

            index++;
        }

        if (index < subtags.Length
            && (subtags[index].Length == 2 || subtags[index].Length == 3))
        {
            var region = subtags[index];
            if (!IsUpperAsciiLetters(region, 2, 2)
                && !IsAsciiDigits(region, 3, 3))
            {
                return false;
            }

            index++;
        }

        var variants = new HashSet<string>(StringComparer.Ordinal);
        while (index < subtags.Length && IsNormalizedVariant(subtags[index]))
        {
            if (!variants.Add(subtags[index]))
            {
                return false;
            }

            index++;
        }

        var extensionSingletons = new HashSet<char>();
        while (index < subtags.Length && IsNormalizedExtensionSingleton(subtags[index]))
        {
            if (!extensionSingletons.Add(subtags[index][0]))
            {
                return false;
            }

            index++;
            var extensionStart = index;
            while (index < subtags.Length
                   && IsLowerAsciiAlphanumeric(subtags[index], 2, 8))
            {
                index++;
            }

            if (index == extensionStart)
            {
                return false;
            }
        }

        if (index < subtags.Length && subtags[index] == "x")
        {
            return ValidatePrivateUse(subtags, index + 1);
        }

        return index == subtags.Length;
    }

    private static bool ValidatePrivateUse(string[] subtags, int startIndex)
    {
        if (startIndex >= subtags.Length)
        {
            return false;
        }

        for (var index = startIndex; index < subtags.Length; index++)
        {
            if (!IsLowerAsciiAlphanumeric(subtags[index], 1, 8))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsNormalizedScript(string subtag) =>
        subtag.Length == 4
        && char.IsAsciiLetterUpper(subtag[0])
        && subtag.AsSpan(1).IndexOfAnyExceptInRange('a', 'z') < 0;

    private static bool IsNormalizedVariant(string subtag) =>
        IsLowerAsciiAlphanumeric(subtag, 5, 8)
        || (subtag.Length == 4
            && char.IsAsciiDigit(subtag[0])
            && IsLowerAsciiAlphanumeric(subtag.AsSpan(1), 3, 3));

    private static bool IsNormalizedExtensionSingleton(string subtag) =>
        subtag.Length == 1
        && subtag[0] != 'x'
        && (char.IsAsciiDigit(subtag[0]) || char.IsAsciiLetterLower(subtag[0]));

    private static bool IsLowerAsciiLetters(string value, int minimum, int maximum) =>
        value.Length >= minimum
        && value.Length <= maximum
        && value.AsSpan().IndexOfAnyExceptInRange('a', 'z') < 0;

    private static bool IsUpperAsciiLetters(string value, int minimum, int maximum) =>
        value.Length >= minimum
        && value.Length <= maximum
        && value.AsSpan().IndexOfAnyExceptInRange('A', 'Z') < 0;

    private static bool IsAsciiDigits(string value, int minimum, int maximum) =>
        value.Length >= minimum
        && value.Length <= maximum
        && value.AsSpan().IndexOfAnyExceptInRange('0', '9') < 0;

    private static bool IsLowerAsciiAlphanumeric(
        string value,
        int minimum,
        int maximum) =>
        IsLowerAsciiAlphanumeric(value.AsSpan(), minimum, maximum);

    private static bool IsLowerAsciiAlphanumeric(
        ReadOnlySpan<char> value,
        int minimum,
        int maximum)
    {
        if (value.Length < minimum || value.Length > maximum)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiDigit(character) && !char.IsAsciiLetterLower(character))
            {
                return false;
            }
        }

        return true;
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
                || ExceedsRasterLimits(sourcePage, containerKind)
                || !indexedPages.TryAdd(sourcePage.SourceIndex, sourcePage))
            {
                return Invalid(DocumentExtractionFailureCode.InvalidSourceMetadata);
            }
        }

        return new DocumentContractValidationResult(true, DocumentExtractionFailureCode.None);
    }

    private static bool ExceedsRasterLimits(
        DocumentSourcePage sourcePage,
        DocumentContainerKind containerKind) =>
        containerKind == DocumentContainerKind.RasterImage
        && (sourcePage.Width > DocumentExtractionLimits.MaxRasterDimensionPixels
            || sourcePage.Height > DocumentExtractionLimits.MaxRasterDimensionPixels
            || sourcePage.Width
                > DocumentExtractionLimits.MaxDecodedPixels / sourcePage.Height);

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
