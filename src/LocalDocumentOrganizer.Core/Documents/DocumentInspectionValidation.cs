using System.Security.Cryptography;
using System.Text.Json;

namespace LocalDocumentOrganizer.Core.Documents;

public static class DocumentInspectionValidator
{
    public static DocumentContractValidationResult ValidateRequest(
        DocumentInspectionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.ProtocolVersion
                != DocumentExtractionProtocol.CurrentVersion)
        {
            return Invalid(
                DocumentExtractionFailureCode.ProtocolVersionMismatch);
        }

        if (request.RequestId == Guid.Empty)
        {
            return Invalid(DocumentExtractionFailureCode.InvalidJobId);
        }

        var source = DocumentSourceDescriptorValidator.Validate(
            request.Source,
            requirePdf: true);
        return source.IsValid
            ? Valid()
            : source;
    }

    public static DocumentContractValidationResult ValidateResponse(
        DocumentInspectionRequest request,
        DocumentInspectionResponse response)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        if (response.ProtocolVersion != request.ProtocolVersion
            || response.ProtocolVersion
                != DocumentExtractionProtocol.CurrentVersion)
        {
            return Invalid(
                DocumentExtractionFailureCode
                    .ResponseProtocolVersionMismatch);
        }

        if (response.RequestId == Guid.Empty
            || response.RequestId != request.RequestId)
        {
            return Invalid(
                DocumentExtractionFailureCode.ResponseJobMismatch);
        }

        if (response.Source is null
            || response.Source.DeclaredLength
                != request.Source.DeclaredLength)
        {
            return Invalid(
                DocumentExtractionFailureCode.InvalidSourceLength);
        }

        if (response.Source.Sha256.IsDefault
            || response.Source.Sha256.Length != SHA256.HashSizeInBytes
            || request.Source.Sha256.IsDefault
            || request.Source.Sha256.Length != SHA256.HashSizeInBytes
            || !CryptographicOperations.FixedTimeEquals(
                response.Source.Sha256.AsSpan(),
                request.Source.Sha256.AsSpan()))
        {
            return Invalid(
                DocumentExtractionFailureCode.InvalidSourceFingerprint);
        }

        if (!Enum.IsDefined(response.Outcome))
        {
            return Invalid(DocumentExtractionFailureCode.InvalidOutcome);
        }

        if (response.Outcome == DocumentInspectionOutcome.Success)
        {
            if (response.PdfPageCount <= 0)
            {
                return Invalid(
                    DocumentExtractionFailureCode.InvalidSourceMetadata);
            }

            if (response.FailureCode
                != DocumentExtractionFailureCode.None)
            {
                return Invalid(
                    DocumentExtractionFailureCode
                        .ResponseFailureCodeMismatch);
            }
        }
        else if (response.PdfPageCount != 0
                 || response.FailureCode
                    == DocumentExtractionFailureCode.None
                 || !Enum.IsDefined(response.FailureCode))
        {
            return Invalid(
                DocumentExtractionFailureCode
                    .ResponseFailureCodeMismatch);
        }

        var serialized = JsonSerializer.SerializeToUtf8Bytes(
            response,
            DocumentExtractionJsonContext.Default
                .DocumentInspectionResponse);
        return serialized.Length
               <= DocumentExtractionLimits.MaxSerializedResponseBytes
            ? Valid()
            : Invalid(DocumentExtractionFailureCode.ResponseTooLarge);
    }

    private static DocumentContractValidationResult Valid() =>
        new(true, DocumentExtractionFailureCode.None);

    private static DocumentContractValidationResult Invalid(
        DocumentExtractionFailureCode failureCode) =>
        new(false, failureCode);
}

internal static class DocumentSourceDescriptorValidator
{
    internal static DocumentContractValidationResult Validate(
        DocumentSourceDescriptor? source,
        bool requirePdf = false)
    {
        if (source is null || source.InheritedHandle == 0)
        {
            return Invalid(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }

        if (source.Sha256.IsDefaultOrEmpty
            || source.Sha256.Length != SHA256.HashSizeInBytes)
        {
            return Invalid(
                DocumentExtractionFailureCode.InvalidSourceFingerprint);
        }

        if (source.DeclaredLength < 0)
        {
            return Invalid(
                DocumentExtractionFailureCode.InvalidSourceLength);
        }

        if (source.DeclaredLength
            > DocumentExtractionLimits.MaxEncodedInputBytes)
        {
            return Invalid(DocumentExtractionFailureCode.InputTooLarge);
        }

        if (requirePdf)
        {
            return source.ContainerKind == DocumentContainerKind.Pdf
                   && source.DeclaredMimeType == "application/pdf"
                ? Valid()
                : Invalid(
                    DocumentExtractionFailureCode
                        .ContainerMimeTypeMismatch);
        }

        var supported = source.DeclaredMimeType is
            "application/pdf"
            or "image/jpeg"
            or "image/png"
            or "image/tiff"
            or "image/bmp";
        if (!supported)
        {
            return Invalid(
                DocumentExtractionFailureCode.UnsupportedMimeType);
        }

        var matches = source.ContainerKind switch
        {
            DocumentContainerKind.Pdf =>
                source.DeclaredMimeType == "application/pdf",
            DocumentContainerKind.RasterImage =>
                source.DeclaredMimeType is
                    "image/jpeg"
                    or "image/png"
                    or "image/tiff"
                    or "image/bmp",
            _ => false,
        };
        return matches
            ? Valid()
            : Invalid(
                DocumentExtractionFailureCode.ContainerMimeTypeMismatch);
    }

    private static DocumentContractValidationResult Valid() =>
        new(true, DocumentExtractionFailureCode.None);

    private static DocumentContractValidationResult Invalid(
        DocumentExtractionFailureCode failureCode) =>
        new(false, failureCode);
}
