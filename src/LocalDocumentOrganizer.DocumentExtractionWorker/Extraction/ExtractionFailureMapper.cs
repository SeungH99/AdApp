using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Source;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public static class ExtractionFailureMapper
{
    public static DocumentExtractionFailureCode Map(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception switch
        {
            SourceDocumentException sourceException => sourceException.FailureCode,
            DocumentExtractionAdapterException adapterException =>
                adapterException.FailureCode,
            OperationCanceledException =>
                DocumentExtractionFailureCode.ExtractionCancelled,
            OutOfMemoryException =>
                DocumentExtractionFailureCode.WorkerMemoryLimitExceeded,
            _ => DocumentExtractionFailureCode.InternalFailure,
        };
    }
}

public abstract class DocumentExtractionAdapterException : Exception
{
    protected DocumentExtractionAdapterException(
        string message,
        DocumentExtractionFailureCode failureCode,
        Exception? innerException = null)
        : base(message, innerException)
    {
        FailureCode = failureCode;
    }

    public DocumentExtractionFailureCode FailureCode { get; }
}

public sealed class UnsupportedDocumentException : DocumentExtractionAdapterException
{
    public UnsupportedDocumentException(string message, Exception? innerException = null)
        : base(
            message,
            DocumentExtractionFailureCode.UnsupportedDocument,
            innerException)
    {
    }
}

public sealed class CorruptDocumentException : DocumentExtractionAdapterException
{
    public CorruptDocumentException(string message, Exception? innerException = null)
        : base(message, DocumentExtractionFailureCode.CorruptDocument, innerException)
    {
    }
}

public sealed class EncryptedDocumentException : DocumentExtractionAdapterException
{
    public EncryptedDocumentException(string message, Exception? innerException = null)
        : base(message, DocumentExtractionFailureCode.EncryptedDocument, innerException)
    {
    }
}

public sealed class UnsupportedLanguageException : DocumentExtractionAdapterException
{
    public UnsupportedLanguageException(string message, Exception? innerException = null)
        : base(
            message,
            DocumentExtractionFailureCode.UnsupportedLanguage,
            innerException)
    {
    }
}

public sealed class DecoderFailureException : DocumentExtractionAdapterException
{
    public DecoderFailureException(string message, Exception? innerException = null)
        : base(message, DocumentExtractionFailureCode.DecoderFailure, innerException)
    {
    }
}

public sealed class OcrFailureException : DocumentExtractionAdapterException
{
    public OcrFailureException(string message, Exception? innerException = null)
        : base(message, DocumentExtractionFailureCode.OcrFailure, innerException)
    {
    }
}
