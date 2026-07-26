using System.Text;
using LocalDocumentOrganizer.Core.Documents;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public sealed class ExtractionResponseBudget
{
    private readonly object gate = new();
    private int usedTextBytes;

    public int MaximumTextBytes { get; } =
        DocumentExtractionLimits.MaxSerializedResponseBytes - (64 * 1024);

    public int UsedTextBytes
    {
        get
        {
            lock (gate)
            {
                return usedTextBytes;
            }
        }
    }

    public void AddText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var byteCount = Encoding.UTF8.GetByteCount(text);
        lock (gate)
        {
            if (byteCount > MaximumTextBytes - usedTextBytes)
            {
                throw new ResponseTooLargeAdapterException();
            }

            usedTextBytes += byteCount;
        }
    }
}
