namespace LocalDocumentOrganizer.CorpusWorkbench.Security;

internal static class CanonicalWindowsPath
{
    private const int MaximumPathLength = 1024;

    internal static bool IsAccepted(string? value)
    {
        if (value is not { Length: >= 3 and <= MaximumPathLength }
            || value.IndexOf('\0') >= 0
            || !Path.IsPathFullyQualified(value)
            || value.StartsWith(@"\\", StringComparison.Ordinal)
            || !char.IsAsciiLetter(value[0])
            || value[1] != ':'
            || value[2] != Path.DirectorySeparatorChar
            || value.AsSpan(2).IndexOf(':') >= 0
            || value.IndexOf(Path.AltDirectorySeparatorChar) >= 0)
        {
            return false;
        }

        var segments = value.AsSpan(3);
        while (!segments.IsEmpty)
        {
            var separator = segments.IndexOf(
                Path.DirectorySeparatorChar);
            var segment = separator < 0
                ? segments
                : segments[..separator];
            if (!IsAcceptedSegment(segment))
            {
                return false;
            }

            if (separator < 0)
            {
                break;
            }

            segments = segments[(separator + 1)..];
            if (segments.IsEmpty)
            {
                return false;
            }
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(value),
                value,
                StringComparison.Ordinal);
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or NotSupportedException
                or PathTooLongException)
        {
            return false;
        }
    }

    private static bool IsAcceptedSegment(
        ReadOnlySpan<char> segment)
    {
        if (segment.IsEmpty
            || segment is "." or ".."
            || segment[^1] is ' ' or '.')
        {
            return false;
        }

        var extension = segment.IndexOf('.');
        var stem = extension < 0
            ? segment
            : segment[..extension];
        if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !IsNumberedDevice(stem, "COM")
            && !IsNumberedDevice(stem, "LPT");
    }

    private static bool IsNumberedDevice(
        ReadOnlySpan<char> stem,
        ReadOnlySpan<char> prefix) =>
        stem.Length == prefix.Length + 1
        && stem[..prefix.Length].Equals(
            prefix,
            StringComparison.OrdinalIgnoreCase)
        && stem[^1] is >= '1' and <= '9';
}
