namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public sealed class ProjectionRebuildRequiredException : InvalidOperationException
{
    public ProjectionRebuildRequiredException(
        IEnumerable<string> projectionNames,
        long requiredGlobalPosition)
        : this(CreateSnapshot(projectionNames), requiredGlobalPosition)
    {
    }

    private ProjectionRebuildRequiredException(
        string[] projectionNames,
        long requiredGlobalPosition)
        : base(
            $"Projection rebuild is required at global position {requiredGlobalPosition} for: " +
            string.Join(", ", projectionNames))
    {
        ArgumentOutOfRangeException.ThrowIfNegative(requiredGlobalPosition);
        ProjectionNames = Array.AsReadOnly(projectionNames);
        RequiredGlobalPosition = requiredGlobalPosition;
    }

    public IReadOnlyList<string> ProjectionNames { get; }

    public long RequiredGlobalPosition { get; }

    private static string[] CreateSnapshot(IEnumerable<string> projectionNames)
    {
        ArgumentNullException.ThrowIfNull(projectionNames);
        return projectionNames
            .OrderBy(projectionName => projectionName, StringComparer.Ordinal)
            .ToArray();
    }
}
