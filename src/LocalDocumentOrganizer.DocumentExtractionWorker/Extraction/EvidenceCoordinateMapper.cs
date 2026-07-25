using LocalDocumentOrganizer.Core.Documents;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public static class EvidenceCoordinateMapper
{
    private const double BoundaryTolerance = 1e-7;
    private const double SingularTolerance = 1e-12;

    public static EvidenceRectangle MapPdfRenderRectangle(
        EvidenceRectangle renderedRectangle,
        double renderedWidth,
        double renderedHeight,
        double pdfWidthPoints,
        double pdfHeightPoints)
    {
        ValidatePositiveFinite(renderedWidth, nameof(renderedWidth));
        ValidatePositiveFinite(renderedHeight, nameof(renderedHeight));
        ValidatePositiveFinite(pdfWidthPoints, nameof(pdfWidthPoints));
        ValidatePositiveFinite(pdfHeightPoints, nameof(pdfHeightPoints));

        var scale = new OrientationTransform(
            pdfWidthPoints / renderedWidth,
            0,
            0,
            -(pdfHeightPoints / renderedHeight),
            0,
            pdfHeightPoints);
        return MapRectangle(
            renderedRectangle,
            scale,
            pdfWidthPoints,
            pdfHeightPoints);
    }

    public static OrientationTransform CreateOrientationTransform(
        int clockwiseDegrees,
        double encodedWidth,
        double encodedHeight)
    {
        ValidatePositiveFinite(encodedWidth, nameof(encodedWidth));
        ValidatePositiveFinite(encodedHeight, nameof(encodedHeight));

        return clockwiseDegrees switch
        {
            0 => new OrientationTransform(1, 0, 0, 1, 0, 0),
            90 => new OrientationTransform(0, 1, -1, 0, encodedHeight, 0),
            180 => new OrientationTransform(-1, 0, 0, -1, encodedWidth, encodedHeight),
            270 => new OrientationTransform(0, -1, 1, 0, 0, encodedWidth),
            _ => throw new UnsupportedDocumentException(
                "Only right-angle raster orientations are supported."),
        };
    }

    public static OrientationTransform Invert(OrientationTransform transform)
    {
        ValidateTransform(transform);
        var determinant =
            transform.M11 * transform.M22 - transform.M12 * transform.M21;
        var inverseM11 = transform.M22 / determinant;
        var inverseM12 = -transform.M12 / determinant;
        var inverseM21 = -transform.M21 / determinant;
        var inverseM22 = transform.M11 / determinant;

        return new OrientationTransform(
            inverseM11,
            inverseM12,
            inverseM21,
            inverseM22,
            -(transform.OffsetX * inverseM11
                + transform.OffsetY * inverseM21),
            -(transform.OffsetX * inverseM12
                + transform.OffsetY * inverseM22));
    }

    public static EvidenceRectangle MapRectangle(
        EvidenceRectangle rectangle,
        OrientationTransform transform,
        double outputWidth,
        double outputHeight)
    {
        ArgumentNullException.ThrowIfNull(rectangle);
        ValidateTransform(transform);
        ValidatePositiveFinite(outputWidth, nameof(outputWidth));
        ValidatePositiveFinite(outputHeight, nameof(outputHeight));
        ValidateRectangle(rectangle);

        var x1 = rectangle.X;
        var y1 = rectangle.Y;
        var x2 = checked(rectangle.X + rectangle.Width);
        var y2 = checked(rectangle.Y + rectangle.Height);
        var corners = new[]
        {
            MapPoint(x1, y1, transform),
            MapPoint(x2, y1, transform),
            MapPoint(x1, y2, transform),
            MapPoint(x2, y2, transform),
        };

        var minimumX = corners.Min(static point => point.X);
        var minimumY = corners.Min(static point => point.Y);
        var maximumX = corners.Max(static point => point.X);
        var maximumY = corners.Max(static point => point.Y);
        if (minimumX < -BoundaryTolerance
            || minimumY < -BoundaryTolerance
            || maximumX > outputWidth + BoundaryTolerance
            || maximumY > outputHeight + BoundaryTolerance)
        {
            throw new CorruptDocumentException(
                "The mapped evidence rectangle is outside its source bounds.");
        }

        minimumX = Math.Clamp(minimumX, 0, outputWidth);
        minimumY = Math.Clamp(minimumY, 0, outputHeight);
        maximumX = Math.Clamp(maximumX, 0, outputWidth);
        maximumY = Math.Clamp(maximumY, 0, outputHeight);
        var mapped = new EvidenceRectangle(
            minimumX,
            minimumY,
            maximumX - minimumX,
            maximumY - minimumY);
        ValidateRectangle(mapped);
        return mapped;
    }

    private static (double X, double Y) MapPoint(
        double x,
        double y,
        OrientationTransform transform)
    {
        var mappedX =
            transform.M11 * x + transform.M21 * y + transform.OffsetX;
        var mappedY =
            transform.M12 * x + transform.M22 * y + transform.OffsetY;
        if (!double.IsFinite(mappedX) || !double.IsFinite(mappedY))
        {
            throw new CorruptDocumentException(
                "The evidence transform produced a non-finite coordinate.");
        }

        return (mappedX, mappedY);
    }

    private static void ValidateTransform(OrientationTransform transform)
    {
        ArgumentNullException.ThrowIfNull(transform);
        if (!double.IsFinite(transform.M11)
            || !double.IsFinite(transform.M12)
            || !double.IsFinite(transform.M21)
            || !double.IsFinite(transform.M22)
            || !double.IsFinite(transform.OffsetX)
            || !double.IsFinite(transform.OffsetY))
        {
            throw new CorruptDocumentException(
                "The evidence transform contains a non-finite value.");
        }

        var determinant =
            transform.M11 * transform.M22 - transform.M12 * transform.M21;
        if (!double.IsFinite(determinant)
            || Math.Abs(determinant) <= SingularTolerance)
        {
            throw new CorruptDocumentException(
                "The evidence transform is singular.");
        }
    }

    private static void ValidateRectangle(EvidenceRectangle rectangle)
    {
        if (!double.IsFinite(rectangle.X)
            || !double.IsFinite(rectangle.Y)
            || !double.IsFinite(rectangle.Width)
            || !double.IsFinite(rectangle.Height)
            || rectangle.X < 0
            || rectangle.Y < 0
            || rectangle.Width <= 0
            || rectangle.Height <= 0)
        {
            throw new CorruptDocumentException(
                "The evidence rectangle is invalid.");
        }
    }

    private static void ValidatePositiveFinite(double value, string parameterName)
    {
        if (!double.IsFinite(value) || value <= 0)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                "The dimension must be finite and positive.");
        }
    }
}
