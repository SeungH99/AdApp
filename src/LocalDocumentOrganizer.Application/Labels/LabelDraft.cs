using System.Collections.Immutable;
using LocalDocumentOrganizer.Application.Contracts;

namespace LocalDocumentOrganizer.Application.Labels;

public sealed record LabelDraft(ImmutableArray<LabeledField> Fields);
