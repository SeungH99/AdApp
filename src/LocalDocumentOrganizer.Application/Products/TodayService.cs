using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Cases.Receivable;

namespace LocalDocumentOrganizer.Application.Products;

public interface ILocalTimeZoneProvider
{
    TimeZoneInfo GetLocalTimeZone();
}

public sealed class SystemLocalTimeZoneProvider : ILocalTimeZoneProvider
{
    public static SystemLocalTimeZoneProvider Instance { get; } = new();
    private SystemLocalTimeZoneProvider() { }
    public TimeZoneInfo GetLocalTimeZone() => TimeZoneInfo.Local;
}

public enum TodayDueState { Upcoming = 1, DueToday = 2, Overdue = 3 }

public sealed record TodayActionItem(
    CaseId CaseId,
    DocumentId SourceDocumentId,
    ReceivableActionId? ActionId,
    ReceivableActionType? ActionType,
    decimal? TotalAmount,
    string? Currency,
    DateOnly DueDate,
    ProductTodayStatus Status,
    TodayDueState DueState,
    string? SafeReason);

public sealed record TodayActionPage(IReadOnlyList<TodayActionItem> Items, TodayCursor? NextCursor);

public sealed class TodayService
{
    private readonly IProductQueryStore _store;
    private readonly TimeProvider _clock;
    private readonly ILocalTimeZoneProvider _timeZone;

    public TodayService(IProductQueryStore store, TimeProvider? clock = null, ILocalTimeZoneProvider? timeZone = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _clock = clock ?? TimeProvider.System;
        _timeZone = timeZone ?? SystemLocalTimeZoneProvider.Instance;
    }

    public async Task<TodayActionPage> QueryAsync(TodayPageRequest request, CancellationToken cancellationToken)
    {
        var page = await _store.QueryTodayAsync(request, cancellationToken).ConfigureAwait(false);
        var localDate = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(_clock.GetUtcNow(), _timeZone.GetLocalTimeZone()).DateTime);
        return new TodayActionPage(page.Items.Select(item => new TodayActionItem(item.CaseId,
            item.SourceDocumentId, item.ActionId, item.ActionType,
            item.TotalAmount, item.Currency, item.DueDate,
            item.Status, item.DueDate < localDate ? TodayDueState.Overdue : item.DueDate == localDate ? TodayDueState.DueToday : TodayDueState.Upcoming,
            item.SafeReason)).ToArray(), page.NextCursor);
    }
}
