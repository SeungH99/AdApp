export class PreviewRequestState {
  #generation = 0;
  #controller = null;

  begin(item, page) {
    this.#controller?.abort();
    this.#controller = new AbortController();
    const context = Object.freeze({
      generation: ++this.#generation,
      documentId: item.documentId,
      revisionSha256: item.labelRevisionSha256,
      page,
      signal: this.#controller.signal,
    });
    return context;
  }

  isCurrent(context, item, page) {
    return Boolean(
      context
      && item
      && !context.signal.aborted
      && context.generation === this.#generation
      && context.documentId === item.documentId
      && context.revisionSha256 === item.labelRevisionSha256
      && context.page === page,
    );
  }

  cancel() {
    this.#generation += 1;
    this.#controller?.abort();
    this.#controller = null;
  }
}
