import { PreviewRequestState } from "/preview-request-state.js";

const fragment = window.location.hash.slice(1);
const validToken = /^[0-9a-f]{64}$/.test(fragment);
history.replaceState(null, "", window.location.pathname);
const sessionToken = validToken ? fragment : null;

const fieldLabels = new Map([
  ["issuer_name", "Issuer name"],
  ["invoice_number", "Invoice number"],
  ["issue_date", "Issue date"],
  ["payment_due_date", "Payment due date"],
  ["total_amount", "Total amount"],
  ["currency", "Currency"],
]);

const elements = {
  market: document.querySelector("#market"),
  progress: document.querySelector("#review-progress"),
  notice: document.querySelector("#notice"),
  workspace: document.querySelector("#review-workspace"),
  documentHeading: document.querySelector("#document-heading"),
  ruleLink: document.querySelector("#official-rule"),
  ruleVersion: document.querySelector("#rule-version"),
  fields: document.querySelector("#fields"),
  form: document.querySelector("#review-form"),
  preview: document.querySelector("#page-preview"),
  evidence: document.querySelector("#evidence-layer"),
  pageLabel: document.querySelector("#page-label"),
  previousPage: document.querySelector("#previous-page"),
  nextPage: document.querySelector("#next-page"),
};

let currentItem = null;
let currentPage = 0;
let previewUrl = null;
const previewRequestState = new PreviewRequestState();

function showNotice(message) {
  elements.notice.textContent = message;
  elements.notice.hidden = false;
}

function clearNotice() {
  elements.notice.textContent = "";
  elements.notice.hidden = true;
}

async function api(path, options = {}) {
  if (!sessionToken) {
    throw new Error("session");
  }

  const headers = new Headers(options.headers || {});
  headers.set("X-Corpus-Session", sessionToken);
  const response = await fetch(path, {
    ...options,
    headers,
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
  });
  return response;
}

function renderFields(item) {
  elements.fields.replaceChildren();
  for (const field of item.fields) {
    const wrapper = document.createElement("div");
    wrapper.className = "field";
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.id = `field-${field.fieldId}`;
    input.name = field.fieldId;
    input.value = field.normalizedValue;
    input.autocomplete = "off";
    input.spellcheck = false;
    label.htmlFor = input.id;
    label.textContent = fieldLabels.get(field.fieldId) || "Normalized field";
    wrapper.append(label, input);
    elements.fields.append(wrapper);
  }
}

function renderEvidence(item, page) {
  elements.evidence.replaceChildren();
  if (!item || !elements.preview.naturalWidth || !elements.preview.naturalHeight) {
    return;
  }

  const boxes = item.fields.flatMap((field) =>
    field.evidence
      .filter((box) => box.sourceIndex === page)
      .map((box) => ({ ...box, fieldId: field.fieldId })),
  );
  const widthExtent = Math.max(
    elements.preview.naturalWidth,
    ...boxes.map((box) => box.x + box.width),
  );
  const heightExtent = Math.max(
    elements.preview.naturalHeight,
    ...boxes.map((box) => box.y + box.height),
  );
  elements.evidence.setAttribute(
    "viewBox",
    `0 0 ${widthExtent} ${heightExtent}`,
  );
  elements.evidence.setAttribute("preserveAspectRatio", "none");
  for (const box of boxes) {
    const overlay = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "rect",
    );
    overlay.setAttribute("class", "evidence-box");
    overlay.setAttribute("x", box.x);
    overlay.setAttribute("y", box.y);
    overlay.setAttribute("width", box.width);
    overlay.setAttribute("height", box.height);
    elements.evidence.append(overlay);
  }
}

async function loadPreview() {
  if (!currentItem) {
    return;
  }

  const item = currentItem;
  const page = currentPage;
  const context = previewRequestState.begin(item, page);
  elements.previousPage.disabled = true;
  elements.nextPage.disabled = true;
  try {
    const response = await api(
      `/api/documents/${encodeURIComponent(item.documentId)}/pages/${page}.png`,
      { signal: context.signal },
    );
    if (!response.ok || response.headers.get("content-type") !== "image/png") {
      throw new Error("preview");
    }

    const blob = await response.blob();
    if (!previewRequestState.isCurrent(context, currentItem, currentPage)) {
      return;
    }

    const nextUrl = URL.createObjectURL(blob);
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
    previewUrl = nextUrl;
    elements.preview.onload = () => {
      if (
        previewUrl === nextUrl
        && previewRequestState.isCurrent(
          context,
          currentItem,
          currentPage,
        )
      ) {
        renderEvidence(item, page);
      }
    };
    elements.preview.src = nextUrl;
    elements.pageLabel.textContent = `Page ${page + 1} of ${item.pageCount}`;
  } catch (error) {
    if (error?.name !== "AbortError") {
      throw error;
    }
  } finally {
    if (previewRequestState.isCurrent(context, currentItem, currentPage)) {
      elements.previousPage.disabled = page === 0;
      elements.nextPage.disabled = page + 1 >= item.pageCount;
    }
  }
}

function renderItem(item) {
  previewRequestState.cancel();
  currentItem = item;
  currentPage = 0;
  elements.market.textContent = item.market;
  elements.progress.textContent = `${item.position} of ${item.total}`;
  elements.documentHeading.textContent = item.documentId;
  elements.ruleLink.href = item.officialRuleLink;
  elements.ruleVersion.textContent =
    `Rule v${item.officialRuleVersion} · ${item.officialRuleSha256.slice(0, 12)}`;
  renderFields(item);
  elements.workspace.hidden = false;
}

async function loadNext(stale = false) {
  clearNotice();
  const response = await api("/api/review/next");
  if (response.status === 204) {
    previewRequestState.cancel();
    currentItem = null;
    elements.workspace.hidden = true;
    elements.progress.textContent = "No pending review items";
    return;
  }
  if (!response.ok) {
    throw new Error("review");
  }

  renderItem(await response.json());
  await loadPreview();
  if (stale) {
    showNotice("This item changed before your decision. The current revision was reloaded; your edits were not applied.");
  }
}

function correctedFields() {
  return currentItem.fields.map((field) => ({
    ...field,
    normalizedValue: elements.form.elements.namedItem(field.fieldId).value,
  }));
}

async function submitDecision(decision) {
  const buttons = elements.form.querySelectorAll("button");
  for (const button of buttons) {
    button.disabled = true;
  }
  try {
    const response = await api(
      `/api/documents/${encodeURIComponent(currentItem.documentId)}/decisions`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          labelRevisionSha256: currentItem.labelRevisionSha256,
          decision,
          correctedFields:
            decision === "correctAndApprove" ? correctedFields() : [],
        }),
      },
    );
    if (response.status === 409) {
      await loadNext(true);
      return;
    }
    if (!response.ok) {
      throw new Error("decision");
    }
    await loadNext(false);
  } finally {
    for (const button of buttons) {
      button.disabled = false;
    }
  }
}

elements.previousPage.addEventListener("click", async () => {
  if (currentPage > 0) {
    currentPage -= 1;
    try {
      await loadPreview();
    } catch {
      showNotice("The requested preview page could not be loaded.");
    }
  }
});
elements.nextPage.addEventListener("click", async () => {
  if (currentItem && currentPage + 1 < currentItem.pageCount) {
    currentPage += 1;
    try {
      await loadPreview();
    } catch {
      showNotice("The requested preview page could not be loaded.");
    }
  }
});
elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const decision = event.submitter?.dataset.decision;
  if (!decision || !currentItem) {
    return;
  }
  clearNotice();
  try {
    await submitDecision(decision);
  } catch {
    showNotice("The review action could not be completed. Reload the current item and try again.");
  }
});

if (!sessionToken) {
  elements.progress.textContent = "Session unavailable";
  showNotice("Open this page from the local corpus workbench.");
} else {
  loadNext(false).catch(() => {
    elements.progress.textContent = "Review unavailable";
    showNotice("The local review session could not load the next item.");
  });
}

window.addEventListener("pagehide", () => {
  previewRequestState.cancel();
  if (previewUrl) {
    URL.revokeObjectURL(previewUrl);
  }
});
