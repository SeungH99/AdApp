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

function renderEvidence() {
  elements.evidence.replaceChildren();
  if (!currentItem || !elements.preview.naturalWidth || !elements.preview.naturalHeight) {
    return;
  }

  const boxes = currentItem.fields.flatMap((field) =>
    field.evidence
      .filter((box) => box.sourceIndex === currentPage)
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

  const response = await api(
    `/api/documents/${encodeURIComponent(currentItem.documentId)}/pages/${currentPage}.png`,
  );
  if (!response.ok || response.headers.get("content-type") !== "image/png") {
    throw new Error("preview");
  }

  const blob = await response.blob();
  if (previewUrl) {
    URL.revokeObjectURL(previewUrl);
  }
  previewUrl = URL.createObjectURL(blob);
  elements.preview.src = previewUrl;
  elements.pageLabel.textContent = `Page ${currentPage + 1} of ${currentItem.pageCount}`;
  elements.previousPage.disabled = currentPage === 0;
  elements.nextPage.disabled = currentPage + 1 >= currentItem.pageCount;
}

function renderItem(item) {
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

elements.preview.addEventListener("load", renderEvidence);
elements.previousPage.addEventListener("click", async () => {
  if (currentPage > 0) {
    currentPage -= 1;
    await loadPreview();
  }
});
elements.nextPage.addEventListener("click", async () => {
  if (currentItem && currentPage + 1 < currentItem.pageCount) {
    currentPage += 1;
    await loadPreview();
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
  if (previewUrl) {
    URL.revokeObjectURL(previewUrl);
  }
});
