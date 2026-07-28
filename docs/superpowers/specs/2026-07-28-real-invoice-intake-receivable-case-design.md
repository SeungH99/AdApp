# Real Invoice Intake to Receivable Case Design

Date: 2026-07-28

Status: Approved for specification

Branch: `release-issue-8`

Issue: [#10](https://github.com/SeungH99/AdApp/issues/10)

## 1. Summary

This release epic replaces the static WinUI document and Case demonstration with
the first real product vertical slice:

1. receive an invoice through a file picker, drag and drop, or one watched
   folder;
2. copy the exact source bytes into the encrypted local Vault without changing
   the original;
3. extract invoice fields and evidence through the existing local
   AppContainer Worker;
4. let the user confirm the market, all required fields, and every evidence
   coordinate;
5. create a receivable Case only after explicit approval; and
6. show a real `Confirm payment received` action in Today.

The slice supports PDF, JPG, PNG, and TIFF. It handles only invoices issued by
the user, meaning money the user expects to receive. It does not complete the
Case, match bank transactions, or change source files.

## 2. Problem

The repository already contains hardened local infrastructure for encrypted
storage, event persistence, projection recovery, file transactions, Worker
execution, and document corpus validation. The product WinUI does not compose
those capabilities. It currently creates a `MainWindow` directly, displays
hard-coded content, and invokes the Case close decider with fixed identifiers.

Users therefore cannot yet:

- add a real document;
- observe processing state;
- review extracted fields and document evidence;
- create a persisted Case from an invoice; or
- see the resulting work in Today.

The goal is to connect one complete, reviewable, local-only workflow without
coupling the UI directly to SQLite, the Vault, the file system, or the Worker.

## 3. Goals

- Add a dedicated Application layer between WinUI and Core/Infrastructure.
- Converge picker, drag-and-drop, and watched-folder inputs on one intake
  service.
- Preserve source bytes, source name, and source location unchanged.
- Deduplicate exact content by SHA-256 across every intake channel.
- Extract and review the six invoice fields already defined by the empirical
  invoice contract.
- Require evidence and explicit user confirmation before Case creation.
- Create only outbound receivable Cases.
- Persist Inbox, review, Case, and Today state across restart.
- Recover interrupted intake, extraction, outbox, and projection work.
- Keep document content and local metadata out of Git and diagnostic logs.

## 4. Non-goals

This epic does not implement:

- accounts payable or utility-payment Cases;
- return, refund, warranty, or other Case types;
- payment-proof linking, Case closure, or Undo UI;
- bank feed import or automatic transaction matching;
- Office documents, email messages, or email attachments;
- more than one watched folder;
- recursive watched-folder traversal or include/exclude rules;
- an always-running Windows background service;
- server-side processing, remote AI, or cloud synchronization;
- local LLM inference or inferred missing invoice values;
- automatic source rename, move, or deletion;
- complete application localization;
- installer, MSIX, code signing, licensing, or payment integration; or
- satisfaction of the 36-cell, 1,440-document production empirical gate.

## 5. Confirmed Product Decisions

| Decision | Result |
|---|---|
| First vertical slice | Document intake to receivable Case to Today |
| Case creation | Explicit user approval only |
| Intake channels | Picker, drag and drop, one watched folder |
| Source mutation | Never rename, move, overwrite, or delete |
| Formats | PDF, JPG, PNG, TIFF |
| Incomplete extraction | Keep as `NeedsReview`; block Case creation |
| Case type | User-issued invoice / accounts receivable only |
| Epic completion point | Today shows `Confirm payment received` |
| Watched folder | One folder, non-recursive |
| Duplicate policy | Same SHA-256 returns the existing Inbox item |
| Market | App suggests `ko-KR` or `en-US`; user confirms |
| Required data | Six fields and evidence for every field |

## 6. Architecture

### 6.1 Dependency direction

```text
LocalDocumentOrganizer.App
        |
        v
LocalDocumentOrganizer.Application
        |
        v
LocalDocumentOrganizer.Core

LocalDocumentOrganizer.Infrastructure.Windows
        |
        +-- implements Application and Core ports
        +-- composes SQLite, Vault, file system, watcher, and Worker
```

Project-reference rules:

- `LocalDocumentOrganizer.Core` remains dependency-free.
- `LocalDocumentOrganizer.Application` references Core and defines product use
  cases plus infrastructure ports.
- `LocalDocumentOrganizer.Infrastructure.Windows` references Application and
  Core to implement those ports.
- `LocalDocumentOrganizer.App` references Application and Infrastructure and
  acts as the composition root.
- `tools/CorpusWorkbench` remains a development and corpus-validation tool. No
  product runtime project references it.
- The existing document extraction Worker remains a separately launched,
  attested AppContainer process.

Architecture tests must reject App access to SQLite/file-system concrete types
outside the composition root and reject any product runtime reference to
CorpusWorkbench.

### 6.2 Process model

The WinUI process owns the Application services and watched-folder coordinator.
The watcher runs only while the app is open. A bounded non-recursive startup
scan catches files added while the app was closed.

Document extraction remains out of process. This epic does not introduce a
daemon, Windows service, or new IPC protocol.

## 7. Application Components

### 7.1 `DocumentIntakeService`

Responsibilities:

- normalize picker, drag/drop, and watcher requests;
- accept only regular PDF, JPG, PNG, and TIFF files;
- apply the existing extraction limits uniformly: at most 20 MiB encoded
  input, 20 PDF pages, 16,384 pixels per raster dimension, and 100,000,000
  decoded pixels;
- obtain a stable read-only source handle;
- bind source identity, length, and SHA-256;
- check the content index for an existing document;
- publish a new immutable Vault object without replacement; and
- append the initial product document event and extraction outbox item.

The service returns either a newly created document identity or the existing
Inbox identity for duplicate content. It never returns a path as the stable
product identifier.

An extension or magic type outside the supported set is rejected before Vault
publication and produces a safe intake notification rather than a durable
Inbox item. A supported container that is later found to be corrupt or
unreadable has already become a product document and receives a durable
`Unsupported` or `Failed` Inbox state.

### 7.2 `DocumentProcessingService`

Responsibilities:

- dispatch authenticated extraction through the existing Worker client;
- bind the request to document identity, exact bytes, and Worker package
  identity;
- validate response shape, limits, evidence coordinates, source length, and
  source SHA;
- generate a deterministic market suggestion;
- persist encrypted extraction Draft state; and
- transition the Inbox item to `ReadyForReview`, `NeedsReview`, `Unsupported`,
  or `Failed`.

The market suggestion may use detected language, currency, and recognized
document patterns. It is never treated as user confirmation.

Missing or uncertain values remain missing or uncertain. This service does not
invent a value through an LLM or heuristic default.

### 7.3 `InboxService`

Responsibilities:

- provide bounded, paged Inbox queries;
- expose processing state without exposing infrastructure details;
- return the current extraction revision and sanitized failure code;
- resolve duplicate intake to the existing item; and
- prevent review or Case commands against stale revisions.

### 7.4 `InvoiceReviewService`

The service requires these field identifiers:

1. `issuer_name`;
2. `invoice_number`;
3. `issue_date`;
4. `payment_due_date`;
5. `total_amount`; and
6. `currency`.

Every field must have user-confirmed evidence tied to the reviewed document
revision. A corrected value remains distinguishable from the Worker's original
value. Corrections do not rewrite the extraction record.

The user must also:

- confirm `ko-KR` or `en-US`;
- confirm that the document is an invoice issued by the user; and
- provide explicit approval for the reviewed revision.

If the document is an incoming/payable invoice, the Inbox item remains
available with a `Not supported in this version` state and cannot create a
Case.

### 7.5 `ReceivableCaseService`

Responsibilities:

- verify the confirmed review revision and outbound direction;
- reject a second Case for the same source document;
- append the receivable Case creation event;
- link the invoice as the first Case evidence document; and
- update the Case and Today projections through the existing atomic event-store
  boundary.

The resulting Case is open and contains a single required action:
`Confirm payment received`. Case completion and payment proof are deliberately
outside this epic.

### 7.6 `WatchFolderCoordinator`

Responsibilities:

- store one approved non-recursive folder setting;
- watch create and change notifications while the app runs;
- wait for a file to become stable before intake;
- perform a bounded startup reconciliation scan;
- recover from watcher buffer overflow by rescanning; and
- send all discovered files through `DocumentIntakeService`.

It does not claim ownership of the source folder and does not mutate entries.

## 8. Core Domain

Core gains product-level document and receivable Case contracts. They remain
independent from Windows, SQLite, and OCR implementation details.

Representative events:

- `ProductDocumentImported`;
- `ProductDocumentExtractionAccepted`;
- `ProductDocumentNeedsReview`;
- `InvoiceReviewConfirmed`;
- `ReceivableCaseCreated`; and
- `ReceivableActionRequired`.

Event payloads use stable document, review-revision, Case, and action
identifiers. Sensitive values are protected by the existing authenticated
event-payload provider before persistence.

### 8.1 Product document state

```text
Discovered
  -> Stabilizing
  -> Imported
  -> Processing
  -> ReadyForReview | NeedsReview | Unsupported | Failed
  -> ReviewConfirmed
  -> CaseCreated
```

`Discovered` and `Stabilizing` are intake-operation states. A durable product
document begins at `Imported`.

The transitions are monotonic for a specific extraction revision. Reprocessing
creates a new revision instead of rewriting a confirmed one.

### 8.2 Case invariants

A receivable Case can be created only when:

- the product document exists in the Vault;
- the extraction and review revisions match;
- the market is user-confirmed;
- all six fields are present and valid;
- every field has valid evidence;
- the user confirmed outbound/receivable direction;
- explicit approval is present; and
- no Case already references the document as its source invoice.

### 8.3 Field normalization

- `issuer_name` preserves the user-confirmed display value and uses Unicode
  normalization only for comparison.
- `invoice_number` preserves the confirmed text after surrounding whitespace
  removal. Case-folding is not used to rewrite the displayed value.
- `issue_date` and `payment_due_date` are timezone-free calendar dates stored
  in ISO `yyyy-MM-dd` form.
- The due date must be on or after the issue date. Relative payment terms do not
  create a missing explicit due date.
- `total_amount` is a positive base-10 decimal value. No floating-point or
  foreign-exchange conversion occurs.
- `currency` is a user-confirmed three-letter ISO 4217 code. A currency symbol
  may support a suggestion but cannot resolve an ambiguous currency without
  confirmation.
- Today compares the due date with the user's current local calendar date.
- Evidence coordinates and page identity remain bound to the exact accepted
  document bytes and extraction revision.

## 9. End-to-end Data Flow

1. A picker, drop target, or watcher creates an intake request.
2. The intake service opens the source through a stable read-only handle.
3. It captures file identity, length, and SHA-256.
4. Existing SHA returns the current Inbox item without a new copy or event.
5. New content is copied into a temporary Vault object and revalidated.
6. The Vault object is published with no-replace semantics.
7. The product document event and extraction outbox entry are persisted.
8. The Worker receives a read-only handle bound to the accepted bytes.
9. The Application layer validates the authenticated Worker result.
10. The Inbox projection exposes `ReadyForReview` or `NeedsReview`.
11. The user reviews the document preview, market, fields, and evidence.
12. The review command includes the expected extraction revision.
13. The user confirms outbound direction and explicitly approves Case
    creation.
14. The Case event and Today projection commit atomically.
15. Today displays the real `Confirm payment received` action.

The original source may later be renamed, edited, or deleted by the user. The
accepted Vault bytes and their SHA remain the product record. If the same path
later contains different bytes, those bytes form a new document.

## 10. Persistence and Recovery

### 10.1 Product data

The existing encrypted SQLite event store remains the source of truth.
Product-specific projections provide Inbox, Case, and Today reads.

The Vault stores immutable content-addressed document bytes. Paths, filenames,
extracted values, and evidence data are never used as global identifiers.
The original display filename may be retained only as authenticated encrypted
metadata for the unlocked UI. A document's full source path is not retained
after intake. The single watched-folder root is a separate protected setting.

### 10.2 Atomic boundaries

- A Vault object is fully copied and revalidated before publication.
- Event append never claims an unverified or temporary object.
- An event-append failure after Vault publication produces a bounded orphan
  that startup reconciliation may identify and safely clean.
- Extraction dispatch uses an outbox so a committed import cannot lose its
  processing request.
- Review confirmation uses optimistic concurrency on the extraction revision.
- Case creation and product projections use the existing atomic SQLite commit
  and rebuild rules.

### 10.3 Startup sequence

1. open and authenticate the Vault key ring;
2. initialize and validate the event store;
3. complete required projection recovery;
4. recover pending operation and extraction outboxes;
5. start the watched-folder coordinator; and
6. run the bounded non-recursive reconciliation scan.

The UI remains in a recovery state until the minimum safe read models are
available. It never displays hard-coded fallback business data.

## 11. WinUI Design

### 11.1 Composition

`App` creates the dependency-injection container, initializes the application
host, and then creates `MainWindow`.

Views and ViewModels consume Application query and command interfaces only.
Code-behind is limited to platform events such as file picking, drag/drop, and
window behavior.

### 11.2 Screens

**Inbox**

- real bounded list of product documents;
- status, received time, suggested/confirmed market, and safe type label;
- duplicate intake focuses the existing row;
- processing and recoverable failure states are visible.

**Review**

- document preview;
- six fields with original and corrected values;
- field-level evidence navigation;
- market suggestion and confirmation;
- outbound-invoice confirmation;
- `Create Case` disabled until every invariant is satisfied.

**Today**

- real projection rows;
- created receivable Case;
- amount, currency, due status, reason, and `Confirm payment received` action;
- completion action visibly marked as unavailable until the following epic.

**Cases**

- basic persisted Case detail and linked source invoice;
- no proof-link, close, or Undo command in this epic.

**Settings**

- choose, replace, or clear one watched folder;
- show watcher and reconciliation health using safe status text.

New UI copy uses resource keys where the touched view permits it, but complete
application localization is a separate release epic.

## 12. Error Handling

| Failure | Required behavior |
|---|---|
| Source is still changing or locked | Wait for two stable observations; retry for at most 30 seconds |
| Duplicate SHA | Return and focus the existing Inbox item |
| Unsupported extension or magic | Reject before Vault publication and show a safe intake notice |
| Supported but corrupt container | Retain the imported document with a safe `Unsupported` or `Failed` Inbox state |
| Missing field or evidence | Set `NeedsReview`; keep Case creation disabled |
| Worker transient failure | Retry automatically once |
| Worker timeout or second failure | Persist a safe failure and offer manual reprocessing |
| Worker identity/SHA/length mismatch | Reject the result and block all downstream commands |
| Vault copy or publication failure | Remove or quarantine temporary state; never change source |
| SQLite commit failure | Do not show success; retain an idempotent retry path |
| Watcher overflow | Stop trusting event continuity and run a bounded full rescan |
| Review revision conflict | Preserve user input, reload latest revision, require reconfirmation |
| App termination | Resume outbox, projection, and processing recovery at next start |

Automatic retry is bounded. The app never loops forever or silently converts
an invalid document into a Case.

User-visible errors contain stable safe codes and actionable descriptions.
Logs exclude document text, field values, filenames, and full paths.

## 13. Security and Privacy

- All processing remains local.
- Source handles are read-only and deny untrusted replacement during
  verification.
- Approved-root and reparse-point protections remain fail-closed.
- Vault objects are content addressed and published without replacement.
- Extraction responses are bound to source bytes and sealed Worker identity.
- Event and projection payloads use existing DPAPI-backed authenticated
  protection.
- Watched-folder configuration is protected local state.
- Diagnostic output uses content-free tokens.
- No real document, extraction output, review payload, or local path is tracked
  by Git.
- Case creation is an explicit user-approved state change.

## 14. Testing Strategy

Test source remains under the ignored local `tests/` tree. Pull requests record
commands and results but do not include test source.

### 14.1 Architecture tests

- Core has no outward dependency.
- Application references Core but not Infrastructure or App.
- Infrastructure implements inward ports.
- App is the only composition root.
- Product projects do not reference CorpusWorkbench.

### 14.2 Core tests

- all six fields and evidence are required;
- market and outbound direction are required;
- explicit approval is required;
- stale revisions are rejected;
- incoming invoices are rejected for Case creation; and
- one source invoice cannot create two Cases.

### 14.3 Application tests

- all three intake channels converge on one service;
- exact-content duplicate returns the existing identity;
- each document-state transition is valid and idempotent;
- incomplete extraction remains `NeedsReview`;
- review corrections preserve original extraction values;
- outbox recovery resumes after restart; and
- Case creation produces the Today action exactly once.

### 14.4 Windows infrastructure tests

- stable-handle and source-identity replacement resistance;
- PDF and image format validation;
- Vault copy, revalidation, no-replace publication, and cleanup;
- non-recursive watcher stabilization and reconciliation;
- watcher overflow recovery;
- Worker timeout, crash, and attestation mismatch;
- encrypted SQLite commit and projection recovery; and
- restart recovery without plaintext leakage.

Native WorkerSecurity and CorpusWorkbench suites run serially because their
protected package-root tests must not compete for the same native handles.

### 14.5 WinUI and smoke tests

- picker and drag/drop command routing;
- Inbox state rendering;
- Review validation and disabled/enabled Case button;
- duplicate-item focus;
- watched-folder setting and health state;
- Today row created from persisted data; and
- full restart smoke from import through Today.

## 15. Acceptance Criteria

The epic is complete only when:

1. PDF, JPG, PNG, and TIFF work through picker, drop, and watched-folder intake.
2. Source contents, filename, and location remain unchanged.
3. Same bytes produce one Inbox document across channels and filenames.
4. The app suggests a market and requires user confirmation.
5. The six required fields and their evidence are user-confirmed.
6. Incomplete or uncertain extraction cannot create a Case.
7. Only a user-issued receivable invoice can create a Case.
8. Explicit approval creates one persisted Case and one Today action.
9. Inbox, Case, Today, outbox, and processing state recover after restart.
10. Logs, diagnostics, Git, and reports expose no private document content or
    local metadata.
11. Existing regression tests and the new ignored local tests pass.
12. Release build finishes with zero warnings and zero errors.
13. Independent SPEC and QUALITY review reports no Critical or Important
    findings.

## 16. Follow-up Epics

The next product slices may add:

1. payment proof linking, explicit completion, and Undo;
2. bank transaction import and match suggestions;
3. payable, utility, return, and refund Cases;
4. multiple and recursive watched folders;
5. Office and email inputs;
6. complete `ko-KR`/`en-US` application localization;
7. packaging, code signing, updating, and licensing; and
8. production empirical corpus completion.
