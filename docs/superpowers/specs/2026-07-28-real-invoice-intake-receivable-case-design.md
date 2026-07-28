# Real Invoice Intake to Receivable Case Design

Date: 2026-07-28

Status: Approved for specification

Branch: `release-issue-8`

Issue: [#10](https://github.com/SeungH99/AdApp/issues/10)

## 1. Summary

This release epic replaces the static WinUI document and Case demonstration with
the first real product vertical slice:

1. receive an invoice through a file picker or drag and drop;
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
- Converge picker and drag-and-drop inputs on one intake service.
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
- watched-folder ingestion beyond a contract reserved for the next release;
- an always-running Windows background service;
- server-side processing, remote AI, or cloud synchronization;
- local LLM inference or inferred missing invoice values;
- automatic source rename, move, or deletion;
- locales beyond `en-US` and `ko-KR`;
- installer, MSIX, code signing, licensing, or payment integration; or
- satisfaction of the 36-cell, 1,440-document production empirical gate.

## 5. Confirmed Product Decisions

| Decision | Result |
|---|---|
| First vertical slice | Document intake to receivable Case to Today |
| Case creation | Explicit user approval only |
| Intake channels | Picker and drag and drop |
| Source mutation | Never rename, move, overwrite, or delete |
| Formats | PDF, JPG, PNG, TIFF |
| Incomplete extraction | Keep as `NeedsReview`; block Case creation |
| Case type | User-issued invoice / accounts receivable only |
| Epic completion point | Today shows `Confirm payment received` |
| Watched folder | Contract only; implementation deferred |
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
        +-- composes SQLite, Vault, file system, and Worker
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
- Pure invoice labeling, official rule contracts, and the `en-US`/`ko-KR`
  catalog move into Application. CorpusWorkbench consumes them through a thin
  adapter so product and corpus validation cannot drift.
- The existing document extraction Worker remains a separately launched,
  attested AppContainer process.

Architecture tests must reject App access to SQLite/file-system concrete types
outside the composition root and reject any product runtime reference to
CorpusWorkbench.

### 6.2 Process model

The WinUI process owns the Application services. Before XAML, DI, the Vault, or
SQLite initializes, `AppInstance.FindOrRegisterForKey` acquires the single
product instance. A second launch redirects activation to the current instance
and exits without opening the Vault.

Document extraction remains out of process. This epic does not introduce a
daemon, Windows service, or new IPC transport. The existing attested Worker
protocol gains one admission-only `InspectDocument` operation that returns an
authoritatively validated PDF page count. It reuses the existing source-byte
binding, package attestation, limits, and AppContainer isolation, extracts no
document fields, and exists only to enforce the pre-Vault page limit.

Picker and drag/drop requests enter one bounded `Channel`. The import consumer
processes one document at a time, and the extraction consumer runs one Worker
at a time. Queue state is observable by the UI; no unbounded `Task.WhenAll`
fan-out is allowed.

### 6.3 Atomic product commits

Application depends on a coarse-grained `IProductCommitStore`. Infrastructure
owns the SQLite transaction for these use-case commits:

- `CommitImport`;
- `CommitExtraction`;
- `CommitReview`; and
- `CommitReceivableCase`.

The interface returns explicit committed, already-committed, conflict, and
recovery-required outcomes. Application never composes separate event, outbox,
and projection repositories into an assumed transaction.

## 7. Application Components

### 7.1 `DocumentIntakeService`

Responsibilities:

- normalize picker and drag/drop requests;
- accept only regular PDF, JPG, PNG, and TIFF files;
- apply the existing extraction limits uniformly: at most 20 MiB encoded
  input, 20 PDF pages, 16,384 pixels per raster dimension, and 100,000,000
  decoded pixels;
- use the existing attested Worker protocol's admission-only
  `InspectDocument` operation for authoritative PDF page counting, including
  object-stream and xref-stream documents; untrusted PDF parsing never moves
  into the WinUI process;
- obtain a stable read-only source handle;
- bind source identity, length, and SHA-256;
- check the content index for an existing document;
- publish a new immutable Vault object without replacement; and
- append the initial product document event and extraction outbox item.

The service returns either a newly created document identity or the existing
Inbox identity for duplicate content. It never returns a path as the stable
product identifier.

The SQLite content index has a unique constraint on content SHA-256. A
concurrent or recovery-time conflict is a successful
`AlreadyImported(existingInboxId)` result, not an error. A Vault no-replace
collision resolves through the same committed identity.

Every new import persists a `VaultImport` intent in the existing Operation
Journal before file publication. The state machine records copy, verification,
publication, product commit, side-effects, and completion. Recovery reuses the
journal evidence to resume, roll back, or require explicit manual recovery; it
never guesses ownership from an unreferenced file scan alone.

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

Each outbox entry persists an `ExtractionAttemptId`, its target extraction
revision, and the commit operation ID. Crash recovery and automatic retry reuse
all three values. Only explicit user-requested reprocessing allocates a new
attempt and revision.

The market suggestion may use detected language, currency, and recognized
document patterns. It is never treated as user confirmation.

Missing or uncertain values remain missing or uncertain. This service does not
invent a value through an LLM or heuristic default.

### 7.3 `InboxService`

Responsibilities:

- provide bounded, keyset-paged Inbox queries;
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

### 7.6 Deferred watched-folder port

Application may reserve an `IWatchedFolderIntake` contract so the next release
can enter the same intake queue. This epic does not implement configuration,
`FileSystemWatcher`, stabilization, reconciliation, Settings UI, or background
execution.

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

The transitions are monotonic for a specific extraction revision. Automatic
retry reuses the same attempt and revision. Explicit user reprocessing creates
a new revision instead of rewriting a confirmed one.

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
- Today stores the timezone-free `DateOnly` due date, then computes display
  status at query time using an injected clock and current system time zone.
- Today refreshes at local midnight and when the system time zone changes.
- Evidence coordinates and page identity remain bound to the exact accepted
  document bytes and extraction revision.

## 9. End-to-end Data Flow

1. A picker or drop target creates an intake request.
2. The intake service opens the source through a stable read-only handle.
3. It captures file identity, length, and SHA-256.
4. Existing SHA returns the current Inbox item without a new copy or event.
5. A `VaultImport` intent is persisted in the Operation Journal.
6. New content is copied into a temporary Vault object and revalidated.
7. The Vault object is published with no-replace semantics.
8. `IProductCommitStore.CommitImport` atomically writes the product document
   event and extraction outbox entry.
9. A unique-SHA conflict resolves to the existing Inbox identity.
10. The Worker receives a read-only handle bound to the accepted bytes.
11. The Application layer validates the authenticated Worker result.
12. The Inbox projection exposes `ReadyForReview` or `NeedsReview`.
13. The user reviews the document preview, market, fields, and evidence.
14. The review command includes the expected extraction revision.
15. The user confirms outbound direction and explicitly approves Case
    creation.
16. `CommitReceivableCase` atomically writes the Case event and rebuildable
    Case/Today projections.
17. Today displays the real `Confirm payment received` action.

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
after intake.

Inbox uses a stable `(received_at_utc, document_id)` keyset cursor. Today uses
stable `(due_date, case_id)` ordering. Projection tables have composite indexes
that support status plus those cursor keys; product reads do not replay event
streams per row.

### 10.2 Atomic boundaries

- A Vault object is fully copied and revalidated before publication.
- Event append never claims an unverified or temporary object.
- A failure after Vault publication remains owned by its `VaultImport`
  Operation Journal entry and follows an evidence-based recovery decision.
- Extraction dispatch uses an outbox so a committed import cannot lose its
  processing request.
- Extraction retry reuses the persisted attempt, target revision, and commit
  operation ID.
- Review confirmation uses optimistic concurrency on the extraction revision.
- Case creation and product projections use the existing atomic SQLite commit
  and rebuild rules.

### 10.3 Startup sequence

1. open and authenticate the Vault key ring;
2. initialize and validate the event store;
3. complete required projection recovery;
4. recover pending `VaultImport` operations;
5. recover extraction outboxes with their persisted attempt IDs; and
6. publish the minimum safe Inbox, Case, and Today read models.

The UI remains in a recovery state until the minimum safe read models are
available. It never displays hard-coded fallback business data.

## 11. WinUI Design

### 11.1 Composition

The custom entry point first enforces single instancing. The primary `App`
creates the dependency-injection container, initializes the application host,
and then creates `MainWindow`.

Views and ViewModels consume Application query and command interfaces only.
Code-behind is limited to platform events such as file picking, drag/drop, and
window behavior.

`MainWindow` is a Shell only. Inbox, Review, Today, and Cases are separate
Pages with separate ViewModels. Shared visual tokens remain in App resources;
business state never lives in XAML literals or Shell code-behind.

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

All user-facing strings in the split Shell and Pages use `en-US` and `ko-KR`
resources. `en-US` is the fallback language. Missing resource keys fail local
validation instead of silently shipping mixed hard-coded copy.

## 12. Error Handling

| Failure | Required behavior |
|---|---|
| Source is still changing or locked | Retry with a bounded delay and show a safe actionable intake error |
| Duplicate SHA | Return and focus the existing Inbox item |
| Concurrent duplicate SHA | Resolve the unique-index conflict to `AlreadyImported(existingInboxId)` |
| Unsupported extension or magic | Reject before Vault publication and show a safe intake notice |
| Supported but corrupt container | Retain the imported document with a safe `Unsupported` or `Failed` Inbox state |
| Missing field or evidence | Set `NeedsReview`; keep Case creation disabled |
| Worker transient failure | Retry automatically once with the same attempt ID and revision |
| Worker timeout or second failure | Persist a safe failure and offer manual reprocessing |
| Worker identity/SHA/length mismatch | Reject the result and block all downstream commands |
| Vault copy or publication failure | Remove or quarantine temporary state; never change source |
| SQLite commit failure | Do not show success; retain an idempotent retry path |
| Review revision conflict | Preserve user input, reload latest revision, require reconfirmation |
| App termination | Resume outbox, projection, and processing recovery at next start |
| Second app launch | Redirect activation before Vault initialization |
| Local midnight or time-zone change | Requery Today and recompute due display state |

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
- Diagnostic output uses content-free tokens.
- No real document, extraction output, review payload, or local path is tracked
  by Git.
- Case creation is an explicit user-approved state change.

## 14. Testing Strategy

Test source remains under the ignored local `tests/` tree. Pull requests record
commands and results but do not include test source.

The release gate has three layers:

1. MSTest unit tests for Core and Application behavior;
2. real temporary Vault/SQLite integration tests for atomicity and recovery;
3. Appium with the Windows driver for the critical WinUI user journey.

### 14.1 Architecture tests

- Core has no outward dependency.
- Application references Core but not Infrastructure or App.
- Infrastructure implements inward ports.
- App is the only composition root.
- Product projects do not reference CorpusWorkbench.
- CorpusWorkbench reuses Application invoice rules through its adapter.

### 14.2 Core tests

- all six fields and evidence are required;
- market and outbound direction are required;
- explicit approval is required;
- stale revisions are rejected;
- incoming invoices are rejected for Case creation; and
- one source invoice cannot create two Cases.

### 14.3 Application tests

- picker and drag/drop converge on one service;
- exact-content duplicate returns the existing identity;
- a concurrent duplicate barrier produces one document and one Inbox identity;
- each document-state transition is valid and idempotent;
- incomplete extraction remains `NeedsReview`;
- review corrections preserve original extraction values;
- outbox recovery reuses the attempt ID and target revision;
- explicit reprocessing alone creates a new revision; and
- Case creation produces the Today action exactly once.

### 14.4 Windows infrastructure tests

- stable-handle and source-identity replacement resistance;
- PDF and image format validation;
- Vault copy, revalidation, no-replace publication, and cleanup;
- every `VaultImport` crash point and recovery decision;
- content-SHA unique constraint and conflict resolution;
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
- second-launch activation redirect;
- `en-US` and `ko-KR` resource rendering and English fallback;
- local-midnight and time-zone-change Today refresh;
- Today row created from persisted data; and
- full restart smoke from import through Today.

## 15. Acceptance Criteria

The epic is complete only when:

1. PDF, JPG, PNG, and TIFF work through picker and drag/drop intake.
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
14. Concurrent identical intake commits one document and returns one Inbox
    identity to both callers.
15. Automatic extraction recovery never creates a new revision.
16. Today changes due status at local midnight and after a time-zone change
    without restarting the app.
17. The split Shell and Pages render in `en-US` and `ko-KR` with English
    fallback.

## 16. Follow-up Epics

The next product slices may add:

1. payment proof linking, explicit completion, and Undo;
2. bank transaction import and match suggestions;
3. payable, utility, return, and refund Cases;
4. one non-recursive watched folder, followed later by multiple/recursive
   folder rules if usage justifies them;
5. Office and email inputs;
6. additional locales;
7. packaging, code signing, updating, and licensing; and
8. production empirical corpus completion.

## 17. What already exists

| Existing capability | Reuse decision |
|---|---|
| Core document extraction contracts and limits | Reuse unchanged as the product/Worker protocol boundary |
| AppContainer Worker, PDF/image adapters, attestation, and source binding | Reuse; product adds orchestration rather than another extractor |
| Encrypted SQLite event store and projection rebuild machinery | Reuse behind `IProductCommitStore` |
| Operation Journal and recovery state machine | Extend with `VaultImport`; do not build a second journal |
| Case state and explicit-approval patterns | Extend for receivable creation while preserving existing close behavior |
| CorpusWorkbench invoice labeler and official rule catalog | Move pure behavior to Application; retain a tool adapter |
| Static WinUI prototype and design resources | Preserve visual language while splitting it into Shell, Pages, and ViewModels |
| Local MSTest suites for storage, transactions, Worker, and corpus rules | Reuse and add product-specific local test projects |

## 18. NOT in scope

- Watched-folder execution is deferred because picker/drop proves the core job
  without introducing a second reliability subsystem.
- Payment proof, Case closure, and Undo are deferred to the next workflow slice.
- Payable, utility, return, refund, and warranty Cases require separate domain
  contracts and empirical validation.
- Bank, email, browser, Office, cloud, and server ingestion require separate
  privacy, authentication, reliability, and support reviews.
- Local or cloud LLM inference is deferred because deterministic official rules
  and explicit review are the current trust boundary.
- Installer, MSIX, signing, updating, licensing, and payment are a later
  distribution epic, not silently part of this runtime feature.
- Locales beyond `en-US` and `ko-KR` and the 1,440-document empirical gate are
  separate release work.

## 19. Failure modes

| Code path | Production failure | Test | Error handling | User outcome |
|---|---|---|---|---|
| App startup | Two processes open one Vault | Appium second-launch E2E | Redirect before initialization | Existing window activates |
| Intake identity | Picker and drop race on identical bytes | Concurrent barrier integration | Unique SHA maps to `AlreadyImported` | Existing Inbox item focuses |
| Vault publication | Process exits after file publish | Fault-injection integration at every journal state | `VaultImport` recovery decision | Recovery state, never silent success |
| Worker execution | Timeout, crash, or attestation mismatch | Existing Worker tests plus product integration | Safe failure code and bounded retry | Retry/reprocess action |
| Extraction commit | Crash after success before commit | Attempt-ID restart integration | Same operation/revision is replayed | Review does not become spuriously stale |
| Review | User submits an old revision | Application concurrency test | Reject and preserve edits | Reconfirm against latest revision |
| Case creation | Double click or retry creates two Cases | Atomic commit integration | Source-document uniqueness | One Case and one Today action |
| Today | App crosses midnight or changes time zone | Fake-clock unit plus Appium boundary E2E | Query-time status and refresh | Due label updates without restart |
| Localization | Resource key is missing | Resource completeness test | English fallback | No blank or mixed-key UI |
| Unsupported input | Magic/size/page limit fails | Worker and intake boundary tests | Reject before Vault or persist safe failure | Actionable safe message |

No planned failure mode remains untested, unhandled, and silent.

## 20. Worktree parallelization strategy

| Step | Modules touched | Depends on |
|---|---|---|
| Foundation contracts and shared invoice rules | Core/, Application/, CorpusWorkbench/ | — |
| Product storage and recovery | Core/Transactions/, Infrastructure.Windows/Storage/, Infrastructure.Windows/FileSystem/ | Foundation |
| Intake and extraction orchestration | Application/, Infrastructure.Windows/Documents/ | Foundation, storage |
| WinUI Shell and resources | App/, App/Resources/ | Foundation DTO freeze |
| Product Pages and ViewModels | App/Pages/, App/ViewModels/ | Orchestration, Shell |
| Local automated verification | tests/ | Each producing step |

Lane A: foundation → storage → intake/extraction → Case/Today orchestration.

Lane B: Shell/resources → Pages/ViewModels after the Foundation DTO freeze.

Lane C: ignored local tests begin with Foundation and follow each merged step;
Appium E2E waits for Lanes A and B.

Execution order: complete Foundation first. Then run Lane A storage work and
Lane B Shell/resources in parallel. Merge both, complete orchestration and
Pages/ViewModels, then run the final integration/Appium gate.

Conflict flag: Lane A and Lane B must not both change Application DTOs after the
Foundation freeze. Any contract change returns to sequential integration.

## 21. Implementation Tasks

Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Codex; checkbox as you ship.

- [ ] **T1 (P1, human: ~1d / CC: ~90min)** — Architecture — Create the Application boundary and share invoice rules.
  - Surfaced by: Architecture review 4A and code-quality review 5A.
  - Files: `src/LocalDocumentOrganizer.Application/`, `tools/CorpusWorkbench/`, solution/project references.
  - Verify: architecture tests and existing CorpusWorkbench labeler/catalog tests.
- [ ] **T2 (P1, human: ~2d / CC: ~3h)** — Storage — Add atomic product commits, projections, indexes, and SHA uniqueness.
  - Surfaced by: Architecture review 1A, performance review 9A, Outside Voice 11A.
  - Files: `src/LocalDocumentOrganizer.Core/`, `src/LocalDocumentOrganizer.Infrastructure.Windows/Storage/`.
  - Verify: atomic commit, rebuild, keyset paging, and concurrent duplicate integration tests.
- [ ] **T3 (P1, human: ~2d / CC: ~3h)** — Intake — Implement bounded picker/drop intake with `VaultImport` recovery and admission-only Worker inspection.
  - Surfaced by: scope decision 0A, architecture review 2A, performance review 8A.
  - Files: `src/LocalDocumentOrganizer.Application/`, `src/LocalDocumentOrganizer.Infrastructure.Windows/FileSystem/`, existing Worker protocol/client/adapter.
  - Verify: format/limit, stable-handle, every crash point, restart, and source-unchanged tests.
- [ ] **T4 (P1, human: ~2d / CC: ~3h)** — Extraction — Persist attempt identity and make retry/reprocessing idempotent.
  - Surfaced by: Outside Voice 12A and test review 7A.
  - Files: `src/LocalDocumentOrganizer.Application/`, `src/LocalDocumentOrganizer.Infrastructure.Windows/Documents/`, storage outbox.
  - Verify: Worker success/crash/timeout/attestation and restart tests.
- [ ] **T5 (P1, human: ~2d / CC: ~3h)** — Domain — Implement review approval, receivable Case creation, and Today projection.
  - Surfaced by: architecture review 1A and Outside Voice 13A.
  - Files: `src/LocalDocumentOrganizer.Core/Cases/`, Application use cases, product projections.
  - Verify: six-field/evidence invariants, stale revision, double-submit, midnight, and time-zone tests.
- [ ] **T6 (P1, human: ~1d / CC: ~2h)** — App lifecycle — Add single instancing and the DI composition root.
  - Surfaced by: architecture review 3A.
  - Files: `src/LocalDocumentOrganizer.App/` entry point, project configuration, composition root.
  - Verify: primary launch, second-launch redirect, activation routing, and locked-Vault startup tests.
- [ ] **T7 (P1, human: ~2d / CC: ~3h)** — WinUI — Split Shell/Pages/ViewModels and localize all user copy.
  - Surfaced by: code-quality reviews 5A and 6A.
  - Files: `src/LocalDocumentOrganizer.App/Pages/`, `ViewModels/`, `Resources/en-US/`, `Resources/ko-KR/`.
  - Verify: ViewModel tests, resource completeness, accessibility tree, and both locales.
- [ ] **T8 (P1, human: ~2d / CC: ~3h)** — QA — Complete the three-layer release gate.
  - Surfaced by: test review 7A.
  - Files: ignored local `tests/` projects and local Appium configuration.
  - Verify: all MSTest suites serial where required, real Vault/SQLite integration, and critical WinUI Appium journey.

## 22. Test Plan

```text
CODE PATHS                                      USER FLOWS
[+] App startup                                 [+] First real workflow
  +-- AppInstance primary/redirect                 +-- [E2E] Import -> Review -> Case -> Today
[+] Intake                                      [+] Error and recovery
  +-- picker/drop -> handle -> SHA                 +-- [E2E] duplicate focuses existing Inbox
  +-- VaultImport journal -> Vault -> commit       +-- [E2E] restart during processing
  +-- unsupported/oversized/corrupt                +-- [E2E] safe invalid-document feedback
[+] Extraction and labeling                    [+] Review safety
  +-- existing Worker format/security tests        +-- missing field/evidence blocks Case
  +-- shared invoice-rule regression tests          +-- stale revision is rejected
  +-- attempt-id outbox recovery                    +-- double submit creates one Case
[+] Case and Today                              [+] Locale and clock boundaries
  +-- atomic Case/Today commit                      +-- [E2E] en-US/ko-KR and fallback
  +-- query-time due status                         +-- [E2E] midnight/time-zone refresh
```

The local release gate runs MSTest unit suites, real temporary Vault/SQLite
integration, then Appium Windows UI E2E. Test source remains ignored; the merge
request records exact commands, environment, counts, and results.

## GSTACK REVIEW REPORT

| Run | Status | Findings |
|---|---|---|
| Scope Challenge | COMPLETE | Scope reduced: watched-folder execution deferred |
| Architecture Review | COMPLETE | 4 findings accepted and folded |
| Code Quality Review | COMPLETE | 2 findings accepted and folded |
| Test Review | COMPLETE | Coverage diagram produced; three-layer gate accepted |
| Performance Review | COMPLETE | 2 findings accepted and folded |
| Codex Outside Voice | COMPLETE | 3 findings accepted and folded; Claude not used |

VERDICT: CLEARED — all engineering decisions are resolved and incorporated.

NO UNRESOLVED DECISIONS
