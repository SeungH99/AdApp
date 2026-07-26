# Empirical Corpus Workbench Design

Date: 2026-07-26  
Status: Approved for implementation planning  
Branch: `release-issue-7`  
Issue: [#8](https://github.com/SeungH99/AdApp/issues/8)

## 1. Purpose

Build a local-first corpus curation workbench that makes official-source research,
document ingestion, field labeling, evidence-coordinate review, delegated labeling,
owner approval, and partial-corpus validation reproducible and auditable.

The first pilot covers one invoice contract in two markets:

- `ko-KR`
- `en-US`

The target is up to 40 held-out public documents per market. The user directly
reviews a deterministic, stratified sample of 10 documents per market. Remaining
documents are labeled under delegated authority using official sources and receive
owner approval only through an explicit final batch approval.

This pilot does not weaken or satisfy the production `CorpusEval` gate. The
production gate continues to require the complete 36-cell, 1,440-held-out-document
owner-approved corpus and a sealed production Worker package.

## 2. Background

T6 implemented and verified:

- local PDF and OCR extraction adapters;
- capability-free AppContainer Worker execution;
- inherited source-handle and NTFS identity checks;
- a 15-second end-to-end hard deadline;
- package and physical-root closure;
- adapter benchmarking;
- a strict 36-cell `CorpusEval` gate.

Synthetic evaluation passes, but the empirical gate remains blocked because an
owner-approved real-document corpus and its published Worker attestation do not
exist. The repository currently has no reusable workflow for building that corpus
without leaking documents, labels, paths, or extracted text.

## 3. Goals

1. Track authoritative labeling rules without tracking corpus documents.
2. Import public documents into a content-addressed, local-only vault.
3. Preserve provenance, reuse status, stable identity, and source-family identity.
4. Generate draft invoice labels and evidence coordinates with the production
   document extraction Worker.
5. Let the user review values and evidence coordinates together.
6. Distinguish direct review from delegated labeling.
7. Require an explicit final batch approval before treating delegated labels as
   owner approved.
8. Produce a tamper-evident partial-pilot report that can later be merged into the
   complete production corpus.
9. Fail closed when provenance, reuse status, identity, labeling, approval, or
   Worker attestation is incomplete.

## 4. Non-goals

- Passing or weakening the 36-cell production empirical gate.
- Committing documents, labels, local paths, extracted text, or approval payloads.
- Building a customer-facing labeling feature in the desktop product.
- Automatically scraping sites that disallow retrieval or whose reuse status is
  unknown.
- Fabricating documents to meet a numerical target.
- Treating all 40 documents as directly reviewed when the user reviewed only 10.
- Supporting all six production contracts in this pilot.
- Supporting private user documents in the first run. The vault and importer must
  be compatible with private documents in later runs.

## 5. Pilot Contract

The pilot contract is `invoice-explicit-due-date-v1`, which will later map to one
production corpus contract cell without assigning final semantics to all six
existing opaque contract IDs.

Each eligible document must visibly contain evidence for:

- `issuer_name`
- `invoice_number`
- `issue_date`
- `payment_due_date`
- `total_amount`
- `currency`

`payment_due_date` must be explicitly printed in the document. Invoices that only
state relative terms such as “Net 30” are excluded from this first contract and
reserved for a later derived-deadline contract. This keeps every required field
grounded in a single visible evidence region compatible with the current
`CorpusEval` evidence model.

Normalized values use:

- Unicode NFC for text;
- ISO 8601 `YYYY-MM-DD` for dates;
- an ungrouped decimal string for amounts;
- ISO 4217 codes for currency.

## 6. Architecture

### 6.1 Official Rule Catalog

Tracked repository metadata defines:

- rule ID and version;
- market;
- contract;
- required field;
- normalization rule;
- official source URI;
- official publisher;
- source publication or revision date when available;
- retrieval verification date;
- provenance and reuse notes.

Only authoritative government, standards-body, regulator, or official program
sources may set a labeling rule. A commercial example may help discover documents
but cannot independently define ground truth.

### 6.2 Local Corpus Vault

The vault stores originals and private metadata outside tracked repository paths.
Documents are addressed by SHA-256, not their original filename.

Each local document record contains:

- stable document ID;
- content SHA-256;
- physical source locator;
- market and pilot contract;
- input kind and codec;
- source-family ID;
- public source receipt;
- provenance and reuse decision;
- local lifecycle state.

The vault root is protected using the same canonical-path, reparse-point, and
physical-identity principles used by T6. The importer must not follow an alias
outside the approved root.

### 6.3 Ingestion CLI

The CLI imports explicit user-selected files or an approved retrieval result. It:

1. validates the physical vault boundary;
2. streams and hashes the source;
3. classifies the real file type from magic bytes;
4. rejects unsupported or oversized input;
5. checks content and source-family duplicates;
6. writes the immutable original to the vault;
7. records a provenance receipt;
8. schedules draft extraction.

Ingestion is idempotent. Importing the same content again returns the existing
stable ID without creating a second corpus member.

### 6.4 Draft Labeler

The draft labeler calls the sealed production document extraction Worker. It
records:

- Worker package manifest identity;
- extraction protocol version;
- adapter and OCR runtime identities;
- draft field values;
- page and normalized evidence coordinates;
- rule IDs used for normalization;
- labeler identity and timestamp.

Draft output is never owner approved. A label change creates a new
`LabelRevision`; it does not overwrite prior revisions.

### 6.5 Local Review Screen

The review screen shows one document at a time:

- page preview with evidence boxes;
- raw extracted value and normalized value;
- required-field checklist;
- official labeling rule and source link;
- review progress and market;
- `Approve exact`, `Correct and approve`, `Reject document`, and `Defer`.

Approval verifies both the normalized value and its evidence location.

### 6.6 Approval Ledger

The append-only ledger records:

- decision ID;
- document hash;
- label revision hash;
- rule-set hash;
- Worker package identity;
- reviewer identity;
- approval mode;
- timestamp;
- previous ledger-entry hash.

Approval modes are:

- `direct-review`: the user inspected the document, values, and evidence;
- `delegated-label`: the label was produced under the approved official-source
  rules but was not individually inspected by the user;
- `batch-approval`: the user accepts the completed market batch after reviewing
  the deterministic sample and sanitized batch summary.

A delegated document is not owner approved until the applicable final
`batch-approval` exists. Changing the document, label revision, rule set, or
Worker package invalidates the derived approval state.

### 6.7 Pilot Validator and Report

The workbench owns a separate partial-pilot schema. It does not emit a production
`CorpusManifest` from two cells.

The pilot validator checks:

- exact market and contract scope;
- target and available document counts;
- unique content and source families;
- required field and evidence coverage;
- official source linkage;
- direct-review sampling coverage;
- approval-chain integrity;
- Worker package identity consistency;
- absence of tracked or reported private payloads.

The sanitized pilot report includes counts, aggregate error metrics, hashes,
approval coverage, rule versions, Worker identity, and explicit blocking reasons.
It excludes filenames, source paths, document text, field values, coordinates, and
personal identifiers.

## 7. Review Sampling

The user directly reviews 10 documents per market.

The selector is deterministic for a fixed corpus epoch and content set. It
stratifies by:

- 5 image PDFs and 5 standalone raster documents when both kinds are available;
- at least three source-layout families;
- date, amount, currency-symbol, and identifier edge cases;
- source and acquisition diversity.

If the available corpus cannot satisfy the strata, the tool reports the missing
coverage and blocks batch approval. It does not silently substitute an easier
sample.

## 8. Data Flow

1. A catalog entry establishes the official labeling rules.
2. A public document and its provenance receipt enter the local vault.
3. The ingestion CLI fixes content and source-family identity.
4. The sealed Worker produces a draft label revision.
5. Automated validation checks required values and evidence geometry.
6. The deterministic selector creates the direct-review queue.
7. The user directly reviews 10 documents per market.
8. Delegated labeling completes the remaining eligible documents.
9. The user sees a sanitized batch summary and explicitly approves or rejects it.
10. The pilot validator emits a sanitized partial report.
11. A future full-corpus assembly step imports the approved pilot records without
    changing the production `CorpusEval` requirements.

## 9. Failure Model

Failures use stable machine-readable codes and safe human-readable explanations.

| Code | Meaning | Result |
|---|---|---|
| `SourceUnverified` | Official provenance cannot be established | Document excluded |
| `ReuseStatusUnknown` | Retrieval or reuse status is unclear | Retrieval blocked |
| `VaultBoundaryViolation` | Canonical or physical path escapes the vault | Operation aborted |
| `ContentHashMismatch` | Stored bytes do not match the receipt | Document quarantined |
| `DuplicateContent` | Content already exists | Existing stable ID returned |
| `SourceFamilyLeakage` | Calibration or evaluation family isolation is violated | Pilot invalid |
| `UnsupportedInput` | Real type, codec, size, or page count is unsupported | Document rejected |
| `MissingRequiredField` | A required invoice field has no normalized value | Review blocked |
| `MissingEvidence` | A required value has no valid page coordinate | Review blocked |
| `StaleRuleSet` | Label references a superseded official rule version | Approval invalidated |
| `InsufficientDirectReview` | Ten valid stratified reviews are not present | Batch approval blocked |
| `ApprovalChainInvalid` | Hash-chain or approval binding fails | Pilot invalid |
| `WorkerAttestationMismatch` | Drafts were produced by a different package identity | Pilot invalid |
| `CoverageIncomplete` | The market has fewer than 40 eligible documents | Pilot remains blocked |

The system never converts an empirical pilot into a synthetic one after a failure.
Interrupted operations resume from an authenticated checkpoint. A changed input
invalidates dependent checkpoints and approvals.

## 10. Privacy and Repository Boundary

Tracked:

- workbench and review UI code;
- schemas;
- official rule catalog metadata;
- sanitized example fixtures containing no real document data;
- design and implementation documentation.

Never tracked:

- source documents;
- original filenames;
- absolute or relative vault locators;
- extracted text;
- normalized field values;
- evidence coordinates;
- label revisions;
- approval ledger payloads;
- checkpoints and empirical reports containing private payloads.

Before commit and before report publication, a privacy scan searches for document
sentinels, local paths, filenames, extracted values, credentials, environment
values, and direct identifiers. Any match blocks publication.

## 11. Testing

Test source remains local under ignored `tests/` paths, as required by repository
policy. Merge requests record commands and results without committing test source.

### Unit and Property Tests

- canonical serialization and hashing;
- label revision immutability;
- approval-chain verification;
- invalidation after document, label, rule, or Worker changes;
- deterministic stratified sampling;
- duplicate and source-family detection;
- normalization for dates, amounts, text, and currency;
- schema rejection of unknown or ambiguous members.

### Security Tests

- traversal, junction, symlink, and physical-root alias attempts;
- hash substitution and time-of-check/time-of-use changes;
- forged approval entries and reordered chains;
- stale checkpoints;
- untrusted source URLs and unsafe retrieval redirects;
- oversized files, decompression bombs, and malformed images/PDFs;
- privacy leakage in logs and sanitized reports.

### Integration Tests

- import through draft extraction with the sealed Worker package;
- Worker timeout and typed failure propagation;
- evidence coordinate display and corrected-label revision;
- direct review, delegated label, and batch approval lifecycle;
- restart and checkpoint resume;
- pilot report generation.

### End-to-End Pilot Verification

- both markets are represented;
- up to 40 eligible held-out documents per market are attempted;
- 10 deterministic direct reviews per market are completed;
- every eligible document has the six required fields and evidence;
- all provenance receipts reference official labeling rules;
- approval and Worker identities verify;
- sanitized report contains no private payload;
- incomplete lawful document supply remains explicitly blocked.

## 12. Completion Criteria

The release issue is implementation-complete when:

1. The workbench CLI, local review screen, schemas, and official rule catalog pass
   Release build and local tests.
2. Import, labeling, revision, review, approval, checkpoint, and report flows are
   exercised end to end.
3. Official public documents are sought for both markets and accepted only when
   provenance and reuse conditions are recorded.
4. The tool reports actual eligible counts without fabrication.
5. If 40 eligible documents per market are available, the user directly reviews
   10 per market and performs the final batch approvals.
6. If either market has fewer than 40 eligible documents, the pilot report states
   `CoverageIncomplete` and the production empirical gate remains blocked.
7. No real corpus content or private metadata is tracked by Git.

Implementation completion and empirical release completion are intentionally
different states. This release issue may complete its tooling while the
production empirical gate remains blocked.

## 13. Approved Decisions

- Two-market pilot: `ko-KR` and `en-US`.
- First workflow: invoice and receivable management.
- Pilot size: up to 40 held-out documents per market.
- Source mix target: official/public documents first; private user documents may
  be added in a later run.
- Originals remain unredacted and local; only sanitized aggregate evidence leaves
  the vault.
- User directly reviews 10 documents per market.
- Remaining documents are delegated labels and require explicit final batch
  approval.
- Implementation approach: manifest-first CLI with a local review screen.
- Existing production `CorpusEval` coverage and release gates remain unchanged.
