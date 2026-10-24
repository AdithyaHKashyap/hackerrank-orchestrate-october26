# Repository Analysis: Ghost Data Still Exists

**Scope:** Read-only analysis of participant-provided repository materials for the October 2026 HackerRank challenge. No prediction file was generated, no dataset file was changed, and no application code was implemented. Organizer-only truth and hidden answers were not accessed.

## 1. Challenge Requirements and Output Contract

The agent must assess every request in `dataset/deletion_requests.csv`, first deciding whether the request text authorizes deletion. For authorized requests, it must resolve current and historical identity, establish the state at that case's `audit_at`, apply `deletion_rules.csv`, and report any remaining records or processes that can recreate data. Workflow statuses and activity results are claims, not proof.

A case is:

- `NOT_APPLICABLE` when deletion was not requested; its steps array must be `[]`.
- `COMPLETE` only when all relevant data has the policy-required treatment, retained records remain available, and no active sync/import/restore path can recreate prohibited data. Include only evidence-backed verification steps.
- `INCOMPLETE` when a supported policy violation or recreation risk remains. Include findings, an ordered remediation plan, and post-remediation verification steps.

The required submission file is the repository-root `output.csv`, with exactly this header and column order:

```text
case_id,deletion_status,steps_json
```

It must have exactly 518 data rows, one per input case, sorted by `case_id`. `steps_json` must be a valid JSON array. Every step has exactly:

```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_01"
}
```

Step numbers are consecutive from 1. Phases are ordered `FINDING`, `REMEDIATION`, `VERIFICATION`. The allowed operation/state pairs are:

| Phase | Operations and states |
| --- | --- |
| FINDING | `REPORT_REMAINING_RECORD` / `PRESENT`; `REPORT_EXPOSED_PII` / `PRESENT`; `REPORT_ACTIVE_DATA_FLOW` / `ACTIVE`; `REPORT_RESTORE_RISK` / `ACTIVE` |
| REMEDIATION | `DISABLE_DATA_FLOW` / `DISABLED`; `BLOCK_RESTORE` / `BLOCKED`; `DELETE_RECORD` / `ABSENT`; `REDACT_RECORD` / `REDACTED`; `ANONYMIZE_RECORD` / `ANONYMIZED` |
| VERIFICATION | `VERIFY_RECORD_ABSENT` / `ABSENT`; `VERIFY_RECORD_PRESENT` / `PRESENT`; `VERIFY_RECORD_REDACTED` / `REDACTED`; `VERIFY_RECORD_ANONYMIZED` / `ANONYMIZED`; `VERIFY_DATA_FLOW_DISABLED` / `DISABLED`; `VERIFY_RESTORE_BLOCKED` / `BLOCKED` |

Finding evidence must cite a participant-visible `file_id`, `activity_id`, or `audit_id`. `COMPLETE` verification must cite evidence that proves the state at `audit_at`. Proposed remediation and future verification in an `INCOMPLETE` case use an empty `evidence_id`. Never use evidence captured after the case cutoff.

The requirements call for disabling data flows and blocking unsafe restores before dependent record changes, and for processing downstream copies before source records when required. The problem statement also prescribes phase/operation ordering and then ascending `system_id`/`resource_id`. The implementation should preserve the explicit ordering rules while making any dependency-driven ordering deterministic; the exact tie-break when a dependency conflicts with lexical resource ordering is not further clarified.

## 2. Input Schemas and Relationships

All CSV files in `dataset/` were read as CSV files. Counts below are from the participant-facing dataset.

| File | Rows | Schema / observed role |
| --- | ---: | --- |
| `deletion_requests.csv` | 518 | `case_id,email,requested_at,reported_status,reported_at,audit_at,request_text`. The 518 rows have unique case IDs. Claimed statuses: 254 `COMPLETE`, 152 `PARTIALLY_COMPLETE`, 112 `NOT_STARTED`. Request times span 2026-01-05 through 2026-09-24 UTC; audit cutoffs span 2026-01-29 through 2026-10-01 UTC. |
| `sample_deletion_requests.csv` | 32 | Same seven columns as the full request file. |
| `sample_output.csv` | 32 | `case_id,deletion_status,steps_json`; 10 `COMPLETE`, 22 `INCOMPLETE`. No `NOT_APPLICABLE` example is present. Its 193 example steps use the seven required step fields, consecutive numbering, and the allowed operation/state vocabulary. |
| `user_identities.csv` | 850 | `user_id,name,email,phone,email_hash,updated_at`. Both `user_id` and current email are unique in this snapshot. Snapshot timestamps span 2023-06-22 through 2026-08-30 UTC. |
| `user_audit_log.csv` | 306 | `audit_id,user_id,event_time,field_name,old_value,new_value`. `audit_id` is unique. Changed fields are phone (92 rows), email (107), and email hash (107); event times span 2024-12-14 through 2026-06-03 UTC. |
| `system_activity.csv` | 4,011 | `activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details`. Activity IDs are unique; event times span 2026-01-04 through 2026-10-01 UTC. It covers 11 source and 19 target systems, with 17 event types. Largest groups include DELETE_RECORD (890), UPDATE_RECORD (672), SYNC_RECORD (447), INDEX_RECORD (400), SEND_EMAIL (368), and REFRESH_CACHE (284); it also includes export, retention, anonymization/redaction, data-flow checks/disablement, restore checks/blocking, and one RESTORE_BACKUP event. |
| `deletion_rules.csv` | 15 | `rule_id,data_category,condition,required_action`; one row per category. Actions are DELETE (7), REDACT (3), ANONYMIZE (2), and RETAIN (3). |
| `evidence_files.csv` | 94 | `file_id,file_path,origin,captured_at`. File IDs are unique. It maps evidence IDs to paths, origin labels, and capture times; it does not establish subject or case membership. Capture timestamps span 2026-01-29 through 2026-10-01 UTC. |
| `dataset/output.csv` | 0 | The provided file is empty/headerless, despite being described as a blank template. The required output schema must therefore come from the written contract. |

### Identity and time relationships

- `user_audit_log.user_id` links historical field transitions to `user_identities.user_id`. For email recovery, consider both `old_value` and `new_value` on rows whose `field_name` is `email`; the same pattern applies to historical phone and email-hash values.
- Matching request emails case-insensitively against the current email snapshot and historical email transitions links all 518 request rows: 418 rows match a current email, 101 match an audit email, with one row in both sets (417 current-only, 100 historical-only, one overlap). There are 517 distinct request emails. The overlap resolves to the same user; no request email was unmatched in these exact joins.
- After resolving a request to a user, collect current and prior identifiers for evidence matching, but retain the identifier's provenance and effective time. Do not merge unrelated people based only on a common value in a free-text field.
- All request `audit_at` values are after `requested_at`. Nonetheless, `system_activity`, audit events, snapshot content, and evidence captures have their own timelines. Filter every candidate fact against the specific case cutoff, including timestamps embedded in files; a filename date or a later capture cannot substitute for the internal event time.
- `reported_status`, `reported_at`, and `system_activity.reported_result` are operational claims. They do not establish the actual final state.

### Policy matrix

The supplied rules make treatment conditional for several categories; the condition must be evidenced rather than assumed.

| Category | Condition | Required action |
| --- | --- | --- |
| USER_PROFILE | Always | DELETE |
| SECONDARY_IDENTIFIER | Always | DELETE |
| SEARCH_INDEX_ENTRY | Always | DELETE |
| CACHE_ENTRY | Always | DELETE |
| SUPPORT_MESSAGE | Conversation contains shared customer, agent, or order context that must be retained | REDACT |
| SUPPORT_ATTACHMENT | Attachment belongs only to the deletion subject | DELETE |
| ANALYTICS_PROFILE | Record is still attributable to a user | ANONYMIZE |
| PRODUCT_TELEMETRY | Record is still attributable to a user | ANONYMIZE |
| USER_EXPORT | Always | DELETE |
| MARKETING_PROFILE | Always | DELETE |
| EMAIL_DELIVERY_LOG | Log contains a user email address | REDACT |
| SECURITY_AUDIT_LOG | Record is within the supplied retention period | RETAIN |
| LEGAL_HOLD_RECORD | A supplied legal hold is active | RETAIN |
| BACKUP_ARCHIVE | Restore access can be blocked | RETAIN |
| ACCOUNT_TOMBSTONE | Deleted account; only a stable internal `user_id` is needed to preserve retained-record references | REDACT |

For an account tombstone, retain the stable `user_id` reference but remove direct identifiers (including name, email, phone, email hash, and other fields required by the applicable redaction rule). Retention is not a blanket exemption from redaction.

## 3. Evidence Inventory and Processing Requirements

`dataset/evidence/` contains 94 files. Inventory by format:

| Directory / format | Count | Evidence files |
| --- | ---: | --- |
| `databases/` — SQL | 24 | `customer_accounts_failover_replica_20260902.sql`; `customer_data_failover_replica_20260920.sql`; `customer_data_inventory_20260213.sql`; `customer_data_inventory_20260310.sql`; `customer_data_inventory_20260404.sql`; `customer_data_inventory_20260504.sql`; `customer_data_inventory_20260524.sql`; `customer_data_inventory_20260618.sql`; `customer_data_inventory_20260703.sql`; `customer_data_inventory_20260723.sql`; `customer_data_inventory_20260817.sql`; `customer_data_inventory_20260905.sql`; `customer_data_inventory_20260916.sql`; `customer_data_read_replica_20260613.sql`; `customer_data_read_replica_20260708.sql`; `customer_data_read_replica_20260802.sql`; `customer_data_read_replica_20260827.sql`; `customer_data_read_replica_20260921.sql`; `customer_data_regional_replicas_20260330.sql`; `customer_data_regional_replicas_20260424.sql`; `customer_data_regional_replicas_20260519.sql`; `customer_data_reporting_replica_20260208.sql`; `customer_data_reporting_replica_20260305.sql`; `customer_search_primary_20260910.sql`. |
| `logs/` — log text | 26 | `application_trace_ap_northeast_20260730.log`; `application_trace_eu_north_20260302.log`; `cloud_runtime_export_af_south_20260930.log`; `cloud_runtime_export_us_west_20260608.log`; `notification_delivery_20260315.log`; `operations_stream_eu_central_20260705.log`; `operations_stream_me_central_20260203.log`; `resource_lookup_trace_20260218_083911.log`; `resource_lookup_trace_20260310_061801.log`; `resource_lookup_trace_20260414_054007.log`; `resource_lookup_trace_20260509_104353.log`; `resource_lookup_trace_20260529_074313.log`; `resource_lookup_trace_20260623_053726.log`; `resource_lookup_trace_20260713_093359.log`; `resource_lookup_trace_20260728_054417.log`; `resource_lookup_trace_20260822_103910.log`; `resource_lookup_trace_20260911_074253.log`; `resource_lookup_trace_20260926_103856.log`; `search_index_diagnostic_20260906.log`; `service_events_ap_south_20260915.log`; `service_events_sa_east_20260516.log`; `structured_service_events_ca_central_20260419.log`; `structured_service_events_eu_west_20260918.log`; `support_replica.log`; `syslog_archive_ap_southeast_20260325.log`; `syslog_archive_us_east_20260824.log`. |
| `records/` — JSON and text | 29 (28 JSON, 1 TXT) | `connector_configurations_20260812.json`; `customer_account_handover_20261001.txt`; `customer_analytics_report_20260907.json`; `customer_data_snapshot_bundle_20260131.json`; `customer_data_snapshot_bundle_20260223.json`; `customer_data_snapshot_bundle_20260322.json`; `customer_data_snapshot_bundle_20260416.json`; `customer_data_snapshot_bundle_20260511.json`; `customer_data_snapshot_bundle_20260605.json`; `customer_data_snapshot_bundle_20260630.json`; `customer_data_snapshot_bundle_20260725.json`; `customer_data_snapshot_bundle_20260819.json`; `customer_data_snapshot_bundle_20260913.json`; `customer_data_snapshot_bundle_20260915.json`; `customer_data_snapshot_bundle_20260917.json`; `customer_export_jobs_20260914.json`; `customer_export_manifest_20260409.json`; `security_audit_ledger_20261001.json`; `service_resource_export_20260129_114459.json`; `service_resource_export_20260228_103637.json`; `service_resource_export_20260320_072349.json`; `service_resource_export_20260429_083222.json`; `service_resource_export_20260514_114454.json`; `service_resource_export_20260603_083457.json`; `service_resource_export_20260628_062556.json`; `service_resource_export_20260718_104335.json`; `service_resource_export_20260807_074104.json`; `service_resource_export_20260901_053316.json`; `service_resource_export_20260915_114455.json`. |
| `documents/` — PDF | 4 | `account_history_report_20260718.pdf`; `delivery_correction_attachment.pdf`; `legal_retention_register_20260529.pdf`; `security_retention_extract.pdf`. |
| `images/` — PNG | 11 | `account_admin_console_20260926.png`; `analytics_profile_view_20260713.png`; `backup_restore_console_20260429.png`; `connector_management_console_20260807.png`; `customer_export_console_20260618.png`; `deleted_account_reference_20260310.png`; `marketing_profile_console.png`; `object_storage_browser_20260213.png`; `search_index_inspector_20260901.png`; `security_audit_explorer_20260905.png`; `support_ticket_console_20260524.png`. |

### Evidence interpretation and ingestion needs

- Use `evidence_files.csv` to resolve a cited `file_id` to a file and capture time. The manifest is not a case-to-evidence index; connect a record to a case through identifiers, stable user references, resource/system IDs, timestamps, and corroborating content.
- SQL files include recurring inventory snapshots and primary, read, regional, reporting, failover, and search captures. The inventory snapshots expose category tables such as profiles, search documents, analytics profiles, support records, exports, connector subscriptions, backup/restore entries, and security audit records. Replica exports also use resource/origin/collection/record/timestamp fields. Compare the same resource across relevant snapshots and replica regions; a primary deletion does not establish replica deletion.
- JSON includes dated snapshot bundles, service-resource exports, connector configuration, exports, analytics, and security-ledger artifacts. Parse nested records into normalized facts while retaining the original path, `file_id`, internal timestamp, and record locator.
- Logs contain service events, lookup traces, operations streams, application traces, delivery events, and search-index diagnostics. Parse structured fields where present and preserve line/event locators for traceability. Treat result/status text as a claim until corroborated by state evidence.
- PDFs and screenshots may hold facts not represented in CSVs or structured exports. They need searchable PDF text extraction and image OCR/vision, with extracted identifiers and dates checked against the visible artifact. In the inspected runtime, no PDF extraction library or OCR executable was available (`pypdf`, `pdfplumber`, `fitz`, `pytesseract`, `pdftotext`, and `tesseract` were absent); Pillow was present but is not a complete OCR solution. These are environment observations, not project dependencies.
- Both manifest `captured_at` and content-level event/snapshot times matter. Exclude evidence captured after `audit_at` and facts that occurred after `audit_at`. For absence claims, require coverage of relevant stores and replicas at the cutoff rather than treating a single empty source as proof of global deletion.
- Findings and complete-case verification need evidence references that point to actual participant evidence. Maintain a provenance trail from each extracted fact to its exact file/activity/audit identifier; never synthesize citations.

## 4. Existing Code, Dependencies, and Reusable Work

- `code/main.py` exists but is empty (0 bytes). `code/evaluation/main.py` also exists but is empty (0 bytes). No implementation, test suite, or shared parser/helper was found under `code/`.
- No dependency manifest was found in the repository root or under `code/`. The documented starter command is `python3 code/main.py`; Python's standard library provides CSV/JSON parsing, datetime handling, and SQLite support. PDF/OCR and image interpretation dependencies are not declared and must be selected and documented if used.
- The current environment had Pillow and pandas installed, but neither is declared by the project. Do not rely on undeclared workstation packages for a clean run.
- `README.md` documents the challenge, output requirements, run command, packaging, and says evaluation reports belong under `code/evaluation/`. `problem_statement.md` supplies the participant-facing rules, schema, and scoring requirements. `AGENTS.md` adds the project contract and transcript-logging requirements. `CLAUDE.md` points back to `AGENTS.md`; `agent_trace_instructions.md` covers packaging a separate trace ZIP.
- There is no repository-root `output.csv`. `dataset/output.csv` is empty rather than a populated header template.
- Path inconsistency to resolve before packaging: `AGENTS.md` §6.8 names `evaluation/evaluation_report.md` and `evaluation/usage_report.md`, while `README.md` explicitly locates them at `code/evaluation/`, and the starter directory is `code/evaluation/`. The user's requested analysis location is also `code/evaluation/`. Confirm the expected archive layout before final packaging; do not silently split or omit reports.

## 5. Major Accuracy Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Non-deletion intent confused with deletion, especially in varied-language requests | Classify request intent before auditing state. Use explicit positive/negative examples and an abstention/review path for ambiguous wording; never infer intent from `reported_status`. |
| Historical email, phone, or hash omitted or assigned to the wrong person | Resolve by `user_id` through ordered audit transitions, retain old/new values and effective times, and track provenance for every alias. Use normalized comparisons consistently without collapsing different users. |
| Current/historical identifiers or evidence from after `audit_at` leak into an earlier case | Apply a strict per-case cutoff to request, audit, activity, snapshot, file-capture, and content-level timestamps before matching or deciding state. |
| Decoy activity or operation results treated as proof | Use activity as a candidate lead, then require corroborating record state in evidence. Preserve source and target systems, resource ID, and result claim separately. |
| Primary store is clear while replicas, logs, attachments, search, exports, or archives still contain data | Search globally across all evidence categories and compare snapshot/replica state for each matched identifier and resource. |
| Sync/import/restore recreates already-deleted data | Model active flows and restore paths as findings in their own right. Disable/block them before dependent cleanup; verify both process state and affected records. |
| Incorrect policy treatment of retained, shared, or tombstone records | Evaluate the supplied condition per record. Retain required security/legal/backup records, redact shared messages and qualifying delivery logs, anonymize attributable analytics/telemetry, and preserve only stable `user_id` on tombstones. |
| Evidence overclaim, missing citations, or fabricated system/resource IDs | Normalize facts with exact evidence provenance and source locators. Emit steps only for grounded facts; proposed remediation/verification uses blank evidence as required. |
| Output accepted syntactically but wrong in step ordering or coverage | Validate exact header/row count/sort order, JSON array shape and exact keys, consecutive numbering, allowed operation-state pairs, evidence rules, phase/operation ordering, and remediation/verification coverage. |
| Thin sample coverage and no non-deletion example | The 32 sample outputs contain only 10 complete and 22 incomplete cases. Add participant-created cases for non-deletion, historical identity, temporal cutoff, tombstone redaction, replica drift, active sync, restore, and conditional retention; do not use hidden answers. |
| Incomplete multimodal support or environment-dependent execution | Declare and pin any OCR/PDF dependencies, provide a clean-run path, and validate extracted facts against the source. If modality extraction is unavailable, surface that coverage limitation rather than returning success-shaped output. |

## 6. Recommended Architecture and Implementation Phases

Use deterministic code for parsing, identity resolution, policy evaluation, temporal filtering, ordering, and serialization. If a model is used for language or unstructured evidence interpretation, constrain it to extract candidate facts with citations; validate those facts in code and do not allow it to invent evidence or override policy.

1. **Phase 1 — Contract and repository baseline (this analysis).** Freeze schemas, allowed values, temporal rules, evidence requirements, output validation, and packaging path. Maintain a participant-data-only boundary.
2. **Phase 2 — Deterministic ingestion and normalized fact model.** Implement CSV readers and schema checks; parse rules and timestamps; create a `Fact` representation with subject identifiers, category, system/resource, state/condition, effective/capture times, provenance (`file_id`/`activity_id`/`audit_id`), and source locator. Implement case cutoff filtering and identity history reconstruction first. Add unit tests for exact current/historical email resolution and timestamp boundaries.
3. **Phase 3 — Evidence adapters and state reconciliation.** Ingest JSON and SQL snapshots, compare primary and replica records by resource and collection, and parse logs with line-level provenance. Add PDF text/OCR and image OCR/vision adapters with dependency/setup documentation and field-level confidence/review behavior. Join facts to subjects only with grounded identifiers/resource links.
4. **Phase 4 — Policy audit and remediation planning.** Classify request authorization; apply each category/condition; distinguish deleted, present, redacted, anonymized, retained, active-flow, and restore-risk states. Build deterministic findings and a dependency-aware remediation plan, disabling flows/blocking restores before dependent cleanup and covering all changed resources in verification.
5. **Phase 5 — Output, evaluation, and clean-run validation.** Serialize exactly one sorted row per request, validate all JSON and allowed fields, and compare sample cases with `sample_output.csv`. Add at least three participant-created cases, report case/step/field/sequence metrics and failures, produce token/cost reporting if models are used, and test packaging without `dataset/`, caches, or credentials.

The first implementation priority should be the Phase 2 identity/time/provenance core. It prevents false joins and cutoff leakage before broad evidence extraction is layered on. The next efficiency improvement is to index normalized evidence once by identifier, resource, system, and timestamp rather than rescanning all 94 artifacts independently for each of 518 cases.

## 7. Unresolved Questions and Limitations

- The sample output does not demonstrate `NOT_APPLICABLE`; multilingual non-deletion intent has no visible gold example. The implementation needs separately designed tests and a documented ambiguity strategy.
- Some rule conditions can be underdetermined by a single record: whether a support attachment belongs only to the subject, whether a legal hold is active, whether a security record is within retention, whether analytics remains attributable, and whether restore access can be blocked. Identify which supplied evidence proves each condition; do not assume the condition from a category name.
- The operation ordering rule and dependency ordering can conflict in edge cases. Define a stable precedence policy and test it against the written phase/operation order and required safe dependency ordering; seek challenge-owner clarification if both cannot be satisfied for a case.
- Evidence manifests do not directly map evidence to users/cases, so matching precision and evidence coverage must be evaluated from contents. A lack of a matching row in an incomplete snapshot is not proof of absence.
- PDF/OCR/vision extraction has not been performed as part of this repository analysis. The report inventories those files and records the current runtime's missing extraction tools; Phase 3 must inspect their contents before any full audit can be considered complete.
- Hidden canonical answers were intentionally not accessed. Beyond the 32 public sample answers, expected scoring and exact canonical step choices cannot be measured from this analysis.
- The repository instructions disagree on whether evaluation reports are at `evaluation/` or `code/evaluation/`; resolve the archive path before packaging.
- No application implementation, dependency installation, test execution, predictions, or output generation was performed because this deliverable is repository analysis only.
