-- name: GetSchemaVersion :one
SELECT schema_version FROM runs WHERE id = 1;

-- name: CreateRun :exec
INSERT INTO runs(created_at, tool_version, schema_version, state)
VALUES (?, ?, ?, 'active');

-- name: ClaimComparison :execrows
UPDATE runs SET state = 'compared' WHERE id = 1 AND state = 'active';

-- name: FinalizeRun :execrows
UPDATE runs SET state = 'finalized' WHERE id = 1 AND state = 'compared';

-- name: InsertSnapshot :exec
INSERT INTO snapshots(ref, source_type, observed_count, coverage)
VALUES (?, ?, ?, ?);

-- name: InsertRecord :exec
INSERT INTO records(
  ref, snapshot, position, kind,
  native_id_valid, native_id,
  title, username, domains, website_origins
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertRecordDomain :exec
INSERT INTO record_domains(record_ref, domain) VALUES (?, ?);

-- name: InsertField :exec
INSERT INTO fields(
  ref, record_ref, role, observed, classification,
  length, path_depth, value_type, element_count,
  group_ref, display_name
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertOccurrence :exec
INSERT INTO content_occurrences(
  field_ref, record_ref, kind, label, ordinal,
  start, end, line, block
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertIndexLimit :exec
INSERT INTO index_limits(record_ref, field_ref, indexed_tokens, omitted_tokens)
VALUES (?, ?, ?, ?);

-- name: InsertEquality :exec
INSERT INTO equality(label, field_ref, kind) VALUES (?, ?, ?);

-- name: InsertContentMatch :exec
INSERT INTO content_matches(
  source_field, destination_field,
  source_start, source_end, destination_start, destination_end, method
)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: InsertSearchLimit :exec
INSERT OR IGNORE INTO search_limits(field_ref, cause) VALUES (?, ?);
