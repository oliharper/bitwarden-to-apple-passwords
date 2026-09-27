-- name: GetRunState :one
SELECT state FROM runs WHERE id = 1;

-- name: ListSnapshots :many
SELECT source_type, observed_count, coverage FROM snapshots ORDER BY ref;

-- name: CountSourcePasswordFields :one
SELECT count(*) AS nonempty_source,
       CAST(coalesce(sum(CASE WHEN EXISTS (
         SELECT 1 FROM equality de
         JOIN fields df ON df.ref = de.field_ref
         JOIN records dr ON dr.ref = df.record_ref
         WHERE de.kind = 'password' AND de.label = se.label
           AND df.role = 'Password' AND dr.snapshot = 'apple'
       ) THEN 1 ELSE 0 END), 0) AS INTEGER) AS present_in_apple
FROM fields sf
JOIN records sr ON sr.ref = sf.record_ref
JOIN equality se ON se.field_ref = sf.ref AND se.kind = 'password'
WHERE sr.snapshot = 'bitwarden' AND sf.role = 'Password'
  AND sf.observed = 'nonempty';

-- name: CountNoteObservations :one
SELECT count(*) AS nonempty_source,
       CAST(coalesce(sum(CASE WHEN observation = 'exact_elsewhere' THEN 1 ELSE 0 END), 0) AS INTEGER) AS exact_elsewhere,
       CAST(coalesce(sum(CASE WHEN observation = 'whole_source_observation' THEN 1 ELSE 0 END), 0) AS INTEGER) AS whole_source_observation,
       CAST(coalesce(sum(CASE WHEN observation = 'partial_observation' THEN 1 ELSE 0 END), 0) AS INTEGER) AS partial_observation,
       CAST(coalesce(sum(CASE WHEN observation = 'no_observed_match' THEN 1 ELSE 0 END), 0) AS INTEGER) AS no_observed_match
FROM source_note_observations WHERE observed = 'nonempty';

-- name: CountSearchLimits :one
SELECT count(*) FROM search_limits;

-- name: CountDomainGroups :one
SELECT count(DISTINCT domain) FROM record_domains;

-- name: CountAnnotations :one
SELECT count(*) FROM annotations;

-- name: ListFieldCoverage :many
SELECT r.snapshot, f.classification, f.observed, count(*) AS count
FROM fields f JOIN records r ON r.ref = f.record_ref
GROUP BY r.snapshot, f.classification, f.observed
ORDER BY r.snapshot, f.classification, f.observed;

-- name: SearchRecords :many
SELECT ref, snapshot, position, kind, native_id_valid, native_id,
       title, username, domains, website_origins
FROM records
WHERE title LIKE sqlc.arg(pattern)
   OR username LIKE sqlc.arg(pattern)
   OR domains LIKE sqlc.arg(pattern)
ORDER BY snapshot, title, position;

-- name: ListFieldsForRecord :many
SELECT ref, record_ref, role, observed, classification, length,
       path_depth, value_type, element_count, group_ref, display_name
FROM fields WHERE record_ref = ? ORDER BY ref;

-- name: ListGroupEntries :many
SELECT d.domain, r.username, r.ref, r.snapshot, r.position, r.title,
       f.observed AS password_observed, e.label AS password_label
FROM record_domains d
JOIN records r ON r.ref = d.record_ref
LEFT JOIN fields f ON f.record_ref = r.ref AND f.role = 'Password'
LEFT JOIN equality e ON e.field_ref = f.ref AND e.kind = 'password'
WHERE (sqlc.arg(domain) = '' OR d.domain = sqlc.arg(domain))
  AND (sqlc.arg(username) = '' OR r.username = sqlc.arg(username))
ORDER BY d.domain, r.username, r.snapshot, r.position;

-- name: ListAbsentPasswords :many
SELECT r.ref, r.title, r.username, r.domains, e.label
FROM equality e
JOIN fields f ON f.ref = e.field_ref
JOIN records r ON r.ref = f.record_ref
WHERE e.kind = 'password' AND r.snapshot = 'bitwarden'
  AND NOT EXISTS (
    SELECT 1 FROM equality de
    JOIN fields df ON df.ref = de.field_ref
    JOIN records dr ON dr.ref = df.record_ref
    WHERE de.kind = 'password' AND de.label = e.label
      AND df.role = 'Password' AND dr.snapshot = 'apple'
  )
ORDER BY r.position;

-- name: ListNoteEvidence :many
SELECT record_ref, title, field_ref, observed, note_label, observation
FROM source_note_observations
ORDER BY position;

-- name: ListMatchesForField :many
SELECT m.id, m.source_field, m.destination_field, m.source_start, m.source_end,
       m.destination_start, m.destination_end, m.method,
       df.role AS destination_role, dr.ref AS destination_record,
       dr.snapshot AS destination_snapshot, dr.title AS destination_title
FROM content_matches m
JOIN fields df ON df.ref = m.destination_field
JOIN records dr ON dr.ref = df.record_ref
WHERE m.source_field = ?
ORDER BY m.id;

-- name: ListOccurrencesForField :many
SELECT o.field_ref, o.kind, o.label, o.ordinal,
       o.start, o.end, o.line, o.block, f.group_ref
FROM content_occurrences o
JOIN fields f ON f.ref = o.field_ref
WHERE o.field_ref = ?
ORDER BY o.kind, o.ordinal;

-- name: ListSearchLimits :many
SELECT l.field_ref, f.record_ref, l.cause,
       i.indexed_tokens, i.omitted_tokens
FROM search_limits l
JOIN fields f ON f.ref = l.field_ref
LEFT JOIN index_limits i ON i.field_ref = l.field_ref
                        AND l.cause = 'token_index_cap'
ORDER BY f.record_ref, l.field_ref, l.cause;

-- name: ListAnnotations :many
SELECT id, kind, source_ref, destination_ref, field_ref, provenance, created_at
FROM annotations ORDER BY id DESC;

-- name: InsertAnnotation :one
INSERT INTO annotations(kind, source_ref, destination_ref, field_ref, provenance, created_at)
VALUES (?, ?, ?, ?, 'user', ?) RETURNING id;
