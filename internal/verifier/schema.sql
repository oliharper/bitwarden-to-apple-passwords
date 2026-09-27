PRAGMA foreign_keys=on;

CREATE TABLE runs (
  id INTEGER primary key,
  created_at TEXT not null,
  tool_version TEXT not null,
  schema_version INTEGER not null,
  state TEXT not null
);

CREATE TABLE snapshots (
  ref TEXT primary key,
  source_type TEXT not null,
  observed_count INTEGER not null,
  coverage TEXT not null
);

CREATE TABLE records (
  ref TEXT primary key,
  snapshot TEXT not null,
  position INTEGER not null,
  kind TEXT not null,
  native_id_valid INTEGER not null,
  native_id TEXT,
  title TEXT not null,
  username TEXT not null,
  domains TEXT not null,
  website_origins TEXT not null
);

CREATE TABLE record_domains (
  record_ref TEXT not null references records(ref),
  domain TEXT not null,
  primary key (record_ref, domain)
);

CREATE INDEX record_domains_group ON record_domains (domain, record_ref);

CREATE TABLE fields (
  ref TEXT primary key,
  record_ref TEXT not null references records(ref),
  role TEXT not null,
  observed TEXT not null,
  classification TEXT not null,
  length INTEGER not null,
  path_depth INTEGER not null,
  value_type TEXT not null,
  element_count INTEGER not null,
  group_ref TEXT,
  display_name TEXT not null
);

CREATE INDEX fields_record_role ON fields (record_ref, role);

CREATE TABLE content_occurrences (
  field_ref TEXT not null references fields(ref),
  record_ref TEXT not null references records(ref),
  kind TEXT not null,
  label TEXT not null,
  ordinal INTEGER not null,
  start INTEGER not null,
  end INTEGER not null,
  line INTEGER not null,
  block INTEGER not null
);

CREATE INDEX occurrences_label ON content_occurrences (kind, label);
CREATE INDEX occurrences_order ON content_occurrences (field_ref, kind, ordinal);

CREATE TABLE index_limits (
  record_ref TEXT not null references records(ref),
  field_ref TEXT not null primary key references fields(ref),
  indexed_tokens INTEGER not null,
  omitted_tokens INTEGER not null
);

CREATE TABLE equality (
  label TEXT not null,
  field_ref TEXT not null references fields(ref),
  kind TEXT not null
);

CREATE INDEX equality_label ON equality (kind, label);

CREATE TABLE content_matches (
  id INTEGER primary key,
  source_field TEXT not null references fields(ref),
  destination_field TEXT not null references fields(ref),
  source_start INTEGER not null,
  source_end INTEGER not null,
  destination_start INTEGER not null,
  destination_end INTEGER not null,
  method TEXT not null
);

CREATE INDEX matches_source ON content_matches (source_field, id);

CREATE TABLE search_limits (
  field_ref TEXT not null references fields(ref),
  cause TEXT not null,
  primary key (field_ref, cause)
);

CREATE TABLE annotations (
  id INTEGER primary key,
  kind TEXT not null,
  source_ref TEXT references records(ref),
  destination_ref TEXT references records(ref),
  field_ref TEXT references fields(ref),
  provenance TEXT not null check (provenance = 'user'),
  created_at TEXT not null
);

CREATE VIEW source_note_observations AS
SELECT r.ref AS record_ref, r.title, r.position, f.ref AS field_ref,
       f.observed, e.label AS note_label,
       CASE
         WHEN f.observed != 'nonempty' THEN 'not_compared'
         WHEN EXISTS (
           SELECT 1 FROM content_occurrences source_occurrence
           JOIN content_occurrences destination_occurrence
             ON destination_occurrence.kind = 'whole'
            AND destination_occurrence.label = source_occurrence.label
           JOIN records destination_record
             ON destination_record.ref = destination_occurrence.record_ref
           WHERE source_occurrence.field_ref = f.ref
             AND source_occurrence.kind = 'whole'
             AND destination_record.snapshot IN ('apple', 'supplemental')
         ) THEN 'exact_elsewhere'
         WHEN EXISTS (
           SELECT 1 FROM content_matches match
           WHERE match.source_field = f.ref
             AND match.source_start = 0 AND match.source_end = f.length
         ) THEN 'whole_source_observation'
         WHEN EXISTS (
           SELECT 1 FROM content_matches match WHERE match.source_field = f.ref
         ) THEN 'partial_observation'
         ELSE 'no_observed_match'
       END AS observation
FROM fields f
JOIN records r ON r.ref = f.record_ref
LEFT JOIN equality e ON e.field_ref = f.ref AND e.kind = 'note'
WHERE r.snapshot = 'bitwarden' AND f.role = 'Notes';
