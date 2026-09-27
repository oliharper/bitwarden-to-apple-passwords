package verifier

import (
	"context"
	"database/sql"
	"strings"

	sqlstore "github.com/oliharper/bitwarden-to-apple-passwords/internal/verifier/db"
)

func nullable(value sql.NullString) any {
	if value.Valid {
		return value.String
	}

	return nil
}

func nullableInt(value sql.NullInt64) any {
	if value.Valid {
		return value.Int64
	}

	return nil
}

func (ledger *Ledger) Summary() (map[string]any, error) {
	ctx := context.Background()
	state, err := ledger.Q.GetRunState(ctx)
	if err != nil {
		return nil, errInput
	}
	if state == "active" {
		return map[string]any{"run_state": state}, nil
	}

	snapshots, err := ledger.Q.ListSnapshots(ctx)
	if err != nil {
		return nil, errInput
	}
	snapshotRows := make([]map[string]any, 0, len(snapshots))
	for _, snapshot := range snapshots {
		snapshotRows = append(snapshotRows, map[string]any{
			"source_type": snapshot.SourceType, "observed_count": snapshot.ObservedCount,
			"coverage": snapshot.Coverage,
		})
	}

	passwords, err := ledger.Q.CountSourcePasswordFields(ctx)
	if err != nil {
		return nil, errInput
	}

	notes, err := ledger.Q.CountNoteObservations(ctx)
	if err != nil {
		return nil, errInput
	}

	domains, err := ledger.Q.CountDomainGroups(ctx)
	if err != nil {
		return nil, errInput
	}

	limits, err := ledger.Q.CountSearchLimits(ctx)
	if err != nil {
		return nil, errInput
	}

	annotations, err := ledger.Q.CountAnnotations(ctx)
	if err != nil {
		return nil, errInput
	}

	coverage, err := ledger.Coverage()
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"run_state": state, "snapshots": snapshotRows, "base_domains": domains,
		"source_passwords": map[string]int64{
			"nonempty":                  passwords.NonemptySource,
			"present_anywhere_in_apple": passwords.PresentInApple,
			"absent_anywhere_in_apple":  passwords.NonemptySource - passwords.PresentInApple,
		},
		"source_notes": map[string]int64{
			"nonempty": notes.NonemptySource, "exact_elsewhere": notes.ExactElsewhere,
			"whole_source_observation": notes.WholeSourceObservation,
			"partial_observation":      notes.PartialObservation,
			"no_observed_match":        notes.NoObservedMatch,
		},
		"coverage": coverage, "search_limits": limits, "user_annotations": annotations,
	}, nil
}

func (ledger *Ledger) Records(query string) ([]map[string]any, error) {
	rows, err := ledger.Q.SearchRecords(context.Background(), "%"+strings.TrimSpace(query)+"%")
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"ref": row.Ref, "snapshot": row.Snapshot, "position": row.Position,
			"kind": row.Kind, "native_id_valid": row.NativeIDValid != 0,
			"native_id": nullable(row.NativeID), "title": row.Title,
			"username": row.Username, "domains": row.Domains,
			"website_origins": row.WebsiteOrigins,
		})
	}

	return out, nil
}

func (ledger *Ledger) Fields(ref string) ([]map[string]any, error) {
	rows, err := ledger.Q.ListFieldsForRecord(context.Background(), ref)
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"ref": row.Ref, "record_ref": row.RecordRef, "role": row.Role,
			"observed": row.Observed, "classification": row.Classification,
			"length": row.Length, "path_depth": row.PathDepth,
			"value_type": row.ValueType, "element_count": row.ElementCount,
			"group_ref": nullable(row.GroupRef), "display_name": row.DisplayName,
		})
	}

	return out, nil
}

func (ledger *Ledger) Groups(domain, username string) ([]map[string]any, error) {
	rows, err := ledger.Q.ListGroupEntries(context.Background(), sqlstore.ListGroupEntriesParams{
		Domain: domain, Username: username,
	})
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"base_domain": row.Domain, "username": row.Username,
			"ref": row.Ref, "snapshot": row.Snapshot, "position": row.Position,
			"title": row.Title, "password_observed": nullable(row.PasswordObserved),
			"password_label": nullable(row.PasswordLabel),
		})
	}

	return out, nil
}

func (ledger *Ledger) AbsentPasswords() ([]map[string]any, error) {
	rows, err := ledger.Q.ListAbsentPasswords(context.Background())
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"ref": row.Ref, "title": row.Title, "username": row.Username,
			"domains": row.Domains, "password_label": row.Label,
		})
	}

	return out, nil
}

func (ledger *Ledger) Notes() ([]map[string]any, error) {
	rows, err := ledger.Q.ListNoteEvidence(context.Background())
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"record_ref": row.RecordRef, "title": row.Title, "field_ref": row.FieldRef,
			"observed": row.Observed, "note_label": nullable(row.NoteLabel),
			"observation": row.Observation,
		})
	}

	return out, nil
}

func (ledger *Ledger) Matches(fieldRef string) ([]map[string]any, error) {
	rows, err := ledger.Q.ListMatchesForField(context.Background(), fieldRef)
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id": row.ID, "source_field": row.SourceField,
			"destination_field": row.DestinationField,
			"source_start":      row.SourceStart, "source_end": row.SourceEnd,
			"destination_start": row.DestinationStart,
			"destination_end":   row.DestinationEnd, "method": row.Method,
			"destination_role":     row.DestinationRole,
			"destination_record":   row.DestinationRecord,
			"destination_snapshot": row.DestinationSnapshot,
			"destination_title":    row.DestinationTitle,
		})
	}

	return out, nil
}

func (ledger *Ledger) Occurrences(fieldRef string) ([]map[string]any, error) {
	rows, err := ledger.Q.ListOccurrencesForField(context.Background(), fieldRef)
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"field_ref": row.FieldRef, "kind": row.Kind, "label": row.Label,
			"ordinal": row.Ordinal, "start": row.Start, "end": row.End,
			"line": row.Line, "block": row.Block, "group_ref": nullable(row.GroupRef),
		})
	}

	return out, nil
}

func (ledger *Ledger) Coverage() ([]map[string]any, error) {
	rows, err := ledger.Q.ListFieldCoverage(context.Background())
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"snapshot": row.Snapshot, "classification": row.Classification,
			"observed": row.Observed, "count": row.Count,
		})
	}

	return out, nil
}

func (ledger *Ledger) Limits() ([]map[string]any, error) {
	rows, err := ledger.Q.ListSearchLimits(context.Background())
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"field_ref": row.FieldRef, "record_ref": row.RecordRef, "cause": row.Cause,
			"indexed_tokens": nullableInt(row.IndexedTokens),
			"omitted_tokens": nullableInt(row.OmittedTokens),
		})
	}

	return out, nil
}

func (ledger *Ledger) Annotations() ([]map[string]any, error) {
	rows, err := ledger.Q.ListAnnotations(context.Background())
	if err != nil {
		return nil, errInput
	}

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id": row.ID, "kind": row.Kind, "source_ref": nullable(row.SourceRef),
			"destination_ref": nullable(row.DestinationRef), "field_ref": nullable(row.FieldRef),
			"provenance": row.Provenance, "created_at": row.CreatedAt,
		})
	}

	return out, nil
}
