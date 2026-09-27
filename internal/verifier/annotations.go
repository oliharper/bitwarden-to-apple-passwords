package verifier

import (
	"context"
	"database/sql"
	"os"

	sqlstore "github.com/oliharper/bitwarden-to-apple-passwords/internal/verifier/db"
)

type Annotation struct {
	Kind, SourceRef, DestinationRef, FieldRef string
}

var annotationKinds = map[string]bool{
	"reviewed": true, "needs_followup": true, "related_entry": true,
	"split": true, "merge": true, "intentional_difference": true,
}

func (annotation Annotation) valid() bool {
	if !annotationKinds[annotation.Kind] ||
		(annotation.SourceRef == "" && annotation.DestinationRef == "" && annotation.FieldRef == "") {
		return false
	}
	if annotation.Kind == "related_entry" || annotation.Kind == "split" || annotation.Kind == "merge" {
		return annotation.SourceRef != "" && annotation.DestinationRef != ""
	}
	return true
}

func ReadAnnotation(path string) (Annotation, error) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() < 2 || st.Size() > 16384 {
		return Annotation{}, errInput
	}

	value, err := readJSON(path)
	if err != nil || value.kind != "object" {
		return Annotation{}, errInput
	}

	allowed := map[string]bool{
		"kind": true, "source_ref": true, "destination_ref": true, "field_ref": true,
	}
	data := map[string]string{}
	for _, member := range value.obj {
		if !allowed[member.key] || member.val.kind != "text" {
			return Annotation{}, errInput
		}
		data[member.key] = member.val.str
	}

	annotation := Annotation{data["kind"], data["source_ref"], data["destination_ref"], data["field_ref"]}
	if !annotation.valid() {
		return Annotation{}, errInput
	}

	return annotation, nil
}

func optionalRef(ref string) sql.NullString {
	return sql.NullString{String: ref, Valid: ref != ""}
}

func (ledger *Ledger) ApplyAnnotation(annotation Annotation) (map[string]any, error) {
	if !annotation.valid() {
		return nil, errInput
	}

	ctx := context.Background()
	for _, check := range []struct{ ref, query string }{
		{annotation.SourceRef, "SELECT count(*) FROM records WHERE ref = ? AND snapshot = 'bitwarden'"},
		{annotation.DestinationRef, "SELECT count(*) FROM records WHERE ref = ? AND snapshot IN ('apple', 'supplemental')"},
		{annotation.FieldRef, "SELECT count(*) FROM fields WHERE ref = ?"},
	} {
		if check.ref == "" {
			continue
		}
		var count int
		if err := ledger.DB.QueryRowContext(ctx, check.query, check.ref).Scan(&count); err != nil || count != 1 {
			return nil, errInput
		}
	}

	if annotation.FieldRef != "" && (annotation.SourceRef != "" || annotation.DestinationRef != "") {
		var owner string
		if err := ledger.DB.QueryRowContext(ctx,
			"SELECT record_ref FROM fields WHERE ref = ?", annotation.FieldRef).Scan(&owner); err != nil ||
			(owner != annotation.SourceRef && owner != annotation.DestinationRef) {
			return nil, errInput
		}
	}

	id, err := ledger.Q.InsertAnnotation(ctx, sqlstore.InsertAnnotationParams{
		Kind: annotation.Kind, SourceRef: optionalRef(annotation.SourceRef),
		DestinationRef: optionalRef(annotation.DestinationRef),
		FieldRef:       optionalRef(annotation.FieldRef), CreatedAt: now(),
	})
	if err != nil {
		return nil, errInput
	}

	return map[string]any{"id": id, "provenance": "user"}, nil
}
