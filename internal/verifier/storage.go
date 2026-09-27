package verifier

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	sqlstore "github.com/oliharper/bitwarden-to-apple-passwords/internal/verifier/db"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

const schemaVersion = 15

var ErrIncompatibleSchema = errors.New("incompatible case schema")

const toolVersion = "1.0.0"

func now() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00") }

type Ledger struct {
	DB      *sql.DB
	Q       *sqlstore.Queries
	Path    string
	created bool
}

func rejectCaseTarget(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return errInput
	}

	if _, err = os.Lstat(abs); err == nil {
		return errInput
	} else if !errors.Is(err, os.ErrNotExist) {
		return errInput
	}

	parent := filepath.Dir(abs)
	parent, err = filepath.EvalSymlinks(parent)
	if err != nil {
		return errInput
	}

	abs = filepath.Join(parent, filepath.Base(abs))
	st, err := os.Stat(parent)
	if err != nil || !st.IsDir() {
		return errInput
	}

	_, file, _, ok := runtime.Caller(0)
	if ok && filepath.IsAbs(file) {
		repo := filepath.Dir(filepath.Dir(filepath.Dir(file)))
		if abs == repo || strings.HasPrefix(abs, repo+string(os.PathSeparator)) {
			return errInput
		}
	}

	for dir := parent; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "internal", "verifier", "schema.sql")); err == nil {
				if _, err := os.Stat(filepath.Join(dir, "cmd", "bw2apple", "main.go")); err == nil {
					return errInput
				}
			}
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}

	return nil
}

// PreflightNewCase checks the output location before any raw input is read.
// CreateLedger repeats this check immediately before creating the directory.
func PreflightNewCase(path string) error { return rejectCaseTarget(path) }

func sqliteDSN(path, mode string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errInput
	}

	return (&url.URL{Scheme: "file", Path: abs, RawQuery: "mode=" + mode}).String(), nil
}

func removeOwnCaseFiles(path string) {
	for _, name := range []string{"evidence.sqlite3-journal", "evidence.sqlite3-wal", "evidence.sqlite3-shm", "evidence.sqlite3"} {
		_ = os.Remove(filepath.Join(path, name))
	}

	_ = os.Remove(path)
}

func CreateLedger(path string) (*Ledger, error) {
	if err := rejectCaseTarget(path); err != nil {
		return nil, err
	}

	if err := os.Mkdir(path, 0700); err != nil {
		return nil, errInput
	}

	ledger := &Ledger{Path: path, created: true}
	cleanup := func() {
		if ledger.DB != nil {
			_ = ledger.DB.Close()
		}
		removeOwnCaseFiles(path)
	}

	if err := os.Chmod(path, 0700); err != nil {
		cleanup()
		return nil, errInput
	}

	databasePath := filepath.Join(path, "evidence.sqlite3")
	databaseFile, err := os.OpenFile(databasePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		cleanup()
		return nil, errInput
	}

	_ = databaseFile.Close()
	dsn, err := sqliteDSN(databasePath, "rw")
	if err != nil {
		cleanup()
		return nil, errInput
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		cleanup()
		return nil, errInput
	}

	ledger.DB = db
	ledger.Q = sqlstore.New(db)
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		cleanup()
		return nil, errInput
	}

	if _, err = db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		cleanup()
		return nil, errInput
	}

	if _, err = db.Exec(schema); err != nil {
		cleanup()
		return nil, errInput
	}

	if err = ledger.Q.CreateRun(context.Background(), sqlstore.CreateRunParams{
		CreatedAt: now(), ToolVersion: toolVersion, SchemaVersion: schemaVersion,
	}); err != nil {
		cleanup()
		return nil, errInput
	}

	return ledger, nil
}

func OpenLedger(path string, readOnly bool) (*Ledger, error) {
	databasePath := filepath.Join(path, "evidence.sqlite3")
	st, err := os.Stat(databasePath)
	if err != nil || !st.Mode().IsRegular() {
		return nil, errInput
	}

	mode := "rw"
	if readOnly {
		mode = "ro"
	}

	dsn, err := sqliteDSN(databasePath, mode)
	if err != nil {
		return nil, errInput
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errInput
	}

	db.SetMaxOpenConns(1)
	queries := sqlstore.New(db)
	version, err := queries.GetSchemaVersion(context.Background())
	if err != nil {
		_ = db.Close()
		return nil, errInput
	}
	if version != schemaVersion {
		_ = db.Close()
		return nil, ErrIncompatibleSchema
	}

	if !readOnly {
		if _, err = db.Exec("PRAGMA foreign_keys=ON"); err != nil {
			_ = db.Close()
			return nil, errInput
		}
		if _, err = db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
			_ = db.Close()
			return nil, errInput
		}
	}

	return &Ledger{DB: db, Q: queries, Path: path}, nil
}

func (ledger *Ledger) Close() {
	if ledger != nil && ledger.DB != nil {
		_ = ledger.DB.Close()
	}
}

func (ledger *Ledger) Abort() {
	if ledger == nil {
		return
	}

	ledger.Close()
	if ledger.created {
		removeOwnCaseFiles(ledger.Path)
	}
}

func (ledger *Ledger) Finalize() error {
	updated, err := ledger.Q.FinalizeRun(context.Background())
	if err != nil || updated != 1 {
		return errInput
	}
	return nil
}

func nullableString(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}

// Write receives only the redacted projection built by Compare.
func (ledger *Ledger) Write(comparison Comparison) error {
	recordRefs := map[string]bool{}
	fieldLengths := map[string]int{}
	fieldRefs := map[string]bool{}
	for _, item := range comparison.Records {
		if recordRefs[item.Ref] {
			return errInput
		}
		recordRefs[item.Ref] = true
	}

	for _, item := range comparison.Fields {
		if fieldRefs[item.Ref] || !recordRefs[item.Record] {
			return errInput
		}
		fieldRefs[item.Ref] = true
		fieldLengths[item.Ref] = item.Length
	}

	for _, item := range comparison.Occurrences {
		if !recordRefs[item.RecordRef] || !fieldRefs[item.FieldRef] ||
			item.Start < 0 || item.End <= item.Start || item.End > fieldLengths[item.FieldRef] {
			return errInput
		}
	}

	for _, item := range comparison.Matches {
		if !fieldRefs[item.SourceField] || !fieldRefs[item.DestinationField] ||
			item.SourceStart < 0 || item.SourceStart > item.SourceEnd || item.SourceEnd > fieldLengths[item.SourceField] ||
			item.DestinationStart < 0 || item.DestinationStart > item.DestinationEnd || item.DestinationEnd > fieldLengths[item.DestinationField] {
			return errInput
		}
	}

	for _, item := range comparison.RecordDomains {
		if !recordRefs[item.RecordRef] || item.Domain == "" {
			return errInput
		}
	}

	for _, item := range comparison.SearchLimits {
		if !fieldRefs[item.FieldRef] || !allowedLimitCauses[item.Cause] {
			return errInput
		}
	}

	tx, err := ledger.DB.Begin()
	if err != nil {
		return errInput
	}
	defer tx.Rollback()

	ctx := context.Background()
	queries := ledger.Q.WithTx(tx)
	claimed, err := queries.ClaimComparison(ctx)
	if err != nil || claimed != 1 {
		return errInput
	}

	for _, item := range comparison.Snapshots {
		if err = queries.InsertSnapshot(ctx, sqlstore.InsertSnapshotParams{
			Ref:           item.Ref,
			SourceType:    item.SourceType,
			ObservedCount: int64(item.ObservedCount),
			Coverage:      item.Coverage,
		}); err != nil {
			return errInput
		}
	}

	for _, item := range comparison.Records {
		valid := int64(0)
		if item.NativeIDValid {
			valid = 1
		}
		if err = queries.InsertRecord(ctx, sqlstore.InsertRecordParams{
			Ref:            item.Ref,
			Snapshot:       item.Snapshot,
			Position:       int64(item.Position),
			Kind:           item.Kind,
			NativeIDValid:  valid,
			NativeID:       nullableString(item.NativeID),
			Title:          item.Title,
			Username:       item.Username,
			Domains:        item.Domains,
			WebsiteOrigins: item.WebsiteOrigins,
		}); err != nil {
			return errInput
		}
	}

	for _, item := range comparison.RecordDomains {
		if err = queries.InsertRecordDomain(ctx, sqlstore.InsertRecordDomainParams{
			RecordRef: item.RecordRef, Domain: item.Domain,
		}); err != nil {
			return errInput
		}
	}

	for _, item := range comparison.Fields {
		if err = queries.InsertField(ctx, sqlstore.InsertFieldParams{
			Ref:            item.Ref,
			RecordRef:      item.Record,
			Role:           item.Role,
			Observed:       item.Observed,
			Classification: item.Classification,
			Length:         int64(item.Length),
			PathDepth:      int64(item.PathDepth),
			ValueType:      item.ValueType,
			ElementCount:   int64(item.ElementCount),
			GroupRef:       nullableString(item.GroupRef),
			DisplayName:    item.DisplayName,
		}); err != nil {
			return errInput
		}
	}

	for _, item := range comparison.Occurrences {
		if err = queries.InsertOccurrence(ctx, sqlstore.InsertOccurrenceParams{
			FieldRef:  item.FieldRef,
			RecordRef: item.RecordRef,
			Kind:      item.Kind,
			Label:     item.Label,
			Ordinal:   int64(item.Ordinal),
			Start:     int64(item.Start),
			End:       int64(item.End),
			Line:      int64(item.Line),
			Block:     int64(item.Block),
		}); err != nil {
			return errInput
		}
	}

	for _, item := range comparison.IndexLimits {
		if err = queries.InsertIndexLimit(ctx, sqlstore.InsertIndexLimitParams{
			RecordRef:     item.RecordRef,
			FieldRef:      item.FieldRef,
			IndexedTokens: int64(item.Indexed),
			OmittedTokens: int64(item.Omitted),
		}); err != nil {
			return errInput
		}
	}

	for _, item := range comparison.Equality {
		if err = queries.InsertEquality(ctx, sqlstore.InsertEqualityParams{
			Label:    item[0],
			FieldRef: item[1],
			Kind:     item[2],
		}); err != nil {
			return errInput
		}
	}

	for _, item := range comparison.Matches {
		if err = queries.InsertContentMatch(ctx, sqlstore.InsertContentMatchParams{
			SourceField:      item.SourceField,
			DestinationField: item.DestinationField,
			SourceStart:      int64(item.SourceStart),
			SourceEnd:        int64(item.SourceEnd),
			DestinationStart: int64(item.DestinationStart),
			DestinationEnd:   int64(item.DestinationEnd),
			Method:           item.Method,
		}); err != nil {
			return errInput
		}
	}

	for _, item := range comparison.SearchLimits {
		if err = queries.InsertSearchLimit(ctx, sqlstore.InsertSearchLimitParams{
			FieldRef: item.FieldRef, Cause: item.Cause,
		}); err != nil {
			return errInput
		}
	}

	if err = tx.Commit(); err != nil {
		return errInput
	}

	return nil
}
