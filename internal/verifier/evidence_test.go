package verifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func inventedRecord(ref, snapshot string, position int, host, username, password, notes string) *RawRecord {
	record := NewRecord(ref, snapshot, position, "login")
	if snapshot == "apple" {
		record.Kind = "csv_row"
	}

	if host != "" {
		record.Hosts[host] = true
	}

	record.Add("Title", "Title", "nonempty", "compared_content", "text", new("Invented "+ref), 0, nil)
	record.Add("Username", "Username", "nonempty", "compared_content", "text", new(username), 0, nil)
	record.Add("Password", "Password", "nonempty", "compared_content", "text", new(password), 0, nil)
	if notes != "" {
		record.Add("Notes", "Notes", "nonempty", "compared_content", "text", new(notes), 0, nil)
	}

	return record
}

func evidenceLedger(t *testing.T, caseData *Case) *Ledger {
	t.Helper()
	ledger, err := CreateLedger(filepath.Join(t.TempDir(), "case"))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(ledger.Close)
	if err := ledger.Write(Compare(caseData)); err != nil {
		t.Fatal(err)
	}

	if err := ledger.Finalize(); err != nil {
		t.Fatal(err)
	}

	return ledger
}

func TestBaseDomainGroupsKeepEveryRowAndUsername(t *testing.T) {
	caseData := &Case{AppleHeaders: map[string]bool{"Password": true, "Notes": true}}
	caseData.Bitwarden = []*RawRecord{
		inventedRecord("B0001", "bitwarden", 1, "login.example.co.uk", "ada", "one", ""),
		inventedRecord("B0002", "bitwarden", 2, "mobile.example.co.uk", "ada", "two", ""),
		inventedRecord("B0003", "bitwarden", 3, "example.co.uk", "bob", "three", ""),
	}
	caseData.Apple = []*RawRecord{
		inventedRecord("A0001", "apple", 1, "www.example.co.uk", "ada", "four", ""),
		inventedRecord("A0002", "apple", 2, "example.co.uk", "", "five", ""),
	}

	ledger := evidenceLedger(t, caseData)
	rows, err := ledger.Groups("example.co.uk", "ada")
	if err != nil || len(rows) != 3 {
		t.Fatalf("group rows: %d, %v", len(rows), err)
	}
	for _, row := range rows {
		if row["base_domain"] != "example.co.uk" || row["username"] != "ada" {
			t.Fatal(row)
		}
	}

	all, err := ledger.Groups("example.co.uk", "")
	if err != nil || len(all) != 5 {
		t.Fatalf("domain-only rows: %d, %v", len(all), err)
	}
}

func TestBaseDomainExtraction(t *testing.T) {
	for host, want := range map[string]string{
		"foo.bar.example.co.uk": "example.co.uk",
		"example.com":           "example.com",
		"localhost":             "localhost",
		"127.0.0.1":             "127.0.0.1",
	} {
		if got := baseDomain(host); got != want {
			t.Fatalf("%s: %s", host, got)
		}
	}
}

func TestSwappedPasswordsRemainDifferentInsideGroups(t *testing.T) {
	caseData := &Case{AppleHeaders: map[string]bool{"Password": true}}
	caseData.Bitwarden = []*RawRecord{
		inventedRecord("B0001", "bitwarden", 1, "a.example", "one", "secret-one", ""),
		inventedRecord("B0002", "bitwarden", 2, "b.example", "two", "secret-two", ""),
	}
	caseData.Apple = []*RawRecord{
		inventedRecord("A0001", "apple", 1, "a.example", "one", "secret-two", ""),
		inventedRecord("A0002", "apple", 2, "b.example", "two", "secret-one", ""),
	}

	ledger := evidenceLedger(t, caseData)
	summary, err := ledger.Summary()
	if err != nil {
		t.Fatal(err)
	}
	passwords := summary["source_passwords"].(map[string]int64)
	if passwords["present_anywhere_in_apple"] != 2 || passwords["absent_anywhere_in_apple"] != 0 {
		t.Fatal(passwords)
	}

	for _, domain := range []string{"a.example", "b.example"} {
		group, err := ledger.Groups(domain, "")
		if err != nil || len(group) != 2 {
			t.Fatalf("%s: %v, %v", domain, group, err)
		}
		if group[0]["password_label"] == group[1]["password_label"] {
			t.Fatalf("swapped password hidden within %s", domain)
		}
	}

	if absent, err := ledger.AbsentPasswords(); err != nil || len(absent) != 0 {
		t.Fatalf("global absence confused with group difference: %v, %v", absent, err)
	}
}

func TestSplitRelocatedNotesOrderedOccurrencesAndUnicodeOffsets(t *testing.T) {
	source := inventedRecord("B0001", "bitwarden", 1, "source.example", "u", "pw", "🙂 Alpha code 0042\nBeta code 0042")
	first := inventedRecord("A0001", "apple", 1, "other.example", "x", "x", "🙂 Alpha code 0042")
	second := inventedRecord("A0002", "apple", 2, "another.example", "y", "y", "Beta code 0042")
	caseData := &Case{Bitwarden: []*RawRecord{source}, Apple: []*RawRecord{first, second},
		AppleHeaders: map[string]bool{"Password": true, "Notes": true}}

	comparison := Compare(caseData)
	sourceNote := source.Get("Notes").Ref
	destinations := map[string]bool{}
	for _, match := range comparison.Matches {
		if match.SourceField == sourceNote {
			destinations[match.DestinationField] = true
		}
	}
	if !destinations[first.Get("Notes").Ref] || !destinations[second.Get("Notes").Ref] {
		t.Fatal("split notes were blocked by unrelated domains")
	}

	starts := []int{}
	for _, occurrence := range comparison.Occurrences {
		if occurrence.FieldRef == sourceNote && occurrence.Kind == "token" &&
			runeSlice(source.Value("Notes"), occurrence.Start, occurrence.End) == "0042" {
			starts = append(starts, occurrence.Start)
		}
	}
	if !slices.Equal(starts, []int{13, 28}) {
		t.Fatalf("repeated Unicode rune offsets: %v", starts)
	}

	ledger := evidenceLedger(t, caseData)
	rows, err := ledger.Occurrences(sourceNote)
	if err != nil || len(rows) == 0 {
		t.Fatalf("ordered occurrences unavailable: %v", err)
	}

	matches, err := ledger.Matches(sourceNote)
	if err != nil || len(matches) < 2 {
		t.Fatalf("cross-entry note observations unavailable: %v", err)
	}
}

func TestNoteViewsDistinguishExactPartialUnobservedAndEmpty(t *testing.T) {
	caseData := &Case{AppleHeaders: map[string]bool{"Notes": true}}
	caseData.Bitwarden = []*RawRecord{
		inventedRecord("B0001", "bitwarden", 1, "one.example", "one", "p1", "Exact invented passage"),
		inventedRecord("B0002", "bitwarden", 2, "two.example", "two", "p2", "Alpha marker\nBeta marker"),
		inventedRecord("B0003", "bitwarden", 3, "three.example", "three", "p3", "Zebraquartz disconnected"),
		inventedRecord("B0004", "bitwarden", 4, "four.example", "four", "p4", ""),
	}
	caseData.Bitwarden[3].Add("Notes", "Notes", "empty", "compared_content", "text", new(""), 0, nil)
	caseData.Apple = []*RawRecord{
		inventedRecord("A0001", "apple", 1, "elsewhere.example", "a", "q1", "Exact invented passage"),
		inventedRecord("A0002", "apple", 2, "elsewhere.example", "b", "q2", "Alpha marker"),
	}

	ledger := evidenceLedger(t, caseData)
	rows, err := ledger.Notes()
	if err != nil || len(rows) != 4 {
		t.Fatalf("note inventory: %v, %v", rows, err)
	}

	want := []string{"exact_elsewhere", "partial_observation", "no_observed_match", "not_compared"}
	for i, row := range rows {
		if row["observation"] != want[i] {
			t.Fatalf("note %d: %v, want %s", i, row, want[i])
		}
	}

	summary, err := ledger.Summary()
	if err != nil {
		t.Fatal(err)
	}
	notes := summary["source_notes"].(map[string]int64)
	if notes["nonempty"] != 3 || notes["exact_elsewhere"] != 1 ||
		notes["partial_observation"] != 1 || notes["no_observed_match"] != 1 {
		t.Fatal(notes)
	}
}

func TestPasswordOccurrencesAndHeadingMovesAreGlobal(t *testing.T) {
	source := inventedRecord("B0001", "bitwarden", 1, "one.example", "u", "s3cret99", "Heading Transfer")
	destination := inventedRecord("A0001", "apple", 1, "elsewhere.example", "v", "different", "🙂 s3cret99 extra")
	*destination.Get("Title").Value = "Heading Transfer"
	caseData := &Case{Bitwarden: []*RawRecord{source}, Apple: []*RawRecord{destination},
		AppleHeaders: map[string]bool{"Password": true, "Notes": true}}

	comparison := Compare(caseData)
	passwordSeen, headingSeen := false, false
	for _, match := range comparison.Matches {
		if match.SourceField == source.Get("Password").Ref &&
			match.DestinationField == destination.Get("Notes").Ref &&
			match.Method == "password_bounded_occurrence" &&
			match.DestinationStart == 2 && match.DestinationEnd == 10 {
			passwordSeen = true
		}
		if match.SourceField == source.Get("Notes").Ref &&
			match.DestinationField == destination.Get("Title").Ref &&
			match.Method == "exact_cross_field" {
			headingSeen = true
		}
	}
	if !passwordSeen || !headingSeen {
		t.Fatalf("global cross-field observations missing: password=%v heading=%v", passwordSeen, headingSeen)
	}

	ledger := evidenceLedger(t, caseData)
	notes, err := ledger.Notes()
	if err != nil || len(notes) != 1 || notes[0]["observation"] != "exact_elsewhere" {
		t.Fatalf("whole Note moved to Title was called partial: %v, %v", notes, err)
	}

	summary, err := ledger.Summary()
	if err != nil || summary["source_notes"].(map[string]int64)["exact_elsewhere"] != 1 {
		t.Fatalf("summary lost whole cross-field Note: %v, %v", summary, err)
	}
}

func TestSearchCapIsExplicitWhileEqualityRemainsComplete(t *testing.T) {
	tokens := make([]string, 100)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("uniquetoken%03d", i)
	}
	source := inventedRecord("B0001", "bitwarden", 1, "same.example", "u", "same", strings.Join(tokens, " "))
	caseData := &Case{Bitwarden: []*RawRecord{source}, AppleHeaders: map[string]bool{"Password": true, "Notes": true}}
	for i := range 100 {
		caseData.Apple = append(caseData.Apple,
			inventedRecord(fmt.Sprintf("A%04d", i+1), "apple", i+1, "same.example", "u", "same", tokens[i]+" extra"))
	}

	comparison := Compare(caseData)
	limited := false
	for _, limit := range comparison.SearchLimits {
		if limit.FieldRef == source.Get("Notes").Ref && limit.Cause == "candidate_cap" {
			limited = true
		}
	}
	if !limited {
		t.Fatal("bounded search did not expose cap")
	}

	ledger := evidenceLedger(t, caseData)
	summary, err := ledger.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if summary["source_passwords"].(map[string]int64)["present_anywhere_in_apple"] != 1 {
		t.Fatal("candidate cap changed exact global equality")
	}

	if summary["search_limits"].(int64) == 0 {
		t.Fatal("search limits missing from summary")
	}
}

func TestLimitsReportIncludesTokenCountsOnlyForIndexCap(t *testing.T) {
	source := inventedRecord("B0001", "bitwarden", 1, "example.test", "u", "p", "Invented note")
	ledger := evidenceLedger(t, &Case{Bitwarden: []*RawRecord{source}})
	fieldRef := source.Get("Notes").Ref

	for _, cause := range []string{"candidate_cap", "token_index_cap"} {
		if _, err := ledger.DB.Exec("INSERT INTO search_limits(field_ref, cause) VALUES (?, ?)", fieldRef, cause); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ledger.DB.Exec(
		"INSERT INTO index_limits(record_ref, field_ref, indexed_tokens, omitted_tokens) VALUES (?, ?, ?, ?)",
		source.Ref, fieldRef, 3, 7,
	); err != nil {
		t.Fatal(err)
	}

	rows, err := ledger.Limits()
	if err != nil || len(rows) != 2 {
		t.Fatalf("limit rows: %v, %v", rows, err)
	}
	if rows[0]["cause"] != "candidate_cap" || rows[0]["indexed_tokens"] != nil || rows[0]["omitted_tokens"] != nil {
		t.Fatal("non-index cap gained counts", rows[0])
	}
	if rows[1]["cause"] != "token_index_cap" || rows[1]["indexed_tokens"] != int64(3) || rows[1]["omitted_tokens"] != int64(7) {
		t.Fatal("index cap lost counts", rows[1])
	}
}

func TestOccurrenceReportUsesFieldGroup(t *testing.T) {
	source := NewRecord("B0001", "bitwarden", 1, "login")
	groupRef := "invented-group"
	field := source.Add("CustomValue", "custom.value", "nonempty", "compared_content", "text", new("invented content"), 0, &groupRef)
	ledger := evidenceLedger(t, &Case{Bitwarden: []*RawRecord{source}})

	rows, err := ledger.Occurrences(field.Ref)
	if err != nil || len(rows) == 0 {
		t.Fatalf("occurrences missing: %v, %v", rows, err)
	}
	for _, row := range rows {
		if row["group_ref"] != groupRef {
			t.Fatal("occurrence lost field group", row)
		}
	}
}

func TestExactFirstSkipsExplorationWithoutLosingLabels(t *testing.T) {
	text := "Alpha invented marker"
	source := inventedRecord("B0001", "bitwarden", 1, "source.example", "u", "same", text)
	caseData := &Case{Bitwarden: []*RawRecord{source}, AppleHeaders: map[string]bool{"Notes": true}}
	for i := range 13 {
		caseData.Apple = append(caseData.Apple,
			inventedRecord(fmt.Sprintf("A%04d", i+1), "apple", i+1, "elsewhere.example", "u", "same", text))
	}
	caseData.Apple = append(caseData.Apple,
		inventedRecord("A0014", "apple", 14, "elsewhere.example", "u", "different", "Alpha invented"))

	comparison := Compare(caseData)
	note := source.Get("Notes").Ref
	exactCount := 0
	for _, match := range comparison.Matches {
		if match.SourceField == note {
			if match.Method != "exact" {
				t.Fatalf("unexpected partial discovery after exact match: %v", match)
			}
			exactCount++
		}
	}
	if exactCount != 13 {
		t.Fatalf("exact observations: %d", exactCount)
	}

	for _, limit := range comparison.SearchLimits {
		if limit.FieldRef == note {
			t.Fatalf("exact Note produced exploratory limit: %v", limit)
		}
	}

	ledger := evidenceLedger(t, caseData)
	notes, err := ledger.Notes()
	if err != nil || notes[0]["observation"] != "exact_elsewhere" {
		t.Fatal(notes, err)
	}

	partialField := caseData.Apple[13].Get("Notes").Ref
	partialLabels := map[string]bool{}
	for _, row := range comparison.Occurrences {
		if row.FieldRef == partialField && row.Kind == "token" {
			partialLabels[row.Label] = true
		}
	}

	shared := false
	for _, row := range comparison.Occurrences {
		if row.FieldRef == note && row.Kind == "token" && partialLabels[row.Label] {
			shared = true
		}
	}
	if !shared {
		t.Fatal("secondary copy no longer discoverable from ordered labels")
	}
}

func TestNormalizedWholeNoteIsNotExactEquality(t *testing.T) {
	source := inventedRecord("B0001", "bitwarden", 1, "source.example", "u", "p", "Alpha\r\nBeta")
	destination := inventedRecord("A0001", "apple", 1, "elsewhere.example", "v", "q", "Alpha\nBeta")
	ledger := evidenceLedger(t, &Case{Bitwarden: []*RawRecord{source}, Apple: []*RawRecord{destination},
		AppleHeaders: map[string]bool{"Notes": true}})
	notes, err := ledger.Notes()
	if err != nil || len(notes) != 1 || notes[0]["observation"] != "whole_source_observation" {
		t.Fatalf("normalized Note status: %v, %v", notes, err)
	}

	matches, err := ledger.Matches(source.Get("Notes").Ref)
	if err != nil || len(matches) != 1 || matches[0]["method"] != "line_endings_only" {
		t.Fatalf("normalization method hidden: %v, %v", matches, err)
	}

	summary, err := ledger.Summary()
	if err != nil || summary["source_notes"].(map[string]int64)["whole_source_observation"] != 1 {
		t.Fatal(summary, err)
	}
}

func TestReportsReturnAllRows(t *testing.T) {
	words := make([]string, 1001)
	for i := range words {
		words[i] = fmt.Sprintf("word%04d", i)
	}
	source := inventedRecord("B0001", "bitwarden", 1, "example.co.uk", "u", "p", strings.Join(words, " "))
	caseData := &Case{Bitwarden: []*RawRecord{source}, AppleHeaders: map[string]bool{"Notes": true}}
	for i := range 501 {
		caseData.Apple = append(caseData.Apple,
			inventedRecord(fmt.Sprintf("A%04d", i+1), "apple", i+1, "example.co.uk",
				fmt.Sprintf("user%04d", i), fmt.Sprintf("password%04d", i), ""))
	}

	ledger := evidenceLedger(t, caseData)
	groups, err := ledger.Groups("example.co.uk", "")
	if err != nil || len(groups) != 502 {
		t.Fatalf("group report silently truncated: %d, %v", len(groups), err)
	}

	occurrences, err := ledger.Occurrences(source.Get("Notes").Ref)
	if err != nil {
		t.Fatal(err)
	}

	tokens := 0
	for _, row := range occurrences {
		if row["kind"] == "token" {
			tokens++
		}
	}
	if tokens != 1001 || len(occurrences) <= 1000 {
		t.Fatalf("occurrence report silently truncated: %d tokens, %d rows", tokens, len(occurrences))
	}
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateLedgerOfflineAndSafeWriteBoundary(t *testing.T) {
	root := t.TempDir()
	bw, apple := filepath.Join(root, "bw.json"), filepath.Join(root, "apple.csv")
	writeFixture(t, bw, `{"items":[{"type":1,"name":"Invented","notes":"line 1\r\nline 2","login":{"username":"u","password":"PRIVATE_PASSWORD_SENTINEL","uris":[{"uri":"https://invented.test/path"}]}}]}`)
	writeFixture(t, apple, "Title,URL,Username,Password,Notes\r\nInvented,https://invented.test/path,u,PRIVATE_PASSWORD_SENTINEL,\"line 1\r\nline 2\"\r\n")

	caseData, err := LoadCase(bw, apple, nil)
	if err != nil || caseData.Apple[0].Value("Notes") != "line 1\r\nline 2" {
		t.Fatal("quoted CRLF changed", err)
	}

	path := filepath.Join(root, "case")
	ledger, err := CreateLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Write(Compare(caseData)); err != nil {
		t.Fatal(err)
	}

	if err := ledger.Finalize(); err != nil {
		t.Fatal(err)
	}
	ledger.Close()

	if _, err := CreateLedger(path); err == nil {
		t.Fatal("existing case overwritten")
	}

	for _, check := range []struct {
		path string
		perm os.FileMode
	}{
		{path, 0700}, {filepath.Join(path, "evidence.sqlite3"), 0600},
	} {
		st, err := os.Stat(check.path)
		if err != nil || st.Mode().Perm() != check.perm {
			t.Fatalf("case permissions: %s, %v", check.path, err)
		}
	}

	raw, err := os.ReadFile(filepath.Join(path, "evidence.sqlite3"))
	if err != nil || bytes.Contains(raw, []byte("PRIVATE_PASSWORD_SENTINEL")) ||
		bytes.Contains(raw, []byte("line 1\r\nline 2")) {
		t.Fatal("raw content persisted")
	}

	_ = os.Remove(bw)
	_ = os.Remove(apple)

	reader, err := OpenLedger(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if summary, err := reader.Summary(); err != nil || summary["run_state"] != "finalized" {
		t.Fatal("offline summary unavailable", err)
	}
}

func TestAbsentNullEmptyAndUnsupportedStayDistinct(t *testing.T) {
	root := filepath.Join("testdata", "golden", "missing-unsupported")
	caseData, err := LoadCase(filepath.Join(root, "bitwarden.json"), filepath.Join(root, "apple.csv"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ledger := evidenceLedger(t, caseData)

	sourceFields, err := ledger.Fields(caseData.Bitwarden[0].Ref)
	if err != nil {
		t.Fatal(err)
	}
	observed := map[string]string{}
	for _, field := range sourceFields {
		observed[field["role"].(string)] = field["observed"].(string)
	}
	if observed["Password"] != "null" || observed["Notes"] != "absent" {
		t.Fatal(observed)
	}

	appleFields, err := ledger.Fields(caseData.Apple[0].Ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range appleFields {
		if field["role"] == "Password" && field["observed"] != "empty" {
			t.Fatal(field)
		}
	}

	coverage, err := ledger.Coverage()
	if err != nil {
		t.Fatal(err)
	}
	unsupported := false
	for _, row := range coverage {
		if row["classification"] == "unsupported_content" && row["observed"] == "nonempty" {
			unsupported = true
		}
	}
	if !unsupported {
		t.Fatal("unsupported nonempty material invisible")
	}
}

func TestAnnotationsKeepUserProvenanceSeparate(t *testing.T) {
	caseData := &Case{Bitwarden: []*RawRecord{inventedRecord("B0001", "bitwarden", 1, "x.example", "u", "p", "")},
		Apple:        []*RawRecord{inventedRecord("A0001", "apple", 1, "x.example", "u", "q", "")},
		AppleHeaders: map[string]bool{"Password": true}}
	ledger := evidenceLedger(t, caseData)
	before, err := ledger.Summary()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ledger.ApplyAnnotation(Annotation{Kind: "related_entry", SourceRef: "B0001", DestinationRef: "missing"}); err == nil {
		t.Fatal("unknown reference accepted")
	}
	result, err := ledger.ApplyAnnotation(Annotation{Kind: "related_entry", SourceRef: "B0001", DestinationRef: "A0001"})
	if err != nil || result["provenance"] != "user" {
		t.Fatal(result, err)
	}

	after, err := ledger.Summary()
	if err != nil || !reflect.DeepEqual(before["source_passwords"], after["source_passwords"]) {
		t.Fatal("annotation changed computed equality", err)
	}

	rows, err := ledger.Annotations()
	if err != nil || len(rows) != 1 || rows[0]["provenance"] != "user" {
		t.Fatal(rows, err)
	}
}

func TestAnnotationRejectsProse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "annotation.json")
	writeFixture(t, path, `{"kind":"reviewed","source_ref":"B0001","note":"PRIVATE_SECRET"}`)
	if _, err := ReadAnnotation(path); err == nil {
		t.Fatal("raw annotation prose accepted")
	}
}

func TestMalformedBitwardenInput(t *testing.T) {
	root := t.TempDir()
	bw, apple := filepath.Join(root, "bw.json"), filepath.Join(root, "apple.csv")
	writeFixture(t, apple, "Title,URL,Username,Password,Notes\n")

	for _, bad := range []string{`{"items":[],"items":[]}`, `{"items":NaN}`} {
		writeFixture(t, bw, bad)
		if _, err := LoadCase(bw, apple, nil); err == nil {
			t.Fatal("malformed Bitwarden JSON accepted")
		}
	}
}

func TestSecondComparisonWriteRejected(t *testing.T) {
	caseData := &Case{AppleHeaders: map[string]bool{}}
	path := filepath.Join(t.TempDir(), "case")
	ledger, err := CreateLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	comparison := Compare(caseData)
	if err := ledger.Write(comparison); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Write(comparison); err == nil {
		t.Fatal("second comparison accepted")
	}
}

func TestIncompatibleCaseDoesNotChangeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "case")
	ledger, err := CreateLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Write(Compare(&Case{AppleHeaders: map[string]bool{}})); err != nil {
		t.Fatal(err)
	}

	if _, err := ledger.DB.Exec("UPDATE runs SET schema_version=9 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	ledger.Close()

	before, err := os.ReadFile(filepath.Join(path, "evidence.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLedger(path, false); !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatal("schema mismatch accepted", err)
	}

	after, err := os.ReadFile(filepath.Join(path, "evidence.sqlite3"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("incompatible case changed")
	}
}

func TestUnicodePrivacyGuard(t *testing.T) {
	record := NewRecord("B0001", "bitwarden", 1, "login")
	record.Add("Title", "name", "nonempty", "compared_content", "text", new("STRASSE Invented"), 0, nil)
	record.Add("Password", "login.password", "nonempty", "compared_content", "text", new("Straße"), 0, nil)
	if got := metadataGuard([]*RawRecord{record})("STRASSE Invented"); got != "[protected content]" {
		t.Fatal("folded secret leaked")
	}
}

func TestStrictJSONRejectsMalformedInput(t *testing.T) {
	for _, bad := range []string{`{"password":"\ud800"}`, `{"a":1,"\u0061":2}`, `{} []`} {
		if _, err := strictJSON([]byte(bad)); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}

func TestHistoryExportKeepsCurrentPasswordOut(t *testing.T) {
	root := t.TempDir()
	source, output := filepath.Join(root, "source.json"), filepath.Join(root, "history.txt")
	data, _ := json.Marshal(map[string]any{"items": []any{map[string]any{
		"type": 1, "name": "Invented",
		"login": map[string]any{"password": "CURRENT_SENTINEL"},
		"passwordHistory": []any{map[string]any{
			"password": "OLDER_SENTINEL", "lastUsedDate": "2026-10-25T00:30:00Z",
		}},
	}}})
	writeFixture(t, source, string(data))

	if _, err := HistoryExport(source, output, "Europe/Amsterdam"); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(output)
	if err != nil || !bytes.Contains(archive, []byte("OLDER_SENTINEL")) ||
		bytes.Contains(archive, []byte("CURRENT_SENTINEL")) {
		t.Fatal("history archive content incorrect")
	}

	if _, err := HistoryExport(source, output, "UTC"); err == nil {
		t.Fatal("archive overwrite accepted")
	}
}

func TestWriteFailureRollsBack(t *testing.T) {
	ledger, err := CreateLedger(filepath.Join(t.TempDir(), "case"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	if _, err := ledger.DB.Exec("CREATE TRIGGER reject_snapshot BEFORE INSERT ON snapshots BEGIN SELECT RAISE(FAIL,'synthetic rollback'); END"); err != nil {
		t.Fatal(err)
	}
	comparison := Compare(&Case{})
	if err := ledger.Write(comparison); err == nil {
		t.Fatal("failed write accepted")
	}

	state, err := ledger.Q.GetRunState(context.Background())
	if err != nil || state != "active" {
		t.Fatalf("failed write changed state: %s", state)
	}

	if _, err := ledger.DB.Exec("DROP TRIGGER reject_snapshot"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Write(comparison); err != nil {
		t.Fatal("rollback prevented retry", err)
	}
}

func TestNoRawValuesInProjectedJSON(t *testing.T) {
	secret := "PRIVATE_SENTINEL_8675309"
	caseData := &Case{Bitwarden: []*RawRecord{inventedRecord("B0001", "bitwarden", 1, "x.example", "u", secret, secret)}}
	projected, err := json.Marshal(Compare(caseData))
	if err != nil || bytes.Contains(projected, []byte(secret)) {
		t.Fatal("raw value in comparison")
	}

	if strings.Contains(string(projected), "supported") || strings.Contains(string(projected), "candidate") {
		t.Fatal("certification state in comparison")
	}
}
