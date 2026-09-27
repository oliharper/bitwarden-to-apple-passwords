package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oliharper/bitwarden-to-apple-passwords/internal/verifier"
)

func run(args []string) (any, error) { return runWithOutput(args, io.Discard) }

func commandCase(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	bw, apple := filepath.Join(root, "bw.json"), filepath.Join(root, "apple.csv")
	bitwardenJSON := `{"items":[{"type":1,"name":"Invented","notes":"some invented note","login":{"username":"u","password":"secret-one","uris":[{"uri":"https://login.example.co.uk/path"}]}}]}`
	if err := os.WriteFile(bw, []byte(bitwardenJSON), 0600); err != nil {
		t.Fatal(err)
	}

	appleCSV := "Title,URL,Username,Password,Notes\n" +
		"Invented,https://mobile.example.co.uk/other,u,secret-two,some invented note\n"
	if err := os.WriteFile(apple, []byte(appleCSV), 0600); err != nil {
		t.Fatal(err)
	}

	casePath := filepath.Join(root, "case")
	if _, err := run([]string{"compare", "--bitwarden", bw, "--apple", apple, "--case", casePath}); err != nil {
		t.Fatal(err)
	}

	return casePath
}

func TestEvidenceViews(t *testing.T) {
	casePath := commandCase(t)
	result, err := run([]string{"report", "--case", casePath, "--view", "groups", "--domain", "example.co.uk", "--username", "u"})
	if err != nil {
		t.Fatal(err)
	}
	groups := result.([]map[string]any)
	if len(groups) != 2 || groups[0]["password_label"] == groups[1]["password_label"] {
		t.Fatal("group password difference hidden")
	}

	result, err = run([]string{"report", "--case", casePath, "--view", "absent-passwords"})
	if err != nil || len(result.([]map[string]any)) != 1 {
		t.Fatal("absent password view", err)
	}

	result, err = run([]string{"report", "--case", casePath, "--view", "notes"})
	if err != nil || result.([]map[string]any)[0]["observation"] != "exact_elsewhere" {
		t.Fatal("note view", err)
	}
}

func TestAnnotationCommand(t *testing.T) {
	casePath := commandCase(t)
	input := filepath.Join(t.TempDir(), "annotation.json")
	if err := os.WriteFile(input, []byte(`{"kind":"related_entry","source_ref":"B0001","destination_ref":"A0002"}`), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := run([]string{"annotate", "--case", casePath, "--input", input}); err != nil {
		t.Fatal(err)
	}

	result, err := run([]string{"report", "--case", casePath, "--view", "annotations"})
	if err != nil || len(result.([]map[string]any)) != 1 {
		t.Fatal("annotation view", err)
	}
}

func TestFrameworkHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"compare", "--help"}, {"report", "--help"}} {
		var output bytes.Buffer
		result, err := runWithOutput(args, &output)
		if err != nil || result != nil || !strings.Contains(output.String(), "bw2apple") {
			t.Fatalf("help unavailable: %v, %v", args, err)
		}
	}
}

func TestSafeUsageErrors(t *testing.T) {
	const sentinel = "PRIVATE_SECRET_SENTINEL"
	for _, args := range [][]string{
		{"compare", "--bitwarden", sentinel},
		{"report", "--case", sentinel, "--view", "invalid"},
		{"report", "--case", sentinel, "--unknown=" + sentinel},
		{"report", "--case", sentinel, "--view", "matches"},
		{"annotate", "--case", sentinel},
	} {
		var output bytes.Buffer
		_, err := runWithOutput(args, &output)
		if !errors.Is(err, errInput) || output.Len() != 0 || strings.Contains(err.Error(), sentinel) {
			t.Fatalf("unsafe or accepted usage error: %v, %v", args, err)
		}
	}
}

func TestCompareRepeatableNotes(t *testing.T) {
	fixture := filepath.Join("..", "..", "internal", "verifier", "testdata", "golden", "two-notes")
	casePath := filepath.Join(t.TempDir(), "case")
	result, err := run([]string{
		"compare", "--bitwarden", filepath.Join(fixture, "bitwarden.json"),
		"--apple", filepath.Join(fixture, "apple.csv"), "--case", casePath,
		"--note", filepath.Join(fixture, "Archive One.txt"),
		"--note", filepath.Join(fixture, "Archive Two.txt"),
	})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, snapshot := range result.(map[string]any)["snapshots"].([]map[string]any) {
		if snapshot["source_type"] == "supplemental" && snapshot["observed_count"] == int64(2) {
			found = true
		}
	}
	if !found {
		t.Fatal("repeated notes omitted")
	}
}

func TestIncompatibleSchemaReportsSafely(t *testing.T) {
	casePath := commandCase(t)
	ledger, err := verifier.OpenLedger(casePath, false)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ledger.DB.Exec("UPDATE runs SET schema_version=9 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	ledger.Close()

	var output bytes.Buffer
	_, err = runWithOutput([]string{"report", "--case", casePath}, &output)
	if !errors.Is(err, verifier.ErrIncompatibleSchema) || output.Len() != 0 {
		t.Fatal("schema mismatch not reported safely", err)
	}
}
