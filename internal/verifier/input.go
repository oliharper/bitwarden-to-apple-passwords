package verifier

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func LoadCase(bitwardenPath, applePath string, notePaths []string) (*Case, error) {
	bitwardenRecords, rootRecord, err := loadBitwarden(bitwardenPath)
	if err != nil {
		return nil, errInput
	}

	appleRecords, appleHeaders, err := loadApple(applePath)
	if err != nil {
		return nil, errInput
	}

	caseData := &Case{Bitwarden: bitwardenRecords, Apple: appleRecords, Root: rootRecord, AppleHeaders: appleHeaders}

	for i, path := range notePaths {
		noteFile, err := os.Open(path)
		if err != nil {
			return nil, errInput
		}

		noteBytes, readErr := io.ReadAll(io.LimitReader(noteFile, 4_000_001))
		closeErr := noteFile.Close()

		if readErr != nil || closeErr != nil || len(noteBytes) > 4_000_000 || !utf8.Valid(noteBytes) {
			return nil, errInput
		}

		noteName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if noteName == "" || len([]rune(noteName)) > 80 || len([]rune(string(noteBytes))) > 1_000_000 {
			return nil, errInput
		}

		for _, ch := range noteName {
			if ch < 32 {
				return nil, errInput
			}
		}

		record := NewRecord(fmt.Sprintf("N%04d", i+1), "supplemental", i+1, "supplied_text_unattested")
		_ = addText(record, "Title", "Title", node{kind: "text", str: noteName}, true, "compared_content")
		_ = addText(record, "Notes", "Notes", node{kind: "text", str: string(noteBytes)}, true, "compared_content")
		caseData.Supplemental = append(caseData.Supplemental, record)
	}

	return caseData, nil
}
