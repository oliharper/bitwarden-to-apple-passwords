package verifier

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
)

var caseFolder = cases.Fold()

func fold(value string) string { return caseFolder.String(value) }

func eligible(record *RawRecord) []*RawField {
	out := []*RawField{}
	for _, field := range record.Fields {
		if field.Classification == "compared_content" && field.Observed == "nonempty" && field.Value != nil {
			out = append(out, field)
		}
	}

	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}

	sort.Strings(out)
	return out
}

func metadataGuard(records []*RawRecord) func(string) string {
	protectedValues := map[string]bool{}
	foldedShortSecrets := map[string]bool{}
	var notes []string
	var metadata []string
	protectedRole := map[string]bool{
		"Password": true, "CustomValue": true,
		"Card:number": true, "Card:code": true,
		"Identity:ssn": true, "Identity:passportNumber": true,
		"Identity:licenseNumber": true, "Specialized": true,
	}
	for _, record := range records {
		for _, field := range record.Fields {
			if field.Value == nil || *field.Value == "" {
				continue
			}

			value := *field.Value
			if protectedRole[field.Role] || field.Classification == "unsupported_content" ||
				field.Classification == "unsupported_member" || field.Role == "Notes" {
				protectedValues[value] = true
			}

			if (protectedRole[field.Role] && len([]rune(value)) <= 256) ||
				((field.Classification == "unsupported_content" || field.Classification == "unsupported_member") &&
					len([]rune(value)) >= 4 && len([]rune(value)) <= 256) {
				foldedShortSecrets[fold(value)] = true
			}

			if field.Role == "Notes" {
				notes = append(notes, value)
			}

			if field.Role == "CustomName" {
				metadata = append(metadata, value)
			}

			if field.Role == "Opaque" {
				parts := strings.Split(field.Path, ".")
				for i := len(parts) - 1; i >= 0; i-- {
					if _, err := strconv.Atoi(parts[i]); err != nil {
						metadata = append(metadata, parts[i])
						break
					}
				}
			}
		}

		metadata = append(metadata, record.Value("Title"), record.Value("Username"))
		if record.NativeID != nil {
			metadata = append(metadata, *record.NativeID)
		}
		metadata = append(metadata, sortedKeys(record.Hosts)...)

		for _, field := range record.Fields {
			if field.Role == "URL" && field.Value != nil {
				_, origin := siteHostOrigin(*field.Value)
				if origin != "" {
					metadata = append(metadata, origin)
				}
			}
		}
	}

	codeLike := func(segment string) bool {
		runes := []rune(segment)
		hasDigit := false
		allDigits := true
		for _, character := range runes {
			if unicode.IsDigit(character) {
				hasDigit = true
			} else {
				allDigits = false
			}
		}

		return (len(runes) >= 6 && hasDigit && (allDigits || len(runes) >= 8)) ||
			(len(runes) >= 4 && len(runes) <= 5 && allDigits)
	}

	candidates := map[string]bool{}
	for _, value := range metadata {
		runes := []rune(value)
		for _, segment := range segments(value) {
			if segment.kind != "token" {
				continue
			}

			code := runeSliceOf(runes, segment.start, segment.end)
			if codeLike(code) {
				candidates[fold(code)] = true
			}
		}
	}

	noteCodes := map[string]bool{}
	for _, value := range notes {
		runes := []rune(value)
		for _, segment := range segments(value) {
			if segment.kind != "token" {
				continue
			}

			code := runeSliceOf(runes, segment.start, segment.end)
			foldedCode := fold(code)
			if !candidates[foldedCode] {
				continue
			}

			if len([]rune(code)) >= 6 {
				noteCodes[foldedCode] = true
				continue
			}

			start := segment.start
			lineStart := 0
			for i := start - 1; i >= 0; i-- {
				if runes[i] == '\r' || runes[i] == '\n' {
					lineStart = i + 1
					break
				}
			}

			prefixStart := max(start-32, lineStart)
			prefix := strings.ToLower(string(runes[prefixStart:start]))
			for _, tag := range []string{"pin", "code", "otp", "totp", "recovery"} {
				if strings.Contains(prefix, tag) {
					noteCodes[foldedCode] = true
					break
				}
			}
		}
	}

	return func(value string) string {
		if value == "" {
			return ""
		}
		if protectedValues[value] {
			return "[protected content]"
		}

		foldedValue := fold(value)
		foldedRunes := []rune(foldedValue)
		for secret := range foldedShortSecrets {
			if !strings.Contains(foldedValue, secret) {
				continue
			}

			if len([]rune(secret)) >= 6 {
				return "[protected content]"
			}

			for _, segment := range segments(foldedValue) {
				if segment.kind == "token" && runeSliceOf(foldedRunes, segment.start, segment.end) == secret {
					return "[protected content]"
				}
			}
		}

		valueRunes := []rune(value)
		for _, segment := range segments(value) {
			if segment.kind == "token" && noteCodes[fold(runeSliceOf(valueRunes, segment.start, segment.end))] {
				return "[protected content]"
			}
		}

		return value
	}
}

func displayName(field *RawField, record *RawRecord, safe func(string) string) string {
	if field.Role == "CustomValue" {
		for _, groupField := range record.Fields {
			if groupField.GroupRef != nil && field.GroupRef != nil &&
				*groupField.GroupRef == *field.GroupRef &&
				groupField.Role == "CustomName" && groupField.Text() != "" {
				return safe(groupField.Text())
			}
		}
	}

	if field.Role == "CustomName" && field.Text() != "" {
		return safe(field.Text())
	}

	if field.Role == "Specialized" {
		for part := range strings.SplitSeq(field.Path, ".") {
			if specializedFields[part] {
				return part
			}
		}
	}

	if field.Role == "Opaque" {
		parts := strings.Split(field.Path, ".")
		for i := len(parts) - 1; i >= 0; i-- {
			if _, err := strconv.Atoi(parts[i]); err != nil {
				return safe(parts[i])
			}
		}
		return "Additional export field"
	}

	return field.Role
}

func project(caseData *Case, comparison *Comparison) {
	allRecords := caseData.AllRecords()
	safe := metadataGuard(allRecords)

	labels := map[string]string{}
	passwordLabels := map[string]string{}
	noteLabels := map[string]string{}
	totalTokens := 0
	for _, record := range allRecords {
		var id *string
		if record.NativeIDValid && record.NativeID != nil && safe(*record.NativeID) == *record.NativeID {
			id = record.NativeID
		}

		origins := map[string]bool{}
		domains := map[string]bool{}
		for host := range record.Hosts {
			if domain := baseDomain(host); domain != "" && safe(domain) == domain {
				domains[domain] = true
			}
		}

		for _, domain := range sortedKeys(domains) {
			comparison.RecordDomains = append(comparison.RecordDomains, RecordDomain{record.Ref, domain})
		}

		for _, field := range record.Fields {
			if field.Role == "URL" && field.Value != nil {
				_, origin := siteHostOrigin(*field.Value)
				if origin != "" {
					origins[origin] = true
				}
			}
		}

		comparison.Records = append(comparison.Records, Record{
			Ref: record.Ref, Snapshot: record.Source, Position: record.Position, Kind: record.Kind,
			NativeIDValid: id != nil, NativeID: id,
			Title: safe(record.Value("Title")), Username: safe(record.Value("Username")),
			Domains:        strings.Join(sortedKeys(domains), ", "),
			WebsiteOrigins: safe(strings.Join(sortedKeys(origins), ", ")),
		})

		for _, field := range record.Fields {
			comparison.Fields = append(comparison.Fields, Field{
				Ref: field.Ref, Record: record.Ref, Role: field.Role,
				Observed: field.Observed, Classification: field.Classification,
				Length: field.Length(), PathDepth: len(strings.Split(field.Path, ".")),
				ValueType: field.ValueType, ElementCount: field.ElementCount,
				GroupRef: field.GroupRef, DisplayName: displayName(field, record, safe),
			})

			if field.Role == "Password" && field.Observed == "nonempty" && field.Value != nil {
				if passwordLabels[*field.Value] == "" {
					passwordLabels[*field.Value] = fmt.Sprintf("P%04d", len(passwordLabels)+1)
				}
				comparison.Equality = append(comparison.Equality, Equality{passwordLabels[*field.Value], field.Ref, "password"})
			}

			if field.Role == "Notes" && field.Observed == "nonempty" && field.Value != nil {
				if noteLabels[*field.Value] == "" {
					noteLabels[*field.Value] = fmt.Sprintf("N%04d", len(noteLabels)+1)
				}
				comparison.Equality = append(comparison.Equality, Equality{noteLabels[*field.Value], field.Ref, "note"})
			}

			if field.Value == nil || *field.Value == "" || field.Role == "Metadata" {
				continue
			}

			value := *field.Value
			runes := []rune(value)
			fieldSegments := segments(value)
			blocks := []int{}
			lineStarts := []int{0}
			for _, segment := range fieldSegments {
				if segment.kind == "paragraph" {
					blocks = append(blocks, segment.start)
				}
			}

			for i := 0; i < len(runes); i++ {
				if runes[i] == '\r' {
					if i+1 < len(runes) && runes[i+1] == '\n' {
						i++
					}
					lineStarts = append(lineStarts, i+1)
				} else if runes[i] == '\n' {
					lineStarts = append(lineStarts, i+1)
				}
			}

			ordinalByKind := map[string]int{}
			fieldTokens, omitted := 0, 0
			for _, segment := range fieldSegments {
				kind := segment.kind
				if kind == "paragraph" {
					kind = "block"
				}

				value := runeSliceOf(runes, segment.start, segment.end)
				if kind == "token" && strings.TrimFunc(value, space) == "" {
					continue
				}
				if kind == "token" && (fieldTokens >= 50000 || totalTokens >= 200000) {
					omitted++
					continue
				}

				if kind == "token" {
					fieldTokens++
					totalTokens++
				}

				key := kind + "\x00" + value
				if labels[key] == "" {
					labels[key] = fmt.Sprintf("E%07d", len(labels)+1)
				}

				ordinalByKind[kind]++
				line, block := 0, 0
				for _, start := range lineStarts {
					if start <= segment.start {
						line++
					}
				}
				for _, start := range blocks {
					if start <= segment.start {
						block++
					}
				}

				comparison.Occurrences = append(comparison.Occurrences, Occurrence{
					FieldRef: field.Ref, RecordRef: record.Ref, Kind: kind,
					Label: labels[key], Ordinal: ordinalByKind[kind],
					Start: segment.start, End: segment.end, Line: line, Block: block,
				})
			}

			if omitted > 0 {
				comparison.IndexLimits = append(comparison.IndexLimits, IndexLimit{record.Ref, field.Ref, fieldTokens, omitted})
			}
		}
	}
}
