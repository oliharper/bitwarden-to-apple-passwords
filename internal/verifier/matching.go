package verifier

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

func normalizeLines(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
}

func shortCodes(text string) map[string]bool {
	runes := []rune(text)
	out := map[string]bool{}
	for _, segment := range segments(text) {
		if segment.kind != "token" ||
			segment.end-segment.start < 3 || segment.end-segment.start > 6 ||
			(segment.start > 0 && word(runes[segment.start-1])) ||
			(segment.end < len(runes) && word(runes[segment.end])) {
			continue
		}

		code := string(runes[segment.start:segment.end])
		digit, ascii := false, true

		for _, character := range code {
			if character > 127 || !unicode.IsLetter(character) && !unicode.IsDigit(character) {
				ascii = false
			}
			if character >= '0' && character <= '9' {
				digit = true
			}
		}

		if ascii && digit {
			out[code] = true
		}
	}

	return out
}

func shortGrams(text string) map[string]bool {
	words := []string{}
	runes := []rune(text)
	for _, segment := range segments(text) {
		if segment.kind == "token" {
			token := runeSliceOf(runes, segment.start, segment.end)
			if len([]rune(token)) > 0 && word([]rune(token)[0]) {
				words = append(words, token)
			}
		}
	}

	out := map[string]bool{}
	for i := 0; i+1 < len(words); i++ {
		firstWord, secondWord := words[i], words[i+1]
		firstLength, secondLength := len([]rune(firstWord)), len([]rune(secondWord))

		if firstLength >= 2 && firstLength <= 5 && secondLength >= 2 && secondLength <= 5 && firstLength+secondLength >= 7 {
			out[firstWord+"\x00"+secondWord] = true
		}
	}

	return out
}

func findOccurrences(text, substring string, boundary bool, limit int) []int {
	if substring == "" || limit <= 0 {
		return nil
	}

	out := []int{}
	for scanOffset := 0; scanOffset < len(text); {
		relativeOffset := strings.Index(text[scanOffset:], substring)
		if relativeOffset < 0 {
			break
		}

		start := scanOffset + relativeOffset
		end := start + len(substring)
		scanOffset = end

		if boundary {
			if start > 0 {
				prior, _ := utf8.DecodeLastRuneInString(text[:start])
				if word(prior) {
					continue
				}
			}

			if end < len(text) {
				next, _ := utf8.DecodeRuneInString(text[end:])
				if word(next) {
					continue
				}
			}
		}

		out = append(out, utf8.RuneCountInString(text[:start]))
		if len(out) >= limit {
			break
		}
	}

	return out
}

func normSpace(text string) string { return strings.Join(strings.FieldsFunc(text, space), " ") }

func matchFields(sourceField, destinationField *RawField) []Match {
	sourceText, destinationText := sourceField.Text(), destinationField.Text()
	if sourceText == "" || destinationText == "" {
		return nil
	}

	sourceLength, destinationLength := len([]rune(sourceText)), len([]rune(destinationText))
	compatibleRoles := sourceField.Role == destinationField.Role ||
		(sourceField.Role == "CustomName" && destinationField.Role == "Title") ||
		(sourceField.Role == "CustomValue" && destinationField.Role == "Username")
	makeMatch := func(sourceStart, sourceEnd, destinationStart, destinationEnd int, method string) Match {
		return Match{sourceField.Ref, destinationField.Ref, sourceStart, sourceEnd, destinationStart, destinationEnd, method}
	}

	if sourceText == destinationText {
		if compatibleRoles {
			return []Match{makeMatch(0, sourceLength, 0, destinationLength, "exact")}
		}
		return []Match{makeMatch(0, sourceLength, 0, destinationLength, "exact_cross_field")}
	}

	if sourceField.Role != "Password" && normalizeLines(sourceText) == normalizeLines(destinationText) {
		if compatibleRoles {
			return []Match{makeMatch(0, sourceLength, 0, destinationLength, "line_endings_only")}
		}
		return []Match{makeMatch(0, sourceLength, 0, destinationLength, "line_endings_cross_field")}
	}

	if sourceField.Role == "Password" {
		return nil
	}

	if sourceField.Role == "Notes" && destinationField.Role == "Notes" &&
		sourceLength >= 8 && strings.HasPrefix(destinationText, sourceText) {
		destinationRunes := []rune(destinationText)
		if destinationLength == sourceLength || destinationRunes[sourceLength] == '\r' || destinationRunes[sourceLength] == '\n' {
			return []Match{makeMatch(0, sourceLength, 0, sourceLength, "exact_source_with_destination_addition")}
		}
	}

	if sourceField.Role == "Notes" && destinationField.Role == "Notes" &&
		sourceLength >= 8 && strings.Count(destinationText, sourceText) == 1 {
		offset := len([]rune(destinationText[:strings.Index(destinationText, sourceText)]))
		return []Match{makeMatch(0, sourceLength, offset, offset+sourceLength, "relocated_whole")}
	}

	if destinationLength >= 3 && destinationLength <= 6 &&
		shortCodes(destinationText)[destinationText] &&
		(destinationField.Role == "Username" || destinationField.Role == "Title" ||
			destinationField.Role == "CustomValue" || destinationField.Role == "CustomName") {
		out := []Match{}
		for _, offset := range findOccurrences(sourceText, destinationText, true, 20) {
			out = append(out, makeMatch(offset, offset+destinationLength, 0, destinationLength, "short_code_occurrence"))
		}
		if len(out) > 0 {
			return out
		}
	}

	if sourceLength >= 3 && sourceLength <= 6 &&
		shortCodes(sourceText)[sourceText] &&
		(sourceField.Role == "CustomValue" || sourceField.Role == "CustomName" ||
			sourceField.Role == "Username" || sourceField.Role == "Title") &&
		destinationField.Role != "Password" {
		out := []Match{}
		for _, offset := range findOccurrences(destinationText, sourceText, true, 20) {
			out = append(out, makeMatch(0, sourceLength, offset, offset+sourceLength, "short_code_occurrence"))
		}
		if len(out) > 0 {
			return out
		}
	}

	if destinationLength >= 6 && strings.Count(sourceText, destinationText) == 1 &&
		(destinationField.Role == "Username" || destinationField.Role == "Title" ||
			destinationField.Role == "CustomValue" || destinationField.Role == "CustomName") {
		offset := len([]rune(sourceText[:strings.Index(sourceText, destinationText)]))
		return []Match{makeMatch(offset, offset+destinationLength, 0, destinationLength, "relocated_substring")}
	}

	if sourceLength >= 6 && strings.Count(destinationText, sourceText) == 1 &&
		(sourceField.Role == "CustomValue" || sourceField.Role == "CustomName" ||
			sourceField.Role == "Username" || sourceField.Role == "Title" ||
			strings.HasPrefix(sourceField.Role, "Card:") || strings.HasPrefix(sourceField.Role, "Identity:")) {
		offset := len([]rune(destinationText[:strings.Index(destinationText, sourceText)]))
		return []Match{makeMatch(0, sourceLength, offset, offset+sourceLength, "relocated_substring")}
	}

	if normSpace(sourceText) == normSpace(destinationText) {
		return []Match{makeMatch(0, sourceLength, 0, destinationLength, "formatting_equivalent")}
	}

	out := []Match{}
	sourceLines, destinationLines := lines(sourceText), lines(destinationText)
	if len(sourceLines)*len(destinationLines) <= 50000 {
		sourceLineTexts, destinationLineTexts := []string{}, []string{}
		for _, segment := range sourceLines {
			sourceLineTexts = append(sourceLineTexts, runeSlice(sourceText, segment.start, segment.end))
		}

		for _, segment := range destinationLines {
			destinationLineTexts = append(destinationLineTexts, runeSlice(destinationText, segment.start, segment.end))
		}

		for _, block := range matchingBlocks(sourceLineTexts, destinationLineTexts) {
			for i := 0; i < block.length; i++ {
				sourceLine, destinationLine := sourceLines[block.sourceStart+i], destinationLines[block.destinationStart+i]
				if strings.TrimFunc(sourceLineTexts[block.sourceStart+i], space) != "" {
					out = append(out, makeMatch(sourceLine.start, sourceLine.end, destinationLine.start, destinationLine.end, "aligned_line"))
				}
			}
		}
	}

	if (destinationField.Role == "Title" || destinationField.Role == "Username" ||
		destinationField.Role == "CustomName" || destinationField.Role == "CustomValue") &&
		destinationLength >= 4 {
		for _, segment := range sourceLines {
			core := strings.TrimRight(runeSlice(sourceText, segment.start, segment.end), "\r\n")
			if core == destinationText && strings.Count(sourceText, core) == 1 {
				out = append(out, makeMatch(segment.start, segment.start+len([]rune(core)), 0, destinationLength, "relocated_line"))
			}
		}
	}

	if sourceLength >= 12 && destinationLength >= 12 {
		sourceTokens, destinationTokens := []segment{}, []segment{}
		for _, segment := range segments(sourceText) {
			if segment.kind == "token" {
				sourceTokens = append(sourceTokens, segment)
			}
		}

		for _, segment := range segments(destinationText) {
			if segment.kind == "token" {
				destinationTokens = append(destinationTokens, segment)
			}
		}

		if len(sourceTokens)*len(destinationTokens) <= 50000 {
			sourceTokenTexts, destinationTokenTexts := []string{}, []string{}
			for _, segment := range sourceTokens {
				sourceTokenTexts = append(sourceTokenTexts, runeSlice(sourceText, segment.start, segment.end))
			}

			for _, segment := range destinationTokens {
				destinationTokenTexts = append(destinationTokenTexts, runeSlice(destinationText, segment.start, segment.end))
			}

			for _, block := range matchingBlocks(sourceTokenTexts, destinationTokenTexts) {
				if block.length < 3 || block.sourceStart >= len(sourceTokens) || block.destinationStart >= len(destinationTokens) {
					continue
				}
				sourceStart, sourceEnd := sourceTokens[block.sourceStart].start, sourceTokens[block.sourceStart+block.length-1].end
				destinationStart, destinationEnd := destinationTokens[block.destinationStart].start, destinationTokens[block.destinationStart+block.length-1].end
				if sourceEnd-sourceStart >= 8 {
					out = append(out, makeMatch(sourceStart, sourceEnd, destinationStart, destinationEnd, "token_block"))
				}
			}
		}
	}

	return out
}

type matchBlock struct{ sourceStart, destinationStart, length int }

// Find contiguous matching blocks without frequency-based filtering. Ties use
// the earliest source position, then the earliest destination position.
func matchingBlocks(sourceLines, destinationLines []string) []matchBlock {
	out := []matchBlock{}
	var visit func(int, int, int, int)
	visit = func(sourceLow, sourceHigh, destinationLow, destinationHigh int) {
		best := matchBlock{}
		previous := map[int]int{}
		for i := sourceLow; i < sourceHigh; i++ {
			current := map[int]int{}
			for j := destinationLow; j < destinationHigh; j++ {
				if sourceLines[i] != destinationLines[j] {
					continue
				}
				length := previous[j-1] + 1
				current[j] = length
				if length > best.length {
					best = matchBlock{i - length + 1, j - length + 1, length}
				}
			}
			previous = current
		}

		if best.length == 0 {
			return
		}

		if sourceLow < best.sourceStart && destinationLow < best.destinationStart {
			visit(sourceLow, best.sourceStart, destinationLow, best.destinationStart)
		}

		out = append(out, best)

		if best.sourceStart+best.length < sourceHigh && best.destinationStart+best.length < destinationHigh {
			visit(best.sourceStart+best.length, sourceHigh, best.destinationStart+best.length, destinationHigh)
		}
	}

	visit(0, len(sourceLines), 0, len(destinationLines))

	sort.Slice(out, func(i, j int) bool {
		if out[i].sourceStart == out[j].sourceStart {
			return out[i].destinationStart < out[j].destinationStart
		}
		return out[i].sourceStart < out[j].sourceStart
	})

	merged := []matchBlock{}
	for _, block := range out {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if last.sourceStart+last.length == block.sourceStart && last.destinationStart+last.length == block.destinationStart {
				last.length += block.length
				continue
			}
		}
		merged = append(merged, block)
	}

	return merged
}
