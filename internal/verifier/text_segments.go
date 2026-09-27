package verifier

import "unicode"

type segment struct {
	start, end int
	kind       string
}

func word(character rune) bool {
	return unicode.IsLetter(character) || unicode.IsNumber(character) || character == '_'
}

func space(character rune) bool {
	return unicode.IsSpace(character) || character >= 0x1c && character <= 0x1f
}

func lines(text string) []segment {
	runes := []rune(text)
	var out []segment
	for start := 0; start < len(runes); {
		end := start
		for end < len(runes) && runes[end] != '\r' && runes[end] != '\n' {
			end++
		}
		if end < len(runes) {
			if runes[end] == '\r' && end+1 < len(runes) && runes[end+1] == '\n' {
				end += 2
			} else {
				end++
			}
		}
		out = append(out, segment{start, end, "line"})
		start = end
	}

	return out
}

func segments(text string) []segment {
	runes := []rune(text)
	out := []segment{{0, len(runes), "whole"}}
	out = append(out, lines(text)...)

	// Keep single line breaks within a paragraph and stop at blank lines.
	paragraphAtom := func(i int) int {
		if runes[i] != '\r' && runes[i] != '\n' {
			return i + 1
		}
		end := i + 1
		if runes[i] == '\r' {
			if end >= len(runes) || runes[end] != '\n' {
				return i
			}
			end++
		}
		if end < len(runes) && (runes[end] == '\n' || runes[end] == '\r' && end+1 < len(runes) && runes[end+1] == '\n') {
			return i
		}
		return end
	}

	for start := 0; start < len(runes); {
		end := start
		for end < len(runes) {
			next := paragraphAtom(end)
			if next == end {
				break
			}
			end = next
		}
		if end > start {
			out = append(out, segment{start, end, "paragraph"})
			start = end
		} else {
			start++
		}
	}

	for start := 0; start < len(runes); {
		end := start + 1
		kind := 0
		if word(runes[start]) {
			kind = 1
		} else if space(runes[start]) {
			kind = 2
		}
		for end < len(runes) {
			nextKind := 0
			if word(runes[end]) {
				nextKind = 1
			} else if space(runes[end]) {
				nextKind = 2
			}
			if nextKind != kind {
				break
			}
			end++
		}
		out = append(out, segment{start, end, "token"})
		start = end
	}

	return out
}

func runeSlice(text string, start, end int) string {
	runes := []rune(text)
	if start < 0 || end > len(runes) || start > end {
		return ""
	}

	return string(runes[start:end])
}

func runeSliceOf(runes []rune, start, end int) string { return string(runes[start:end]) }
