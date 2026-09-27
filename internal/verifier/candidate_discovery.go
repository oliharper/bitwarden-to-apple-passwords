package verifier

import (
	"sort"
	"strings"
)

var allowedLimitCauses = map[string]bool{
	"line_fanout": true, "token_fanout": true, "short_key_cap": true,
	"short_key_fanout": true, "candidate_cap": true, "pair_cost": true,
	"occurrence_cap": true, "token_index_cap": true,
}

func discoverContent(caseData *Case) ([]Match, []SearchLimit) {
	destinations := append(append([]*RawRecord{}, caseData.Apple...), caseData.Supplemental...)
	fields := map[string]*RawField{}
	exactIndex, lineIndex := map[string]map[string]bool{}, map[string]map[string]bool{}
	tokenIndex, shortIndex := map[string]map[string]bool{}, map[string]map[string]bool{}
	add := func(index map[string]map[string]bool, key, ref string) {
		if index[key] == nil {
			index[key] = map[string]bool{}
		}
		index[key][ref] = true
	}

	for _, record := range destinations {
		for _, field := range eligible(record) {
			fields[field.Ref] = field
			add(exactIndex, field.Text(), field.Ref)

			if field.Role == "Password" || field.Role == "URL" {
				continue
			}

			runes := []rune(field.Text())
			for _, line := range lines(field.Text()) {
				value := strings.TrimRight(runeSliceOf(runes, line.start, line.end), "\r\n")
				if len([]rune(value)) >= 8 {
					add(lineIndex, value, field.Ref)
				}
			}

			for _, segment := range segments(field.Text()) {
				if segment.kind == "token" && segment.end-segment.start >= 6 {
					value := runeSliceOf(runes, segment.start, segment.end)
					if word([]rune(value)[0]) {
						add(tokenIndex, value, field.Ref)
					}
				}
			}

			for code := range shortCodes(field.Text()) {
				add(shortIndex, "code\x00"+code, field.Ref)
			}
			for gram := range shortGrams(field.Text()) {
				add(shortIndex, "gram\x00"+gram, field.Ref)
			}
		}
	}

	matches, limits := []Match{}, []SearchLimit{}
	for _, source := range caseData.Bitwarden {
		for _, field := range eligible(source) {
			exactMatches := []Match{}
			for _, ref := range sortedKeys(exactIndex[field.Text()]) {
				destination := fields[ref]
				if (field.Role == "Password") != (destination.Role == "Password") {
					continue
				}
				exactMatches = append(exactMatches, matchFields(field, destination)...)
			}

			if len(exactMatches) > 0 {
				matches = append(matches, exactMatches...)
				continue
			}

			candidates, causes := map[string]bool{}, map[string]bool{}
			if field.Role != "Password" {
				indexNonexactCandidates(field, candidates, causes, lineIndex, tokenIndex, shortIndex)
			}

			refs := sortedKeys(candidates)
			if len(refs) > 80 {
				causes["candidate_cap"] = true
				refs = refs[:80]
			}

			for _, ref := range refs {
				destination := fields[ref]
				if (field.Role == "Password") != (destination.Role == "Password") {
					continue
				}
				if field.Role != "Password" && field.Text() != destination.Text() &&
					normalizeLines(field.Text()) != normalizeLines(destination.Text()) {
					if len(lines(field.Text()))*len(lines(destination.Text())) > 50000 ||
						tokenCount(field.Text())*tokenCount(destination.Text()) > 50000 {
						causes["pair_cost"] = true
					}
				}

				if destination.Length() >= 3 && destination.Length() <= 6 &&
					shortCodes(destination.Text())[destination.Text()] &&
					len(findOccurrences(field.Text(), destination.Text(), true, 21)) > 20 {
					causes["occurrence_cap"] = true
				}

				if field.Length() >= 3 && field.Length() <= 6 &&
					shortCodes(field.Text())[field.Text()] &&
					len(findOccurrences(destination.Text(), field.Text(), true, 21)) > 20 {
					causes["occurrence_cap"] = true
				}

				matches = append(matches, matchFields(field, destination)...)
			}

			for _, cause := range sortedKeys(causes) {
				limits = append(limits, SearchLimit{field.Ref, cause})
			}
		}
	}

	return matches, limits
}

func tokenCount(value string) int {
	count := 0
	for _, segment := range segments(value) {
		if segment.kind == "token" {
			count++
		}
	}

	return count
}

func indexNonexactCandidates(field *RawField, candidates, causes map[string]bool,
	lineIndex, tokenIndex, shortIndex map[string]map[string]bool) {
	runes := []rune(field.Text())
	if field.Role == "Notes" {
		for _, line := range lines(field.Text()) {
			value := strings.TrimRight(runeSliceOf(runes, line.start, line.end), "\r\n")
			if len(lineIndex[value]) > 12 {
				causes["line_fanout"] = true
				continue
			}
			for ref := range lineIndex[value] {
				candidates[ref] = true
			}
		}
	}

	seen := map[string]bool{}
	for _, segment := range segments(field.Text()) {
		if segment.kind != "token" || segment.end-segment.start < 6 {
			continue
		}
		value := runeSliceOf(runes, segment.start, segment.end)
		if !word([]rune(value)[0]) || seen[value] {
			continue
		}
		seen[value] = true
		if len(tokenIndex[value]) > 12 {
			causes["token_fanout"] = true
			continue
		}
		for ref := range tokenIndex[value] {
			candidates[ref] = true
		}
	}

	keys := []string{}
	for code := range shortCodes(field.Text()) {
		keys = append(keys, "code\x00"+code)
	}
	for gram := range shortGrams(field.Text()) {
		keys = append(keys, "gram\x00"+gram)
	}

	sort.Strings(keys)

	if len(keys) > 100 {
		causes["short_key_cap"] = true
		keys = keys[:100]
	}

	for _, key := range keys {
		if len(shortIndex[key]) > 12 {
			causes["short_key_fanout"] = true
			continue
		}
		for ref := range shortIndex[key] {
			candidates[ref] = true
		}
	}
}
