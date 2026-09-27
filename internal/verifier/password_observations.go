package verifier

func observePasswordOccurrences(caseData *Case, comparison *Comparison) {
	all := caseData.AllRecords()
	sourcePasswordCounts, destinationPasswordCounts := map[string]int{}, map[string]int{}
	for _, record := range caseData.Bitwarden {
		if record.Value("Password") != "" {
			sourcePasswordCounts[record.Value("Password")]++
		}
	}

	for _, record := range caseData.Apple {
		if record.Value("Password") != "" {
			destinationPasswordCounts[record.Value("Password")]++
		}
	}

	count := 0
	limited := map[string]bool{}
	for _, source := range all {
		passwordField := source.Get("Password")
		if passwordField == nil || passwordField.Observed != "nonempty" || passwordField.Text() == "" {
			continue
		}
		if passwordField.Length() < 4 &&
			sourcePasswordCounts[passwordField.Text()]+destinationPasswordCounts[passwordField.Text()] > 8 {
			limited[source.Ref] = true
			continue
		}

		for _, record := range all {
			for _, field := range eligible(record) {
				if field.Role == "Password" || field.Ref == passwordField.Ref {
					continue
				}
				if count >= 10000 {
					limited[source.Ref] = true
					continue
				}

				starts := findOccurrences(field.Text(), passwordField.Text(), false, 21)
				for i, start := range starts {
					if i >= 20 || count >= 10000 {
						limited[source.Ref] = true
						break
					}
					end := start + passwordField.Length()
					fieldRunes := []rune(field.Text())
					boundary := (start == 0 || !unicodeAlphaNum(fieldRunes[start-1])) &&
						(end == len(fieldRunes) || !unicodeAlphaNum(fieldRunes[end]))
					method := "embedded_substring"
					if start == 0 && end == len(fieldRunes) {
						method = "whole_field"
					} else if boundary {
						method = "bounded_occurrence"
					}

					comparison.Matches = append(comparison.Matches, Match{
						SourceField: passwordField.Ref, DestinationField: field.Ref,
						SourceStart: 0, SourceEnd: passwordField.Length(),
						DestinationStart: start, DestinationEnd: end,
						Method: "password_" + method,
					})
					count++
				}
			}
		}
	}

	for _, record := range all {
		if limited[record.Ref] {
			comparison.SearchLimits = append(comparison.SearchLimits, SearchLimit{record.Get("Password").Ref, "occurrence_cap"})
		}
	}
}

func unicodeAlphaNum(character rune) bool { return word(character) && character != '_' }
