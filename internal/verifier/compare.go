package verifier

import "strings"

func Compare(caseData *Case) Comparison {
	comparison := NewComparison()
	project(caseData, &comparison)
	comparison.Matches, comparison.SearchLimits = discoverContent(caseData)
	observePasswordOccurrences(caseData, &comparison)

	for _, limit := range comparison.IndexLimits {
		comparison.SearchLimits = append(comparison.SearchLimits, SearchLimit{limit.FieldRef, "token_index_cap"})
	}

	coverage := "partial_export"
	for _, role := range []string{"Password", "Notes"} {
		if !caseData.AppleHeaders[role] {
			coverage += ";missing_" + strings.ToLower(role) + "_column"
		}
	}
	comparison.Snapshots = append(comparison.Snapshots,
		Snapshot{Ref: "bitwarden", SourceType: "bitwarden", ObservedCount: len(caseData.Bitwarden), Coverage: "partial_export"},
		Snapshot{Ref: "apple", SourceType: "apple", ObservedCount: len(caseData.Apple), Coverage: coverage},
	)
	if len(caseData.Supplemental) > 0 {
		comparison.Snapshots = append(comparison.Snapshots, Snapshot{
			Ref: "supplemental", SourceType: "supplemental",
			ObservedCount: len(caseData.Supplemental), Coverage: "user_supplied_unverified",
		})
	}
	comparison.Snapshots = append(comparison.Snapshots, Snapshot{
		Ref: "bitwarden_export", SourceType: "bitwarden_export",
		ObservedCount: 1, Coverage: "root_inventory",
	})
	return comparison
}
