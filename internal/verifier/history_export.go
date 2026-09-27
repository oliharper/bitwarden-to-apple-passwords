package verifier

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var timestampRE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)

type passwordVersion struct {
	password, original, local, fraction string
	second                              time.Time
	known                               bool
	position                            int
}

type historyAccount struct {
	title, username string
	nativeID        *string
	position        int
	versions        []passwordVersion
}

func quoteJSON(value string) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return strings.ReplaceAll(strings.TrimSuffix(buffer.String(), "\n"), "\u0085", "\\u0085")
}

func oneLine(value string) string {
	if value == "" || strings.TrimFunc(value, space) != value {
		return quoteJSON(value)
	}

	for _, character := range value {
		if character < 32 || character == 127 || character == '\u0085' || character == '\u2028' || character == '\u2029' {
			return quoteJSON(value)
		}
	}

	return value
}

func compareFraction(firstFraction, secondFraction string) int {
	firstFraction = strings.TrimPrefix(firstFraction, ".")
	secondFraction = strings.TrimPrefix(secondFraction, ".")
	width := max(len(firstFraction), len(secondFraction))

	firstFraction += strings.Repeat("0", width-len(firstFraction))
	secondFraction += strings.Repeat("0", width-len(secondFraction))
	return strings.Compare(firstFraction, secondFraction)
}

func parseVersion(date node, password string, position int, zone *time.Location, zoneName string) (passwordVersion, error) {
	version := passwordVersion{password: password, position: position, local: "unknown"}
	if date.kind == "" || date.kind == "null" || date.kind == "text" && date.str == "" {
		return version, nil
	}

	if date.kind != "text" {
		return version, errInput
	}

	timestampParts := timestampRE.FindStringSubmatch(date.str)
	if timestampParts == nil {
		return version, errInput
	}

	offset := timestampParts[4]
	if offset == "Z" {
		offset = "+00:00"
	}

	instant, err := time.Parse("2006-01-02T15:04:05-07:00", timestampParts[1]+"T"+timestampParts[2]+offset)
	if err != nil {
		return version, errInput
	}

	local := instant.In(zone)
	_, offsetSeconds := local.Zone()
	sign := "+"
	if offsetSeconds < 0 {
		sign = "-"
		offsetSeconds = -offsetSeconds
	}

	version.original = date.str
	version.fraction = timestampParts[3]
	version.second = instant.UTC()
	version.known = true
	version.local = local.Format("2006-01-02 15:04:05") + timestampParts[3] +
		fmt.Sprintf(" %s%02d:%02d %s", sign, offsetSeconds/3600, offsetSeconds%3600/60, zoneName)
	return version, nil
}

func historyAccounts(path string, zone *time.Location, zoneName string) ([]historyAccount, int, error) {
	root, err := readJSON(path)
	if err != nil || root.kind != "object" {
		return nil, 0, errInput
	}

	encrypted, ok := root.get("encrypted")
	if ok && (encrypted.kind != "boolean" || encrypted.str != "false") {
		return nil, 0, errInput
	}

	items, ok := root.get("items")
	if !ok || items.kind != "array" {
		return nil, 0, errInput
	}

	accounts := []historyAccount{}
	total := 0
	for i, item := range items.arr {
		typeNode, ok := item.get("type")
		if item.kind != "object" || !ok || typeNode.kind != "number" ||
			len(typeNode.str) != 1 || typeNode.str[0] < '1' || typeNode.str[0] > '5' {
			return nil, 0, errInput
		}

		organizationNode, _ := item.get("organizationId")
		if organizationNode.kind != "" && !organizationNode.empty() {
			return nil, 0, errInput
		}
		title, ok := item.get("name")
		if ok && title.kind != "text" {
			return nil, 0, errInput
		}
		login, _ := item.get("login")
		if (typeNode.str == "1" && login.kind != "object") ||
			(login.kind != "" && login.kind != "null" && login.kind != "object") {
			return nil, 0, errInput
		}
		username := node{}
		if login.kind == "object" {
			username, _ = login.get("username")
		}
		if username.kind != "" && username.kind != "null" && username.kind != "text" {
			return nil, 0, errInput
		}

		history, _ := item.get("passwordHistory")
		if history.kind == "" || history.kind == "null" {
			continue
		}
		if history.kind != "array" {
			return nil, 0, errInput
		}

		versions := []passwordVersion{}
		for j, entry := range history.arr {
			passwordNode, ok := entry.get("password")
			if entry.kind != "object" || !ok || passwordNode.kind != "text" {
				return nil, 0, errInput
			}

			date, _ := entry.get("lastUsedDate")
			version, err := parseVersion(date, passwordNode.str, j, zone, zoneName)
			if err != nil {
				return nil, 0, errInput
			}

			versions = append(versions, version)
		}
		if len(versions) == 0 {
			continue
		}

		nativeID := (*string)(nil)
		id, _ := item.get("id")
		if id.kind == "text" && uuidRE.MatchString(id.str) {
			nativeID = new(id.str)
		}

		accounts = append(accounts, historyAccount{title.text(), username.text(), nativeID, i + 1, versions})
		total += len(versions)
	}

	sort.SliceStable(accounts, func(i, j int) bool {
		leftAccount, rightAccount := accounts[i], accounts[j]
		if fold(leftAccount.title) != fold(rightAccount.title) {
			return fold(leftAccount.title) < fold(rightAccount.title)
		}

		if fold(leftAccount.username) != fold(rightAccount.username) {
			return fold(leftAccount.username) < fold(rightAccount.username)
		}

		return leftAccount.position < rightAccount.position
	})
	return accounts, total, nil
}

func renderArchive(accounts []historyAccount, zoneName string) string {
	lines := []string{
		"Bitwarden password history archive",
		"Passwords are JSON-quoted: surrounding quotes and escapes are notation, not password characters.",
		"Last used times are shown in " + zoneName + "; each original export timestamp is retained.",
		"",
	}
	duplicates := map[string]int{}
	for _, account := range accounts {
		duplicates[fold(account.title)+"\x00"+fold(account.username)]++
	}

	for _, account := range accounts {
		heading := "(untitled)"
		if account.title != "" {
			heading = oneLine(account.title)
		}
		if account.username != "" {
			heading += " (" + oneLine(account.username) + ")"
		}
		if duplicates[fold(account.title)+"\x00"+fold(account.username)] > 1 || account.title == "" {
			heading += fmt.Sprintf(" [export item %d", account.position)
			if account.nativeID != nil {
				heading += "; Bitwarden ID " + *account.nativeID
			}
			heading += "]"
		}

		lines = append(lines, heading)
		sort.SliceStable(account.versions, func(i, j int) bool {
			leftVersion, rightVersion := account.versions[i], account.versions[j]
			if leftVersion.known != rightVersion.known {
				return leftVersion.known
			}

			if leftVersion.known && !leftVersion.second.Equal(rightVersion.second) {
				return leftVersion.second.After(rightVersion.second)
			}

			if fractionOrder := compareFraction(leftVersion.fraction, rightVersion.fraction); fractionOrder != 0 {
				return fractionOrder > 0
			}

			return leftVersion.position < rightVersion.position
		})

		for _, version := range account.versions {
			date := "unknown"
			if version.known {
				date = version.local + " [source " + version.original + "]"
			}
			lines = append(lines, "  Last used: "+date+" | Password: "+quoteJSON(version.password))
		}
		lines = append(lines, "")
	}

	if len(accounts) == 0 {
		lines = append(lines, "No passwordHistory entries were present in the supplied export.")
	}

	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
}

func HistoryExport(source, output, zoneName string) (any, error) {
	if zoneName == "" {
		return nil, errInput
	}

	zone, err := time.LoadLocation(zoneName)
	if err != nil {
		return nil, errInput
	}

	if err = rejectCaseTarget(output); err != nil {
		return nil, err
	}

	sourceInfo, err := os.Stat(source)
	if err != nil || !sourceInfo.Mode().IsRegular() {
		return nil, errInput
	}

	absSource, _ := filepath.Abs(source)
	absOutput, _ := filepath.Abs(output)
	if absSource == absOutput {
		return nil, errInput
	}

	accounts, total, err := historyAccounts(source, zone, zoneName)
	if err != nil {
		return nil, err
	}

	content := renderArchive(accounts, zoneName)

	random := make([]byte, 12)
	if _, err = rand.Read(random); err != nil {
		return nil, errInput
	}

	temporaryPath := filepath.Join(filepath.Dir(output), "."+filepath.Base(output)+"."+hex.EncodeToString(random)+".tmp")
	outputFile, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errInput
	}

	defer func() { _ = os.Remove(temporaryPath) }()
	if err = outputFile.Chmod(0600); err != nil {
		_ = outputFile.Close()
		return nil, errInput
	}

	if _, err = outputFile.WriteString(content); err != nil {
		_ = outputFile.Close()
		return nil, errInput
	}

	if err = outputFile.Sync(); err != nil {
		_ = outputFile.Close()
		return nil, errInput
	}

	if err = outputFile.Close(); err != nil {
		return nil, errInput
	}

	if err = os.Link(temporaryPath, output); err != nil {
		return nil, errInput
	}

	return map[string]any{"accounts": len(accounts), "history_entries": total, "output": "created; open privately; passwords are JSON-quoted"}, nil
}
