package verifier

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"
)

func siteHostOrigin(value string) (string, string) {
	trimmedValue := strings.TrimFunc(value, space)
	if trimmedValue == "" {
		return "", ""
	}

	parse := trimmedValue
	if !strings.Contains(trimmedValue, "://") {
		parse = "//" + trimmedValue
	}

	parsedURL, err := url.Parse(parse)
	if err != nil {
		return "", ""
	}

	if parsedURL.Scheme != "" && parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", ""
	}

	host := strings.TrimSuffix(strings.ToLower(parsedURL.Hostname()), ".")
	if host == "" {
		return "", ""
	}

	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	port := parsedURL.Port()
	origin := ""
	if parsedURL.Scheme != "" {
		origin = strings.ToLower(parsedURL.Scheme) + "://"
	}

	origin += authority
	if port != "" {
		origin += ":" + port
	}

	return host, origin
}

// parseCSV deliberately retains CRLF inside quoted fields, unlike encoding/csv.
func parseCSV(data []byte) ([][]string, error) {
	if !utf8.Valid(data) {
		return nil, errInput
	}

	csvText := string(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	var rows [][]string
	var row []string
	var builder strings.Builder
	quoted := false
	afterQuote := false
	atStart := true
	for i := 0; i < len(csvText); i++ {
		currentByte := csvText[i]
		if quoted {
			if currentByte == '"' {
				if i+1 < len(csvText) && csvText[i+1] == '"' {
					builder.WriteByte('"')
					i++
				} else {
					quoted = false
					afterQuote = true
				}
			} else {
				builder.WriteByte(currentByte)
			}
			continue
		}

		if afterQuote {
			if currentByte != ',' && currentByte != '\r' && currentByte != '\n' {
				return nil, errInput
			}
			afterQuote = false
		}

		switch currentByte {
		case '"':
			if !atStart {
				return nil, errInput
			}
			quoted = true
			atStart = false
		case ',':
			row = append(row, builder.String())
			builder.Reset()
			atStart = true
		case '\r', '\n':
			if currentByte == '\r' && i+1 < len(csvText) && csvText[i+1] == '\n' {
				i++
			}
			if len(row) == 0 && builder.Len() == 0 && atStart {
				continue
			}

			row = append(row, builder.String())
			builder.Reset()
			rows = append(rows, row)
			row = nil
			atStart = true
		default:
			builder.WriteByte(currentByte)
			atStart = false
		}
	}

	if quoted {
		return nil, errInput
	}

	if len(row) > 0 || builder.Len() > 0 || !atStart {
		row = append(row, builder.String())
		rows = append(rows, row)
	}

	return rows, nil
}

func loadApple(path string) ([]*RawRecord, map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, errInput
	}

	rows, err := parseCSV(data)
	if err != nil || len(rows) == 0 {
		return nil, nil, errInput
	}

	headers := map[string]bool{}
	for _, header := range rows[0] {
		if headers[header] {
			return nil, nil, errInput
		}
		headers[header] = true
	}

	for _, header := range []string{"Title", "URL", "Username"} {
		if !headers[header] {
			return nil, nil, errInput
		}
	}

	var out []*RawRecord
	for i, row := range rows[1:] {
		if len(row) != len(rows[0]) {
			return nil, nil, errInput
		}

		record := NewRecord(fmt.Sprintf("A%04d", i+2), "apple", i+2, "csv_row")
		values := map[string]string{}
		for j, header := range rows[0] {
			values[header] = row[j]
			role := header
			classification := "compared_content"
			if header != "Title" && header != "URL" && header != "Username" &&
				header != "Password" && header != "Notes" {
				role = "Opaque"
				classification = "unsupported_content"
			}
			_ = addText(record, role, header, node{kind: "text", str: row[j]}, true, classification)
		}

		for _, role := range []string{"Notes", "Password", "Title", "URL", "Username"} {
			if !headers[role] {
				_ = addText(record, role, role, node{}, false, "compared_content")
			}
		}

		host, _ := siteHostOrigin(values["URL"])
		if host != "" {
			record.Hosts[host] = true
		}

		out = append(out, record)
	}

	return out, headers, nil
}
