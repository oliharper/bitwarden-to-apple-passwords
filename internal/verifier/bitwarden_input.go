package verifier

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var uuidRE = regexp.MustCompile(`(?i)^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

var specializedFields = map[string]bool{
	"totp": true, "fido2Credentials": true, "passwordHistory": true,
	"attachments": true, "passkeys": true, "passkey": true,
	"privateKey": true, "publicKey": true, "keyFingerprint": true,
}

var itemMetadata = map[string]bool{
	"id": true, "organizationId": true, "folderId": true, "collectionIds": true,
	"revisionDate": true, "creationDate": true, "deletedDate": true,
	"favorite": true, "reprompt": true, "type": true, "object": true,
}

var cardText = map[string]bool{
	"cardholderName": true, "brand": true, "number": true,
	"expMonth": true, "expYear": true, "code": true,
}

var identityText = map[string]bool{
	"title": true, "firstName": true, "middleName": true, "lastName": true,
	"address1": true, "address2": true, "address3": true, "city": true,
	"state": true, "postalCode": true, "country": true,
	"company": true, "email": true, "phone": true, "ssn": true,
	"username": true, "passportNumber": true, "licenseNumber": true,
}

func bitwardenRole(path []string) string {
	shape := append([]string(nil), path...)
	for i, part := range shape {
		if _, err := strconv.Atoi(part); err == nil {
			shape[i] = "[]"
		}
	}

	joinedPath := strings.Join(shape, ".")
	switch joinedPath {
	case "name":
		return "Title"
	case "notes":
		return "Notes"
	case "login.username":
		return "Username"
	case "login.password":
		return "Password"
	case "login.uris.[].uri":
		return "URL"
	case "fields.[].name":
		return "CustomName"
	case "fields.[].value":
		return "CustomValue"
	}

	if len(shape) == 2 && shape[0] == "card" && cardText[shape[1]] {
		return "Card:" + shape[1]
	}

	if len(shape) == 2 && shape[0] == "identity" && identityText[shape[1]] {
		return "Identity:" + shape[1]
	}

	for _, part := range path {
		if specializedFields[part] {
			return "Specialized"
		}
	}

	if (len(shape) == 1 && (itemMetadata[shape[0]] || shape[0] == "encrypted")) ||
		joinedPath == "login.uris.[].match" || joinedPath == "fields.[].type" ||
		joinedPath == "fields.[].linkedId" || joinedPath == "secureNote.type" ||
		joinedPath == "collectionIds.[]" {
		return "Metadata"
	}

	return "Opaque"
}

func knownContainer(path []string, kind string) bool {
	shape := append([]string(nil), path...)
	for i, part := range shape {
		if _, err := strconv.Atoi(part); err == nil {
			shape[i] = "[]"
		}
	}

	joinedPath := strings.Join(shape, ".")
	switch joinedPath {
	case "login", "login.uris.[]", "fields.[]", "secureNote", "card", "identity":
		return kind == "object"
	case "login.uris", "fields", "collectionIds":
		return kind == "array"
	default:
		return false
	}
}

func inventoryBitwardenNode(record *RawRecord, currentNode node, path []string, inherited bool) error {
	classification := ""
	specialPath := false
	for _, part := range path {
		if specializedFields[part] {
			specialPath = true
		}
	}

	fieldRole := bitwardenRole(path)
	if len(path) > 0 {
		comparedRole := fieldRole == "Title" || fieldRole == "Notes" ||
			fieldRole == "Username" || fieldRole == "Password" || fieldRole == "URL" ||
			fieldRole == "CustomName" || fieldRole == "CustomValue" ||
			strings.HasPrefix(fieldRole, "Card:") || strings.HasPrefix(fieldRole, "Identity:")
		if inherited {
			classification = "unsupported_member"
		} else if specialPath || record.Kind == "unknown" {
			if currentNode.empty() {
				classification = "export_limit_inventory"
			} else {
				classification = "unsupported_content"
			}
		} else if currentNode.kind == "array" || currentNode.kind == "object" {
			if knownContainer(path, currentNode.kind) {
				classification = "structural_metadata"
			} else {
				classification = "unsupported_content"
			}
		} else if fieldRole == "Metadata" && (path[0] != "encrypted" || record.Kind == "export_metadata") {
			classification = "structural_metadata"
		} else if comparedRole && (currentNode.kind == "text" || currentNode.kind == "null") {
			classification = "compared_content"
		} else {
			classification = "unsupported_content"
		}

		scalarRole := fieldRole == "Title" || fieldRole == "Notes" ||
			fieldRole == "Username" || fieldRole == "Password" || fieldRole == "URL" ||
			fieldRole == "CustomName" || fieldRole == "CustomValue"
		if scalarRole && currentNode.kind != "text" && currentNode.kind != "null" {
			return errInput
		}

		var value *string
		if currentNode.kind == "text" {
			value = new(currentNode.str)
		}

		var group *string
		if len(path) >= 2 && path[0] == "fields" {
			if i, err := strconv.Atoi(path[1]); err == nil {
				group = new(fmt.Sprintf("%sC%04d", record.Ref, i+1))
			}
		} else if path[0] == "card" || path[0] == "identity" {
			group = new(record.Ref + ":" + path[0])
		}

		observed := "nonempty"
		if currentNode.kind == "null" {
			observed = "null"
		} else if currentNode.empty() {
			observed = "empty"
		}

		record.Add(fieldRole, strings.Join(path, "."), observed, classification, currentNode.kind, value, currentNode.count(), group)
	}

	childUnsupported := inherited || specialPath || (len(path) > 0 && classification == "unsupported_content")
	for _, member := range currentNode.obj {
		if err := inventoryBitwardenNode(record, member.val, append(append([]string(nil), path...), member.key), childUnsupported); err != nil {
			return err
		}
	}

	for i, childNode := range currentNode.arr {
		if err := inventoryBitwardenNode(record, childNode, append(append([]string(nil), path...), strconv.Itoa(i)), childUnsupported); err != nil {
			return err
		}
	}

	return nil
}

func addText(record *RawRecord, role, path string, fieldNode node, present bool, classification string) error {
	if present && fieldNode.kind != "text" && fieldNode.kind != "null" {
		return errInput
	}

	observed := "absent"
	valueType := "absent"
	var value *string
	if present {
		valueType = fieldNode.kind
		if fieldNode.kind == "null" {
			observed = "null"
		} else if fieldNode.str == "" {
			observed = "empty"
		} else {
			observed = "nonempty"
		}
		if fieldNode.kind == "text" {
			value = new(fieldNode.str)
		}
	}

	record.Add(role, path, observed, classification, valueType, value, 0, nil)
	return nil
}

func loadBitwarden(path string) ([]*RawRecord, *RawRecord, error) {
	root, err := readJSON(path)
	if err != nil || root.kind != "object" {
		return nil, nil, errInput
	}

	encrypted, has := root.get("encrypted")
	if has && (encrypted.kind != "boolean" || encrypted.str != "false") {
		return nil, nil, errInput
	}

	items, has := root.get("items")
	if !has || items.kind != "array" {
		return nil, nil, errInput
	}

	rootRecord := NewRecord("BROOT", "bitwarden_export", 0, "export_metadata")
	for _, rootMember := range root.obj {
		if rootMember.key == "items" {
			state := "nonempty"
			if len(items.arr) == 0 {
				state = "empty"
			}
			rootRecord.Add("Metadata", "items", state, "structural_metadata", "array", nil, len(items.arr), nil)
		} else if err := inventoryBitwardenNode(rootRecord, node{kind: "object", obj: []member{rootMember}}, nil, false); err != nil {
			return nil, nil, errInput
		}
	}

	var records []*RawRecord
	for i, item := range items.arr {
		typeNode, ok := item.get("type")
		if item.kind != "object" || !ok || typeNode.kind != "number" ||
			strings.ContainsAny(typeNode.str, ".eE") {
			return nil, nil, errInput
		}
		itemType, err := strconv.Atoi(typeNode.str)
		if err != nil {
			return nil, nil, errInput
		}

		organizationNode, _ := item.get("organizationId")
		if !organizationNode.empty() && organizationNode.kind != "" {
			return nil, nil, errInput
		}

		kind := map[int]string{1: "login", 2: "secure_note", 3: "card", 4: "identity", 5: "ssh_key"}[itemType]
		if kind == "" {
			kind = "unknown"
		}
		record := NewRecord(fmt.Sprintf("B%04d", i+1), "bitwarden", i+1, kind)
		idNode, _ := item.get("id")
		if idNode.kind == "text" && uuidRE.MatchString(idNode.str) {
			record.NativeIDValid = true
			record.NativeID = new(idNode.str)
		}

		if err := inventoryBitwardenNode(record, item, nil, false); err != nil {
			return nil, nil, errInput
		}

		expectedFields := [][2]string{{"Title", "name"}, {"Notes", "notes"}}
		if kind == "login" {
			login, ok := item.get("login")
			if !ok || login.kind != "object" {
				return nil, nil, errInput
			}
			expectedFields = append(expectedFields, [2]string{"Username", "login.username"}, [2]string{"Password", "login.password"})
			uris, ok := login.get("uris")
			if ok && uris.kind != "null" && uris.kind != "array" {
				return nil, nil, errInput
			}
			for _, uriNode := range uris.arr {
				uri, _ := uriNode.get("uri")
				if uriNode.kind != "object" ||
					(uri.kind != "" && uri.kind != "null" && uri.kind != "text") {
					return nil, nil, errInput
				}
				if uri.text() != "" {
					host, _ := siteHostOrigin(uri.str)
					if host != "" {
						record.Hosts[host] = true
					}
				}
			}
		}

		for _, expectedField := range expectedFields {
			found := false
			for _, field := range record.Fields {
				if field.Path == expectedField[1] {
					found = true
					break
				}
			}
			if !found {
				_ = addText(record, expectedField[0], expectedField[1], node{}, false, "compared_content")
			}
		}

		records = append(records, record)
	}

	return records, rootRecord, nil
}
