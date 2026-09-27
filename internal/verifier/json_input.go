package verifier

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"io"
	"os"
)

var errInput = errors.New("invalid source")

type member struct {
	key string
	val node
}

type node struct {
	kind string
	obj  []member
	arr  []node
	str  string
}

func (currentNode node) get(key string) (node, bool) {
	for _, member := range currentNode.obj {
		if member.key == key {
			return member.val, true
		}
	}

	return node{}, false
}

func (currentNode node) text() string {
	if currentNode.kind == "text" {
		return currentNode.str
	}

	return ""
}

func (currentNode node) empty() bool {
	switch currentNode.kind {
	case "null":
		return true
	case "text":
		return currentNode.str == ""
	case "array":
		return len(currentNode.arr) == 0
	case "object":
		return len(currentNode.obj) == 0
	default:
		return false
	}
}

func (currentNode node) count() int {
	if currentNode.kind == "array" {
		return len(currentNode.arr)
	}

	if currentNode.kind == "object" {
		return len(currentNode.obj)
	}

	return 0
}

func parseNode(decoder *jsontext.Decoder, token jsontext.Token) (node, error) {
	switch token.Kind() {
	case jsontext.KindBeginObject:
		currentNode := node{kind: "object"}
		for {
			keyToken, err := decoder.ReadToken()
			if err != nil {
				return node{}, errInput
			}
			if keyToken.Kind() == jsontext.KindEndObject {
				return currentNode, nil
			}
			if keyToken.Kind() != jsontext.KindString {
				return node{}, errInput
			}

			key := keyToken.String()
			valueToken, err := decoder.ReadToken()
			if err != nil {
				return node{}, errInput
			}
			child, err := parseNode(decoder, valueToken)
			if err != nil {
				return node{}, errInput
			}

			currentNode.obj = append(currentNode.obj, member{key, child})
		}
	case jsontext.KindBeginArray:
		currentNode := node{kind: "array"}
		for {
			childToken, err := decoder.ReadToken()
			if err != nil {
				return node{}, errInput
			}
			if childToken.Kind() == jsontext.KindEndArray {
				return currentNode, nil
			}

			child, err := parseNode(decoder, childToken)
			if err != nil {
				return node{}, errInput
			}

			currentNode.arr = append(currentNode.arr, child)
		}
	case jsontext.KindString:
		return node{kind: "text", str: token.String()}, nil
	case jsontext.KindNumber:
		return node{kind: "number", str: token.String()}, nil
	case jsontext.KindTrue, jsontext.KindFalse:
		return node{kind: "boolean", str: token.String()}, nil
	case jsontext.KindNull:
		return node{kind: "null"}, nil
	default:
		return node{}, errInput
	}
}

func strictJSON(data []byte) (node, error) {
	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	rootToken, err := decoder.ReadToken()
	if err != nil {
		return node{}, errInput
	}
	rootNode, err := parseNode(decoder, rootToken)
	if err != nil {
		return node{}, errInput
	}

	if _, err = decoder.ReadToken(); err != io.EOF {
		return node{}, errInput
	}
	return rootNode, nil
}

func readJSON(path string) (node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return node{}, errInput
	}

	return strictJSON(data)
}
