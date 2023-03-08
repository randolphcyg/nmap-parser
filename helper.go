package parser

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf16"
)

// HelperP Filters out unprintable characters.
// TODO fix logic
func HelperP(input string) string {
	r := []rune(input)

	tmp := utf16.Encode(r)

	utf16Str := utf16.Decode(tmp)

	filteredRunes := make([]rune, 0, len(utf16Str))
	for _, r := range utf16Str {
		if unicode.IsGraphic(r) {
			filteredRunes = append(filteredRunes, r)
		}
	}

	return string(filteredRunes)
}

// HelperSubst Makes substitutions in matches before they are printed.
func HelperSubst(input, searchStr, replaceStr string) string {
	return strings.ReplaceAll(input, searchStr, replaceStr)
}

// HelperI Unpacks an unsigned integer from the captured bytes.
func HelperI(sign rune, b []byte) (uint32, error) {
	var val uint32
	for i := 0; i < len(b); i++ {
		if sign == '>' {
			val += uint32(b[i]) << uint(8*(len(b)-1-i))
		} else if sign == '<' {
			val += uint32(b[i]) << uint(8*i)
		} else {
			return val, errors.New("invalid sign")
		}
	}

	return val, nil
}
