package parser

import (
	"errors"
	"strings"
	"unicode"
)

// HelperP Filters out unprintable characters.
func HelperP(str string) string {
	var sb strings.Builder
	for _, r := range str {
		if unicode.IsPrint(r) {
			sb.WriteRune(r)
		}
	}

	return sb.String()
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
