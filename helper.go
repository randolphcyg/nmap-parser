package parser

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	pNum       = `\$\d+`
	pHelpP     = `\$(P\(\d+\))`
	pHelpSubst = `\$(SUBST\(.*"\))`
	pHelpI     = `\$(I\(.*"\))`
)

var patternFlags = []string{pNum, pHelpP, pHelpSubst, pHelpI}

// helperP Filters out unprintable characters.
func helperP(str string) string {
	var sb strings.Builder
	for _, r := range str {
		if unicode.IsPrint(r) {
			sb.WriteRune(r)
		}
	}

	return sb.String()
}

// helperSubst Makes substitutions in matches before they are printed.
func helperSubst(input, searchStr, replaceStr string) string {
	return strings.ReplaceAll(input, searchStr, replaceStr)
}

// helperI Unpacks an unsigned integer from the captured bytes.
func helperI(sign string, b []byte) (val uint32) {
	for i := 0; i < len(b); i++ {
		if sign == ">" {
			val += uint32(b[i]) << uint(8*(len(b)-1-i))
		} else if sign == "<" {
			val += uint32(b[i]) << uint(8*i)
		} else {
			return
		}
	}

	return
}

// FillHelperFuncOrVariable replace versionInfo helper functions and Variable
func (c *Client) FillHelperFuncOrVariable(str string, src [][]byte) string {
	if len(str) == 0 {
		return str
	}

	for _, p := range patternFlags {
		re, err := regexp.Compile(p)
		if err != nil {
			return str
		}

		matches := re.FindAllString(str, -1)
		if matches == nil {
			continue
		}

		for _, match := range matches {
			reNum, err := regexp.Compile(`\d+`)
			if err != nil {
				continue
			}
			matchesNum := reNum.FindAllString(match, -1)
			tmpNum, _ := strconv.Atoi(matchesNum[0])

			switch p {
			case pNum:
				{
					str = strings.ReplaceAll(str, match, string(src[tmpNum]))
				}
			case pHelpP:
				{
					str = strings.ReplaceAll(str, match, helperP(string(src[tmpNum])))
				}
			case pHelpSubst:
				{
					reC, err := regexp.Compile(`"([^"]*)"`)
					if err != nil {
						continue
					}
					matchC := reC.FindAllString(match, -1)
					if len(matchC) == 2 {
						str = strings.ReplaceAll(str, match, helperSubst(string(src[tmpNum]), strings.Trim(matchC[0], "\""), strings.Trim(matchC[1], "\"")))
					}

				}
			case pHelpI:
				{
					reC, err := regexp.Compile(`"([^"]*)"`)
					if err != nil {
						continue
					}
					matchC := reC.FindAllString(match, -1)
					if len(matchC) == 1 {
						ele := strings.Trim(matchC[0], "\"")
						str = strings.ReplaceAll(str, match, strconv.Itoa(int(helperI(ele, src[tmpNum]))))
					}
				}
			}

		}

	}

	return str
}
