package util

import (
	"encoding/json"
	"io"
	"unicode/utf8"
)

var (
	strBackslashQuote  = []byte(`\"`)
	strDoubleBackslash = []byte(`\\`)
	strBackslashLF     = []byte(`\n`)
	strBackslashCR     = []byte(`\r`)
	strBackslashB      = []byte(`\b`)
	strBackslashF      = []byte(`\f`)
	strBackslashT      = []byte(`\t`)
	strBackslashZero   = []byte(`\u0000`)
	strQuote           = []byte(`"`)
)

func AppendJSONString(dst, s []byte) []byte {
	s = fixIncorrectUTF8(s)

	dst = append(dst, strQuote...)
	startPos := 0
	for i, n := 0, len(s); i < n; i++ {
		switch s[i] {
		case '"':
			dst = append(dst, s[startPos:i]...)
			startPos = i + 1
			dst = append(dst, strBackslashQuote...)
		case '\\':
			dst = append(dst, s[startPos:i]...)
			startPos = i + 1
			dst = append(dst, strDoubleBackslash...)
		case '\n':
			dst = append(dst, s[startPos:i]...)
			startPos = i + 1
			dst = append(dst, strBackslashLF...)
		case '\r':
			dst = append(dst, s[startPos:i]...)
			startPos = i + 1
			dst = append(dst, strBackslashCR...)
		case '\b':
			dst = append(dst, s[startPos:i]...)
			startPos = i + 1
			dst = append(dst, strBackslashB...)
		case '\f':
			dst = append(dst, s[startPos:i]...)
			startPos = i + 1
			dst = append(dst, strBackslashF...)
		case '\t':
			dst = append(dst, s[startPos:i]...)
			startPos = i + 1
			dst = append(dst, strBackslashT...)
		case 0:
			dst = append(dst, s[startPos:i]...)
			startPos = i + 1
			dst = append(dst, strBackslashZero...)
		}
	}
	dst = append(dst, s[startPos:]...)
	return append(dst, strQuote...)
}

func WriteJSONString(w io.Writer, s []byte) {
	s = fixIncorrectUTF8(s)

	w.Write(strQuote)
	startPos := 0
	for i, n := 0, len(s); i < n; i++ {
		switch s[i] {
		case '"':
			w.Write(s[startPos:i])
			startPos = i + 1
			w.Write(strBackslashQuote)
		case '\\':
			w.Write(s[startPos:i])
			startPos = i + 1
			w.Write(strDoubleBackslash)
		case '\n':
			w.Write(s[startPos:i])
			startPos = i + 1
			w.Write(strBackslashLF)
		case '\r':
			w.Write(s[startPos:i])
			startPos = i + 1
			w.Write(strBackslashCR)
		case '\b':
			w.Write(s[startPos:i])
			startPos = i + 1
			w.Write(strBackslashB)
		case '\f':
			w.Write(s[startPos:i])
			startPos = i + 1
			w.Write(strBackslashF)
		case '\t':
			w.Write(s[startPos:i])
			startPos = i + 1
			w.Write(strBackslashT)
		case 0:
			w.Write(s[startPos:i])
			startPos = i + 1
			w.Write(strBackslashZero)
		}
	}
	w.Write(s[startPos:])
	w.Write(strQuote)
}

// ValidateJSON returns true if s is a valid json dictionary.
func ValidateJSON(s []byte) error {
	var tmp struct{}
	return json.Unmarshal(s, &tmp)
}

func fixIncorrectUTF8(s []byte) []byte {
	if !utf8.Valid(s) {
		var ss []rune
		for _, ch := range string(s) {
			if ch == utf8.RuneError {
				ch = '?'
			}
			ss = append(ss, ch)
		}
		s = []byte(string(ss))
	}
	return s
}
