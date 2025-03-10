package util

import (
	"bytes"
	"unicode"
)

func ParseHost(url []byte) ([]byte, bool) {
	isHTTPS := false
	n := bytes.Index(url, []byte("//"))
	if n >= 0 {
		isHTTPS = string(url[:n]) == "https:"
		url = url[n+2:]
	}
	if n = bytes.IndexByte(url, '/'); n == -1 {
		n = bytes.IndexByte(url, '?')
	}
	if n >= 0 {
		url = url[:n]
	}
	for pos := range url {
		if url[pos] <= 'Z' {
			url[pos] = byte(unicode.ToLower(rune(url[pos])))
		}
	}

	if len(url) > 4 && bytes.Equal(url[:4], []byte("www.")) {
		url = url[4:]
	}

	return url, isHTTPS
}
