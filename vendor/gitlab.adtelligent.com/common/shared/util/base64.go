package util

import (
	"encoding/base64"
)

// Base64Decode decodes base64-encoded src and appends it to dst.
//
// Returns appended dst.
func Base64Decode(dst, src []byte) ([]byte, error) {
	n := base64Encoder.DecodedLen(len(src))
	dstLen := len(dst)
	freeN := cap(dst) - dstLen
	if freeN < n {
		dst = append(make([]byte, 0, n+dstLen), dst...)
	}
	b := dst[dstLen : dstLen+n]
	m, err := base64Encoder.Decode(b, src)
	return dst[:dstLen+m], err
}

var base64Encoder = base64.RawURLEncoding
