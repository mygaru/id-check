package util

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

var (
	errInvalidDigit = errors.New("invalid digit")
	errWrongFormat  = errors.New("wrong format")
	errEmptyString  = errors.New("empty string")
)

// This is a dirty hack, which avoids memory allocations unlike strconv.ParseUint(),
// which allocates memory during bytes conversion to string.
//
// Also it skips "," when returning unparsed byte slice.
func ParseUint32(b []byte) (uint32, []byte, error) {
	return ParseUint32Ext(b, ',')
}

// This is a dirty hack, which avoids memory allocations unlike strconv.ParseFloat().
//
// Also it skips "," when returning uparsed byte slice.
func ParseFloat64(b []byte) (float64, []byte, error) {
	return ParseFloat64Ext(b, ',')
}

func ParseFloat64Ext(buf []byte, stopChar byte) (float64, []byte, error) {
	var v uint64
	var offset = float64(1.0)
	var pointFound bool
	b := buf
	for i, c := range b {
		if c < '0' || c > '9' {
			if c == stopChar {
				if i+1 > len(b) {
					return 0, nil, errWrongFormat
				}
				return float64(v) * offset, b[i+1:], nil
			}
			if c == '.' {
				if pointFound {
					return 0, nil, errWrongFormat
				}
				pointFound = true
				continue
			}
			if c == 'e' || c == 'E' {
				if i+1 >= len(b) {
					return 0, nil, errWrongFormat
				}
				b = b[i+1:]
				minus := -1
				switch b[0] {
				case '+':
					b = b[1:]
					minus = 1
				case '-':
					b = b[1:]
				default:
					minus = 1
				}
				vv, b, err := ParseUint32Ext(b, stopChar)
				if err != nil {
					return 0, nil, errWrongFormat
				}
				return float64(v) * offset * math.Pow10(minus*int(vv)), b, nil
			}
			return 0, nil, errWrongFormat
		}
		v = 10*v + uint64(c-'0')
		if pointFound {
			offset /= 10
		}
	}
	if len(buf) > 0 {
		return float64(v) * offset, buf[len(buf):], nil
	}
	return 0, nil, errWrongFormat
}

// This is a dirty hack, which avoids memory allocations unlike strconv.ParseUint(),
// which allocates memory during bytes conversion to string.
//
// Also it skips stopchar when returning unparsed byte slice.
func ParseUint32Ext(b []byte, stopChar byte) (uint32, []byte, error) {
	var v uint32
	if len(b) == 0 {
		return 0, nil, errEmptyString
	}
	for i, c := range b {
		if c < '0' || c > '9' {
			if c == stopChar {
				if i+1 > len(b) {
					return 0, nil, errWrongFormat
				}
				return v, b[i+1:], nil
			}
			return 0, nil, errInvalidDigit
		}
		v = 10*v + uint32(c-'0')
	}
	return v, nil, nil

}

func AppendUint32Bin(dst []byte, v uint32) []byte {
	return append(dst, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func AppendUint64Bin(dst []byte, v uint64) []byte {
	return append(dst, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func Bin2Uint16(b []byte) uint16 {
	_ = b[1]
	return uint16(b[0]) | (uint16(b[1]) << 8)
}

func Bin2Uint32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24)
}

func Bin2Uint64(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0]) | (uint64(b[1]) << 8) | (uint64(b[2]) << 16) | (uint64(b[3]) << 24) |
		(uint64(b[4]) << 32) | (uint64(b[5]) << 40) | (uint64(b[6]) << 48) | (uint64(b[7]) << 56)
}

// UnsafeBytes2Str converts bytes slice to string without memory allocation.
//
// WARNING: this function must be used with caution and only if you understand
// what it does!
func UnsafeBytes2Str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// UnsafeStr2Bytes converts string to byte slice without memory allocation.
//
// WARNING: this function must be used with caution and only if you understand
// what it does!
func UnsafeStr2Bytes(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh := reflect.SliceHeader{
		Data: sh.Data,
		Len:  sh.Len,
		Cap:  sh.Len,
	}
	return *(*[]byte)(unsafe.Pointer(&bh))
}

// TrimSpace trims leading and trailing spaces from b and returns
// the corresponding sub-slice.
func TrimSpace(b []byte) []byte {
	for len(b) > 0 && b[0] == ' ' {
		b = b[1:]
	}
	for len(b) > 0 && b[len(b)-1] == ' ' {
		b = b[:len(b)-1]
	}
	return b
}

var AByteRune = byte('A')
var ZByteRune = byte('Z')
var diffIndex = byte('a') - byte('A')

func ToLower(dst, src []byte) []byte {
	srcLen := len(src)
	if srcLen == 0 { // quick return for empty strings
		return dst
	}
	if isASCII(UnsafeBytes2Str(src)) { // optimize for ascii condition
		if cap(dst) < srcLen {
			dst = make([]byte, srcLen)
		} else {
			dst = dst[:srcLen]
		}

		for i, c := range src {
			if c >= AByteRune && c <= ZByteRune {
				c += diffIndex
			}
			dst[i] = byte(c)
		}
		return dst
	}
	return bytes.Map(unicode.ToLower, src)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
