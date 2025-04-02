// package rowbinary implements RowBinary encoding for ClickHouse.
//
// See http://clickhouse-docs.readthedocs.io/en/latest/formats/rowbinary.html
//
// This package mustn't depend on another packages from lib/*, because otherwise
// lib/log may break.
package log

import (
	"bytes"
	"math"
	"time"
)

func AppendVarchar(b, v []byte) []byte {
	b = AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}

func AppendChar(b, v []byte, charLen int) []byte {
	lenDiff := charLen - len(v)
	if lenDiff > 0 {
		v = append(v, bytes.Repeat([]byte{' '}, lenDiff)...)
	} else {
		v = v[:charLen]
	}

	return append(b, v...)
}

func AppendBytes(b, v []byte) []byte {
	b = appendVarint(b, len(v))
	return append(b, v...)
}

func AppendString(b []byte, v string) []byte {
	b = appendVarint(b, len(v))
	return append(b, v...)
}

func AppendStringSlice(b []byte, v []string) []byte {
	b = appendVarint(b, len(v))
	for _, x := range v {
		b = AppendString(b, x)
	}
	return b
}

func AppendFloat32(b []byte, v float32) []byte {
	n := math.Float32bits(v)
	return AppendUint32(b, n)
}

func AppendFloat64(b []byte, v float64) []byte {
	n := math.Float64bits(v)
	return AppendUint64(b, n)
}

func AppendInt64(b []byte, v int64) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func AppendUint64(b []byte, v uint64) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func AppendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func AppendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func AppendUint8(b []byte, v uint8) []byte {
	return append(b, byte(v))
}

func AppendUint32Slice(b []byte, v []uint32) []byte {
	b = appendVarint(b, len(v))
	for _, x := range v {
		b = AppendUint32(b, x)
	}
	return b
}

func AppendFloatSlice(b []byte, v []float64) []byte {
	b = appendVarint(b, len(v))
	for _, x := range v {
		b = AppendFloat64(b, x)
	}
	return b
}

func AppendBool(b []byte, v bool) []byte {
	vi := uint8(0)
	if v {
		vi = 1
	}
	return append(b, vi)
}

func AppendDateTime(b []byte, t time.Time) []byte {
	n := t.Unix()
	return AppendUint32(b, uint32(n))
}

func AppendDate(b []byte, t time.Time) []byte {
	n := t.Unix() / 86400
	return AppendUint16(b, uint16(n))
}

func appendVarint(b []byte, x int) []byte {
	n := uint(x)
	for n > 127 {
		b = append(b, 128|byte(n&127))
		n >>= 7
	}
	return append(b, byte(n))
}

func AppendUint64Slice(b []byte, v []uint64) []byte {
	b = appendVarint(b, len(v))
	for _, x := range v {
		b = AppendUint64(b, x)
	}
	return b
}

func AppendStringArrayUint64Map(b []byte, m map[string][]uint64) []byte {
	b = appendVarint(b, len(m))

	for k, v := range m {
		b = AppendString(b, k)
		b = AppendUint64Slice(b, v)
	}

	return b
}

func AppendStringBoolMap(b []byte, m map[string]bool) []byte {
	b = appendVarint(b, len(m))

	for k, v := range m {
		b = AppendString(b, k)
		b = AppendBool(b, v)

	}
	return b
}
