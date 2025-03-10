package util

import (
	"encoding/hex"
	"github.com/valyala/fasthttp"
	"gitlab.adtelligent.com/common/shared/log"
	"math/big"
	"net"
	"sync"
)

// InetAton converts IPv4 address s in the form 'x.y.z.q' to uint32.
func InetAton(s []byte) uint32 {
	var (
		buf [4]byte
		ip  = buf[:]
		err error
	)
	ip, err = fasthttp.ParseIPv4(ip, s)
	if err != nil {
		return 0
	}
	return IPToUint32(ip)
}

// IPToUint32 converts IPv4 to uint32
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[3]) | (uint32(ip[2]) << 8) | (uint32(ip[1]) << 16) | (uint32(ip[0]) << 24)
}

// Uint32ToIP converts the given n to IPv4 in dst.
func Uint32ToIP(dst net.IP, n uint32) {
	dst[3] = byte(n)
	dst[2] = byte(n >> 8)
	dst[1] = byte(n >> 16)
	dst[0] = byte(n >> 24)
}

func HexToIP(ipHex string) (ip net.IP, err error) {
	hex, err := hex.DecodeString(ipHex)
	if err != nil {
		return nil, err
	}
	return net.IP(hex), nil
}

func IPToHex(ip net.IP) string {
	ipv4 := false
	if ip.To4() != nil {
		ipv4 = true
	}

	ipInt := big.NewInt(0)
	if ipv4 {
		ipInt.SetBytes(ip.To4())
		ipHex := hex.EncodeToString(ipInt.Bytes())
		return ipHex
	}

	ipInt.SetBytes(ip.To16())
	ipHex := hex.EncodeToString(ipInt.Bytes())
	return ipHex
}

// ExternalIP returns the local IP used for external network connections.
//
// Returns net.IPv4zero if the ip couldn't be determined.
func ExternalIP() net.IP {
	externalIPOnce.Do(initExternalIP)
	return externalIP
}

func initExternalIP() {
	// addresses to try to establish connection to in order
	// to determine the local IP.
	var addrs = []string{
		"google.com:80",
		"facebook.com:80",
		"ya.ru:80",
		"msn.com:80",
	}
	var lastErr error
	for _, addr := range addrs {
		conn, err := fasthttp.Dial(addr)
		if err == nil {
			la := conn.LocalAddr()
			tcpAddr := la.(*net.TCPAddr)
			externalIP = tcpAddr.IP
			conn.Close()
			return
		}
		lastErr = err
	}
	log.Errorf("couldn't determine external IP by dialing %q. The last error: %s", addrs, lastErr)
}

var externalIP = net.IPv4zero
var externalIPOnce sync.Once

func AppendIP(ip net.IP, b []byte) []byte {
	p := ip

	if len(ip) == 0 {
		return append(b[:0], "<nil>"...)
	}

	// If IPv4, use dotted notation.
	if p4 := p.To4(); len(p4) == net.IPv4len {
		const maxIPv4StringLen = len("255.255.255.255")
		if len(b) < maxIPv4StringLen {
			b = make([]byte, maxIPv4StringLen)
		}

		n := ubtoa(b, 0, p4[0])
		b[n] = '.'
		n++

		n += ubtoa(b, n, p4[1])
		b[n] = '.'
		n++

		n += ubtoa(b, n, p4[2])
		b[n] = '.'
		n++

		n += ubtoa(b, n, p4[3])
		return b[:n]
	}

	if len(p) != net.IPv6len {
		b = append(b[:0], '?')
		b = append(b, hexString(ip)...)
		return b
	}

	// Find longest run of zeros.
	e0 := -1
	e1 := -1
	for i := 0; i < net.IPv6len; i += 2 {
		j := i
		for j < net.IPv6len && p[j] == 0 && p[j+1] == 0 {
			j += 2
		}
		if j > i && j-i > e1-e0 {
			e0 = i
			e1 = j
			i = j
		}
	}
	// The symbol "::" MUST NOT be used to shorten just one 16 bit 0 field.
	if e1-e0 <= 2 {
		e0 = -1
		e1 = -1
	}

	const maxLen = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	if len(b) < maxLen {
		b = make([]byte, 0, maxLen)
	}

	b = b[:0]
	// Print with possible :: in place of run of zeros
	for i := 0; i < net.IPv6len; i += 2 {
		if i == e0 {
			b = append(b, ':', ':')
			i = e1
			if i >= net.IPv6len {
				break
			}
		} else if i > 0 {
			b = append(b, ':')
		}
		b = appendHex(b, (uint32(p[i])<<8)|uint32(p[i+1]))
	}
	return b
}

func hexString(src []byte) []byte {
	s := make([]byte, len(src)*2)
	for i, tn := range src {
		s[i*2], s[i*2+1] = hexDigit[tn>>4], hexDigit[tn&0xf]
	}
	return s
}

const hexDigit = "0123456789abcdef"

// Convert i to a hexadecimal string. Leading zeros are not printed.
func appendHex(dst []byte, i uint32) []byte {
	if i == 0 {
		return append(dst, '0')
	}
	for j := 7; j >= 0; j-- {
		v := i >> uint(j*4)
		if v > 0 {
			dst = append(dst, hexDigit[v&0xf])
		}
	}
	return dst
}

// ubtoa encodes the string form of the integer v to dst[start:] and
// returns the number of bytes written to dst. The caller must ensure
// that dst has sufficient length.
func ubtoa(dst []byte, start int, v byte) int {
	if v < 10 {
		dst[start] = v + '0'
		return 1
	} else if v < 100 {
		dst[start+1] = v%10 + '0'
		dst[start] = v/10 + '0'
		return 2
	}

	dst[start+2] = v%10 + '0'
	dst[start+1] = (v/10)%10 + '0'
	dst[start] = v/100 + '0'
	return 3
}
