// This is a stripped down copy of lib/util that doesn't use lib/log
// in order to avoid recursion.

package util

import (
	"github.com/valyala/fasthttp"

	// The log package is used intentionally here instead of lib/log
	// in order to avoid recursion!
	"log"

	"net"
	"sync"
)

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
	log.Printf("couldn't determine external IP by dialing %q. The last error: %s", addrs, lastErr)
}

var externalIP = net.IPv4zero
var externalIPOnce sync.Once

// IPToUint32 converts IPv4 to uint32
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[3]) | (uint32(ip[2]) << 8) | (uint32(ip[1]) << 16) | (uint32(ip[0]) << 24)
}
