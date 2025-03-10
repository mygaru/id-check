package util

import (
	"bytes"
	"unicode"

	"github.com/valyala/fasthttp"
)

func GetUint32OrZero(args *fasthttp.Args, argName string) uint32 {
	v := args.GetUintOrZero(argName)
	if v >= (1 << 31) {
		v = 0
	}
	return uint32(v)
}

func requestOrigin(ctx *fasthttp.RequestCtx) []byte {
	// First, try extracting the origin from 'Origin' request header.
	origin := ctx.Request.Header.Peek("Origin")
	if len(origin) > 0 {
		return origin
	}

	// Extract the origin from referer.
	referer := ctx.Referer()
	n := bytes.Index(referer, strSlashSlash)
	if n < 0 {
		return strStar
	}
	m := bytes.IndexByte(referer[n+len(strSlashSlash):], '/')
	if m < 0 {
		return referer
	}
	return referer[:n+len(strSlashSlash)+m]
}

func SetRequestOrigin(ctx *fasthttp.RequestCtx) {
	origin := requestOrigin(ctx)

	h := &ctx.Response.Header
	h.SetBytesV("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Connection", "Keep-Alive")
}

func SetPermissionsPolicy(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Permissions-Policy", "browsing-topics=()")
}

func OptionsRequestHandler(ctx *fasthttp.RequestCtx) bool {
	if string(ctx.Method()) != "OPTIONS" {
		return false
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Response.Header.Set("Access-Control-Allow-Methods", "OPTIONS,GET,POST,PUT,DELETE")
	ctx.Response.Header.Set("Access-Control-Max-Age", "3600")
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "*")
	SetRequestOrigin(ctx)
	return true
}

// NormalizeDomain prunes scheme and 'www'
func NormalizeDomain(dst, src []byte) []byte {
	// copy lowercased domain name to dst
	for _, c := range src {
		cl := unicode.ToLower(rune(c))
		dst = append(dst, byte(cl))
	}

	bb := dst[len(dst)-len(src):]
	b := bb

	// strip scheme
	n := bytes.Index(b, strSlashSlash)
	if n >= 0 {
		b = b[n+len(strSlashSlash):]
	}

	// strip 'www' prefix
	b = bytes.TrimPrefix(b, strWWW)

	// trim uri after the domain
	n = bytes.IndexByte(b, '/')
	if n >= 0 {
		b = b[:n]
	}

	n = len(bb) - len(b)
	if n > 0 {
		copy(bb, b)
		dst = dst[:len(dst)-n]
	}

	return dst
}

var (
	strStar       = []byte("*")
	strSlashSlash = []byte("//")
	strWWW        = []byte("www.")
)
