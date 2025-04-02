package util

import (
	"github.com/valyala/fasthttp"
)

var crossdomainBody = []byte(`<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
    <site-control permitted-cross-domain-policies="all"/>
    <allow-access-from domain="*" secure="false"/>
</cross-domain-policy>`)

var crossdomainBodyCompressed = fasthttp.AppendGzipBytesLevel(nil, crossdomainBody, fasthttp.CompressBestCompression)

func CrossdomainHandler(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("text/xml")

	if ctx.Request.Header.HasAcceptEncoding("gzip") {
		ctx.Response.Header.Set("Content-Encoding", "gzip")
		ctx.SetBody(crossdomainBodyCompressed)
	} else {
		ctx.SetBody(crossdomainBody)
	}
}
