package main

import (
	"flag"
	"fmt"
	"github.com/mygaru/id-check/pkg/mtls"
	"github.com/valyala/fasthttp"
	"github.com/vharitonsky/iniflags"
	"log"
	"net/url"
	"time"
)

var (
	forwardTrafficAddr = flag.String("idCheckForwardTrafficAddr", "", "Where you want the Auth MW to forward your request to...")
	forwardTimeout     = flag.Duration("idCheckForwardTimeout", 5*time.Second, "How long to wait for forwarded request")
)

func main() {
	iniflags.Parse()
	logAllFlags()

	log.Printf("Initializing...")
	// :'( empty
	log.Printf("Initialized.")

	mtls.RunServer(requestHandler)
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())

	// todo do this only once on init
	parsed, err := url.Parse(*forwardTrafficAddr)
	if err != nil {
		log.Fatalf("Failed to parse forwardTrafficAddr: %v", err)
	}
	client := fasthttp.HostClient{Addr: parsed.Host}

	switch path {
	case "/test", "/test/":
		_, _ = fmt.Fprintf(ctx, "Hello World!")

	default:
		peerCert := ctx.TLSConnectionState().PeerCertificates[0]

		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		ctx.Request.CopyTo(req)

		req.Header.Set("X-ClientID", peerCert.Subject.CommonName)

		ogQueryPArams := ctx.QueryArgs().String()

		if ogQueryPArams != "" {
			req.SetRequestURI(*forwardTrafficAddr + string(ctx.Path()) + "?" + ogQueryPArams)
		} else {
			req.SetRequestURI(*forwardTrafficAddr + string(ctx.Path()))
		}

		if ctx.IsTLS() && parsed.Scheme == "http" {
			req.URI().SetScheme("http")
		}

		req.Header.SetHost(parsed.Host)

		defer func() {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}()

		err := client.DoTimeout(req, resp, *forwardTimeout)
		if err != nil {
			ctx.Error(fmt.Sprintf("request failed: %s", err), fasthttp.StatusBadRequest)
			return
		}

		ctx.SetStatusCode(resp.StatusCode())
		ctx.SetBody(resp.Body())
	}
}

func logAllFlags() {
	flag.VisitAll(func(f *flag.Flag) {
		log.Printf("FLAG: --%s=%s", f.Name, f.Value)
	})
}
