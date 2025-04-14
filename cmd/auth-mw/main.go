package main

import (
	"flag"
	"fmt"
	"github.com/mygaru/mygaru-authmw/pkg/mtls"
	"github.com/valyala/fasthttp"
	"gitlab.adtelligent.com/common/shared/log"
	"gitlab.adtelligent.com/common/shared/metric"
	"gitlab.adtelligent.com/common/shared/secretFlags"
	"gitlab.adtelligent.com/common/shared/util"
	"net/url"
	"time"
)

var (
	forwardTrafficAddr = flag.String("authMWForwardTrafficAddr", "", "Where you want the Auth MW to forward your request to...")
	forwardTimeout     = flag.Duration("authMWForwardTimeout", 5*time.Second, "How long to wait for forwarded request")
)

var (
	forwardRequests           = metric.NewCounter("authMWForwardRequests")
	forwardSuccessfulRequests = metric.NewCounter("authMWForwardSuccessfulRequests")
	forwardFailedRequests     = metric.NewCounter("authMWForwardFailedRequests")
)

func main() {
	secretFlags.Init()
	util.LogAllFlags()

	log.Infof("Initializing...")
	// :'( empty
	log.Infof("Initialized.")

	mtls.RunServer(requestHandler)
}

var (
	Requests        = metric.NewCounter("authMWRequests")
	OptionsRequests = metric.NewCounter("authMWOptionsRequests")
)

func requestHandler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())
	Requests.Inc()

	// todo do this only once on init
	parsed, err := url.Parse(*forwardTrafficAddr)
	if err != nil {
		log.Fatalf("Failed to parse forwardTrafficAddr: %v", err)
	}
	client := fasthttp.HostClient{Addr: parsed.Host}

	if util.OptionsRequestHandler(ctx) {
		OptionsRequests.Inc()
		return
	}

	util.SetRequestOrigin(ctx)
	util.SetPermissionsPolicy(ctx)

	switch path {
	case "/test", "/test/":
		_, _ = fmt.Fprintf(ctx, "Hello World!")

	default:
		peerCert := ctx.TLSConnectionState().PeerCertificates[0]

		forwardRequests.Inc()

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
			forwardFailedRequests.Inc()
			ctx.Error(fmt.Sprintf("request failed: %s", err), fasthttp.StatusBadRequest)
			return
		}

		ctx.SetStatusCode(resp.StatusCode())
		ctx.SetBody(resp.Body())

		forwardSuccessfulRequests.Inc()
	}
}
