package main

import (
	"flag"
	"fmt"
	"github.com/mygaru/mygaru-authmw/pkg/mtls"
	"github.com/valyala/fasthttp"
	"github.com/vharitonsky/iniflags"
	"gitlab.adtelligent.com/common/shared/log"
	"gitlab.adtelligent.com/common/shared/metric"
	"gitlab.adtelligent.com/common/shared/util"
	"time"
)

var (
	forwardTrafficAddr = flag.String("authMWForwardTrafficAddr", "https://en.wikipedia.org", "Where you want the Auth MW to forward your request to...")
	forwardTimeout     = flag.Duration("authMWForwardTimeout", 5*time.Second, "How long to wait for forwarded request")
)

var (
	forwardRequests           = metric.NewCounter("authMWForwardRequests")
	forwardSuccessfulRequests = metric.NewCounter("authMWForwardSuccessfulRequests")
	forwardFailedRequests     = metric.NewCounter("authMWForwardFailedRequests")
)

func main() {
	iniflags.Parse()
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
		// todo set header the name of certificate

		forwardRequests.Inc()

		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		ctx.Request.CopyTo(req)

		ogQueryPArams := ctx.QueryArgs().String()

		if ogQueryPArams != "" {
			req.SetRequestURI(*forwardTrafficAddr + string(ctx.Path()) + "?" + ogQueryPArams)
		} else {
			req.SetRequestURI(*forwardTrafficAddr + string(ctx.Path()))
		}

		err := fasthttp.DoTimeout(req, resp, *forwardTimeout)
		if err != nil {
			forwardFailedRequests.Inc()
			ctx.Error(fmt.Sprintf("request failed: %s", err), fasthttp.StatusBadRequest)
		}

		ctx.SetStatusCode(resp.StatusCode())
		ctx.SetBody(resp.Body())

		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)

		forwardSuccessfulRequests.Inc()
	}
}
