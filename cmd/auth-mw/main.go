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
)

func main() {
	iniflags.Parse()
	util.LogAllFlags()

	log.Infof("Initializing...")
	// :'( empty
	log.Infof("Initialized.")

	mtls.Run(requestHandler)
}

var (
	Requests            = metric.NewCounter("authMWRequests")
	OptionsRequests     = metric.NewCounter("authMWOptionsRequests")
	UnsupportedRequests = metric.NewCounter("authMWUnsupportedRequests")
)
var writeLogUnsupportedError = flag.Bool("authMWWriteLogUnsupportedError", true, "Unsupported http path Logger")

func requestHandler(ctx *fasthttp.RequestCtx) {
	path := ctx.Path()

	Requests.Inc()

	if util.OptionsRequestHandler(ctx) {
		OptionsRequests.Inc()
		return
	}

	util.SetRequestOrigin(ctx)
	util.SetPermissionsPolicy(ctx)

	switch string(path) {
	case "/test", "/test/":
		_, _ = fmt.Fprintf(ctx, "Hello World!")
	case "/egg", "/egg/":
		_, _ = fmt.Fprintf(ctx, `
      Auth MW Server
----------------------------------
	    /\_/\
	  =( °w° )=
	    ) - (  //
	   (__ __)//
----------------------------------
      All rights reserved

Rev: %s / %s
MyGaru Inc

`, log.GetBuildRevision(), log.GetBuildVersion())

		if *writeLogUnsupportedError {
			ctx.Logger().Printf("Unsupported http path requested: %q", path)
		}

		ctx.Error("Unsupported http path", fasthttp.StatusNotFound)
		UnsupportedRequests.Inc()
	}
}
