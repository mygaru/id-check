package util

import (
	"flag"
	"runtime/debug"

	"github.com/vharitonsky/iniflags"

	"gitlab.adtelligent.com/common/shared/log"
)

var gogc = flag.Int("gogc", 100, "GOGC value")

func init() {
	iniflags.OnFlagChange("gogc", func() {
		log.Infof("Updating GOGC to %d...", *gogc)
		debug.SetGCPercent(*gogc)
	})
}
