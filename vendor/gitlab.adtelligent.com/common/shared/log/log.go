// The package shouldn't import lib/* packages outside lib/log in order to avoid
// log recursion!

package log

import (
	"flag"
	"fmt"
	"gitlab.adtelligent.com/common/shared/log/internal/baselog"
	"gitlab.adtelligent.com/common/shared/log/internal/util"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	FATAL = "FATAL"
	ERROR = "ERROR"
	WARN  = "WARN"
	INFO  = "INFO"
	DEBUG = "DEBUG"
)

var logSeverity = map[string]uint8{DEBUG: 1, INFO: 2, WARN: 3, ERROR: 4}

var (
	clickhouseLogAppID = flag.String("clickhouseLogAppID", "", "AppID to be written clickhouse log. "+
		"The AppID may be used to distiguinsh between multiple apps running on the same server")
	logSuppressFasthttpWorkerpoolWarnings = flag.Bool("logSuppressFasthttpWorkerpoolWarnings", false,
		"Whether to suppress common fasthttp errors from fasthttp/workerpool.go that usually occur "+
			"when serving a lot of real-world traffic")
	logLevel = flag.String("logLevel", INFO, "Which log level to output. Will ignore anything lower")
)

func SuppressInfof(suppress bool) {
	baselog.SuppressInfof(suppress)
}

func PrintLogStatus(w io.Writer) {
	baselog.PrintLogStatus(w)
}

// FasthttpErrorLogger must be used by fasthttp.Server defined
// in lib/httpserver.
var FasthttpErrorLogger fasthttpErrorLogger

type fasthttpErrorLogger struct{}

func (cl fasthttpErrorLogger) Printf(format string, args ...interface{}) {
	if *logSuppressFasthttpWorkerpoolWarnings {
		_, file, _, ok := runtime.Caller(1)
		if ok && strings.HasSuffix(file, "fasthttp/workerpool.go") {
			return
		}
	}
	logOutput(4, baselog.OutputError, ERROR, format, args)
}

func Debugf(format string, args ...interface{}) {
	if logSeverity[*logLevel] > logSeverity[DEBUG] {
		return
	}
	logOutput(2, baselog.OutputDebug, DEBUG, format, args)
}

func Warnf(format string, args ...interface{}) {
	if logSeverity[*logLevel] > logSeverity[WARN] {
		return
	}
	logOutput(2, baselog.OutputWarn, WARN, format, args)
}

func Infof(format string, args ...interface{}) {
	if logSeverity[*logLevel] > logSeverity[INFO] {
		return
	}
	logOutput(2, baselog.OutputInfo, INFO, format, args)
}

func Errorf(format string, args ...interface{}) {
	logOutput(2, baselog.OutputError, ERROR, format, args)
}

func Fatalf(format string, args ...interface{}) {
	logOutput(2, baselog.OutputFatal, FATAL, format, args)
}

func Panicf(format string, args ...interface{}) {
	logOutput(2, baselog.OutputPanic, FATAL, format, args)
}

func logOutput(calldepth int, logFunc func(calldepth int, s string), level, format string, args []interface{}) {
	s := fmt.Sprintf(format, args...)

	if *clickhouseLogAddr != "" {
		initOnce.Do(logInit)

		_, file, line, ok := runtime.Caller(calldepth)
		if !ok {
			file = "???"
		}

		lr := logRecord{
			LogLevel:   level,
			AppName:    appName,
			AppIP:      appIP,
			AppID:      *clickhouseLogAppID,
			AppVersion: appVersion,
			AppFile:    file,
			AppLine:    uint32(line),
			LogMessage: s,
		}
		clickhouseLogBatcher.Push(lr.appendRow)
		if level == "FATAL" {
			// Sleep for a while before exitting, so the buffered
			// message could be sent to clickhouse.
			time.Sleep(clickhouseLogBatcher.MaxDelay + time.Second)
		}
	}
	logFunc(calldepth, s)
}

var initOnce sync.Once

func logInit() {
	appName = filepath.Base(os.Args[0])
	appVersion = fmt.Sprintf("%s %s", runtime.Version(), GetBuildRevision())
	appIP = util.IPToUint32(util.ExternalIP())

	clickhouseInit()
}

var (
	appName    string
	appVersion string
	appIP      uint32
)
