// This package shouldn't use lib/* packages in order to prevent log recursion!

package baselog

import (
	"bytes"
	"fmt"
	"gitlab.adtelligent.com/common/shared/osexit"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sync"
)

const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Reset  = "\033[0m"
)

var (
	stdLogFlags     = log.LstdFlags | log.Lshortfile | log.LUTC
	outputCallDepth = 2

	tl        = &tailLogger{}
	logStream = io.MultiWriter(os.Stderr, tl)

	DebugLogger = log.New(logStream, Green+"DEBUG: "+Reset, stdLogFlags)
	InfoLogger  = log.New(logStream, Blue+"INFO: "+Reset, stdLogFlags)
	WarnLogger  = log.New(logStream, Yellow+"WARN: "+Reset, stdLogFlags)
	ErrorLogger = log.New(logStream, Red+"ERROR: "+Reset, stdLogFlags)
	FatalLogger = log.New(logStream, Red+"FATAL: "+Reset, log.LstdFlags|log.Llongfile|log.LUTC)
)

const maxTailSize = 16 * 1024

type tailLogger struct {
	lock sync.Mutex
	tail []byte
}

func (w *tailLogger) Write(p []byte) (int, error) {
	w.lock.Lock()
	w.tail = append(w.tail, p...)
	w.tail = trimTail(w.tail, maxTailSize)
	w.lock.Unlock()
	return len(p), nil
}

func PrintLogStatus(w io.Writer) {
	fmt.Fprintf(w, "Recent log messages\n---------------\n")
	w.Write(tl.tail)
	fmt.Fprintf(w, "\n---------------\nEnd of recent log messages\n")
}

func trimTail(b []byte, n int) []byte {
	for len(b) > n {
		pos := bytes.IndexByte(b, '\n')
		if pos < 0 {
			pos = len(b) - n - 1
		}
		b = b[pos+1:]
	}
	return b
}

func init() {
	osexit.Before(func(s os.Signal) {
		Infof("Obtained signal %q. Terminating...", s)
	})

}

func Debugf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	OutputDebug(1, s)
}

func OutputDebug(callDepth int, s string) {
	DebugLogger.Output(outputCallDepth+callDepth, s)
}

func Warnf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	OutputDebug(1, s)
}

func OutputWarn(callDepth int, s string) {
	WarnLogger.Output(outputCallDepth+callDepth, s)
}

func SuppressInfof(suppress bool) {
	if suppress {
		InfoLogger.SetOutput(ioutil.Discard)
	} else {
		InfoLogger.SetOutput(logStream)
	}
}

func Infof(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	OutputInfo(1, s)
}

func OutputInfo(callDepth int, s string) {
	InfoLogger.Output(outputCallDepth+callDepth, s)
}

func Errorf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	OutputError(1, s)
}

func OutputError(callDepth int, s string) {
	ErrorLogger.Output(outputCallDepth+callDepth, s)
}

func Fatalf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	OutputFatal(1, s)
}

func OutputFatal(callDepth int, s string) {
	FatalLogger.Output(outputCallDepth+callDepth, s)
	os.Exit(1)
}

func Panicf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	OutputPanic(1, s)
}

func OutputPanic(callDepth int, s string) {
	FatalLogger.Output(outputCallDepth+callDepth, s)
	panic(s)
}
