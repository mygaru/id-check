package util

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/valyala/bytebufferpool"

	"gitlab.adtelligent.com/common/shared/log"
)

func PrintAllFlags(w io.Writer) {
	fmt.Fprintf(w, "Flag values\n")
	flag.VisitAll(func(f *flag.Flag) {
		k := f.Name
		v := f.Value.String()
		if strings.Contains(k, "assword") || strings.Contains(k, "Key") {
			v = "hidden"
		}
		fmt.Fprintf(w, "\t%s=%q\n", k, v)
	})
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "\tbuildTime=%s\n", log.GetBuildTime())
	fmt.Fprintf(w, "\tbuildRevision=%s\n", log.GetBuildRevision())
	fmt.Fprintf(w, "\tgoVersion=%s\n", runtime.Version())
	fmt.Fprintf(w, "\tGOMAXPROCS=%d\n", runtime.GOMAXPROCS(-1))
	fmt.Fprintf(w, "\tNumCPU=%d\n", runtime.NumCPU())
}

func LogAllFlags() {
	w := bytebufferpool.Get()
	PrintAllFlags(w)
	log.Infof("%s", w.B)
	bytebufferpool.Put(w)
}

func PrintStatus(w io.Writer) {
	log.PrintLogStatus(w)
}

func AtomicCopyCounters(v interface{}) interface{} {
	srcV := reflect.ValueOf(v).Elem()
	dstP := reflect.New(srcV.Type())
	dstV := dstP.Elem()
	n := srcV.NumField()
	for i := 0; i < n; i++ {
		px := srcV.Field(i).Addr().Interface().(*uint64)
		x := atomic.LoadUint64(px)
		dstV.Field(i).SetUint(x)
	}
	return dstP.Interface()
}

func AtomicInc(p *uint64) {
	atomic.AddUint64(p, 1)
}

type StringSet map[string]struct{}

func NewStringSet(a []string) StringSet {
	result := make(map[string]struct{}, len(a))
	for _, s := range a {
		result[s] = struct{}{}
	}
	return result
}

func (ss StringSet) HasBytes(s []byte) bool {
	_, ok := ss[string(s)]
	return ok
}

func ParseIntList(str string) []int {
	if str == "" {
		return nil
	}
	var list []int
	for _, x := range strings.Split(str, ",") {
		n, err := strconv.Atoi(x)
		if err != nil {
			return nil
		}
		list = append(list, n)
	}
	return list
}

var TransparentGIFBody = func() []byte {
	// See http://stackoverflow.com/questions/9126105/blank-image-encoded-as-data-uri
	data, err := base64.StdEncoding.DecodeString("R0lGODlhAQABAID/AMDAwAAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==")
	if err != nil {
		log.Panicf("BUG: cannot decode 1px gif image: %s", err)
	}
	return data
}()

// FunctionName returns string name of passed function f
func FunctionName(f interface{}) string {
	result := strings.Split(runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name(), "/")
	return result[len(result)-2] + "/" + result[len(result)-1]
}
