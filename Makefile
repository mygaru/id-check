.PHONY: all clean format

VENDOR_GOPATH = GOPATH=`pwd`:`pwd`/vendor

format: format-fix-slow vet

format-fix-slow:
	gofmt -w -r 'true == a -> a' cmd/
	gofmt -w -r 'false == a -> !a' cmd/
	gofmt -w -r 'true != a -> !a' cmd/
	gofmt -w -r 'false != a -> a' cmd/
	gofmt -w -r '0 < a -> a > 0' cmd/
	gofmt -w -r '0 <= a -> a >= 0' cmd/
	gofmt -w -r 'a == true -> a' cmd/
	gofmt -w -r 'a == false -> !a' cmd/
	gofmt -w -r 'a != true -> !a' cmd/
	gofmt -w -r 'a != false -> a' cmd/
	gofmt -w -r '0 != len(a) -> len(a) > 0' cmd/
	gofmt -w -r '0 != a -> a != 0' cmd/
	gofmt -w -r '0 == a -> a == 0' cmd/
	gofmt -w -r '1 != a -> a != 1' cmd/
	gofmt -w -r '1 == a -> a == 1' cmd/
	gofmt -w -r '-1 != a -> a != -1' cmd/
	gofmt -w -r '-1 == a -> a == -1' cmd/
	gofmt -w -r 'nil != a -> a != nil' cmd/
	gofmt -w -r 'nil == a -> a == nil' cmd/
	gofmt -w -r 'ssp.a != b -> b != ssp.a' cmd/
	gofmt -w -r 'ssp.a == b -> b == ssp.a' cmd/
	gofmt -w -r 'adstats.a != b -> b != adstats.a' cmd/
	gofmt -w -r 'adstats.a == b -> b == adstats.a' cmd/
	gofmt -w -r 'bytes.Compare(a, b) != 0 -> !bytes.Equal(a, b)' cmd/
	gofmt -w -r 'bytes.Compare(a, b) == 0 -> bytes.Equal(a, b)' cmd/

vet:
	$(VENDOR_GOPATH) go vet -printfuncs=Infof,Errorf,Fatalf,Panicf -all -composites=false ./cmd/...

proto:
	protoc -I="." -I="pkg/base" -I="vendor"  --gofast_out="pkg/base" ./pkg/base/*.proto

include cmd/*/Makefile

BUILD_OPTS = -mod=vendor

generate-quicktemplate: install-qtc
	qtc -dir=./cmd

install-qtc:
	which qtc ||  go get github.com/valyala/quicktemplate/qtc