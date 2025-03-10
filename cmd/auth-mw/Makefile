authmw:
	go build $(BUILD_OPTS) -o bin/auth-mw ./cmd/auth-mw

run-authmw: authmw
	./bin/auth-mw --config=../cfg/base.local.ini