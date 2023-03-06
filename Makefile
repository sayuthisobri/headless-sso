SOURCES := $(shell find . -type f -name '*.go')
BIN_PATH := $(shell go env GOBIN)
BIN := $(BIN_PATH)/headless-sso
FILES := $(BIN)

build: $(BIN)

$(BIN): $(SOURCES)
	go build -ldflags="-s -w" -o $(BIN)
	#upx --best --lzma $(BIN)

clean:
	-rm $(BIN)
