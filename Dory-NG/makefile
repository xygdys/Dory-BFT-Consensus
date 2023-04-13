all: build

.PHONY: build
build:
	go build -o ./build/start ./cmd/main

.PHONY: config
config:
	go run ./cmd/configMaker

.PHONY: clean
clean:
	rm build/*
