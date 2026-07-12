.PHONY: build run test clean key-gen

build:
	@go build -o cypherstorm ./cmd/cypherstorm

run:
	@go run ./cmd/cypherstorm

test:
	@go test ./...

clean:
	@rm -f ./cypherstorm

key-gen:
	@openssl rand -out key.bin 32
	@chmod 600 key.bin
	@echo "generated 32-byte raw key at key.bin"
