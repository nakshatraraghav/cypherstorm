build:
	@go build -o cli ./main.go 

run:
	@go run ./main.go

rm:
	@rm ./cli

key-gen:
	@openssl rand -out key.bin 32
	@echo "generated key saved to key.bin"
