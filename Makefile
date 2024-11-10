build:
	@go build -o cli ./main.go 

run:
	@go run ./main.go

rm:
	@rm ./cli