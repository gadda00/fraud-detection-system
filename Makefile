.PHONY: build run test docker clean fmt vet tidy

build:
	go build -o fraud-detection-system .

run:
	go run main.go

test:
	go test ./...

docker:
	docker build -t fraud-detection-system .

clean:
	rm -f fraud-detection-system

fmt:
	gofmt -s -w .

vet:
	go vet ./...

tidy:
	go mod tidy
