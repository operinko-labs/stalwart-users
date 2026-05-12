.PHONY: build test clean run

build:
	go build -o server ./cmd/server

test:
	go test ./...

clean:
	rm -f server

run: build
	./server

help:
	@echo "Available targets:"
	@echo "  build   - Build the server binary"
	@echo "  test    - Run tests"
	@echo "  clean   - Remove build artifacts"
	@echo "  run     - Build and run the server"
	@echo "  help    - Show this help message"
