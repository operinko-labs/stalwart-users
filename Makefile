.PHONY: build test clean run docker-build docker-push zip-ui

build:
	go build -o server ./cmd/server

test:
	go test ./...

clean:
	rm -f server

run: build
	./server

docker-build:
	docker build -t harbor.vaderrp.com/operinko-labs/stalwart-users:latest .

docker-push:
	docker push harbor.vaderrp.com/operinko-labs/stalwart-users:latest

zip-ui:
	cd ui && zip -r ../stalwart-users-ui.zip .

help:
	@echo "Available targets:"
	@echo "  build        - Build the server binary"
	@echo "  test         - Run tests"
	@echo "  clean        - Remove build artifacts"
	@echo "  run          - Build and run the server"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-push  - Push Docker image to Harbor"
	@echo "  zip-ui       - Create SPA zip for Stalwart"
	@echo "  help         - Show this help message"
