.PHONY: all build build-server build-cli run-server run-cli test docker-up docker-cli docker-down clean

all: build

build: build-server build-cli

build-server:
	go build -o bin/server ./cmd/server

build-cli:
	go build -o bin/cli ./cmd/cli

run-server:
	go run ./cmd/server

run-cli:
	go run ./cmd/cli

test:
	go test -v -race ./...

docker-up:
	docker compose up -d postgres server

docker-cli:
	docker compose run --rm cli

docker-down:
	docker compose down

clean:
	rm -rf bin/ auth.db /tmp/.auth_cli_history
