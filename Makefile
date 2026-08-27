# CareerPathDesk backend: every local command stays inside the named synthetic boundary.
.PHONY: prepare db-up db-down migrate seed test vet build verify

prepare:
	bash scripts/prepare-synthetic.sh

db-up: prepare
	docker compose -f deploy/docker/compose.synthetic.yaml up -d --wait

db-down:
	docker compose -f deploy/docker/compose.synthetic.yaml down

migrate: db-up
	bash scripts/with-synthetic-env.sh go run ./cmd/migrate

seed: migrate
	bash scripts/with-synthetic-env.sh go run ./cmd/seed-synthetic

test: db-up
	bash scripts/with-synthetic-env.sh go test ./... -count=1

vet:
	go vet ./...

build:
	install -d bin
	go build -trimpath -o bin/careerpathdesk-api ./cmd/api

verify: test vet build
	docker compose -f deploy/docker/compose.synthetic.yaml config --quiet
