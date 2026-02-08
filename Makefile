.PHONY: gen lint test test-unit test-integration test-e2e test-all verify build compose-up compose-down smoke health-report

gen:
	bash scripts/gen-proto.sh

lint:
	pnpm lint

test:
	pnpm test

test-unit:
	pnpm test:unit

test-integration:
	pnpm test:integration

test-e2e:
	pnpm test:e2e

test-all:
	pnpm test:all

verify:
	pnpm verify

build:
	pnpm build

compose-up:
	docker compose -f infra/compose/docker-compose.yml --env-file .env.example up -d --build

compose-down:
	docker compose -f infra/compose/docker-compose.yml --env-file .env.example down

smoke:
	docker compose -f infra/compose/docker-compose.yml config >/dev/null

health-report:
	pnpm health:report
