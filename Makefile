.PHONY: gen lint test build compose-up compose-down smoke

gen:
	bash scripts/gen-proto.sh

lint:
	pnpm lint

test:
	pnpm test

build:
	pnpm build

compose-up:
	docker compose -f infra/compose/docker-compose.yml up -d

compose-down:
	docker compose -f infra/compose/docker-compose.yml down

smoke:
	docker compose -f infra/compose/docker-compose.yml config >/dev/null
