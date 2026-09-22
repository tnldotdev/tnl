package config

//go:generate go run ./cmd/configgen
//go:generate node ../../scripts/generate-config-types.ts
//go:generate pnpm --dir ../.. exec oxfmt --write schema/v1.json internal/projectconfig/keys.gen.json packages/tnl/src/config.gen.ts
