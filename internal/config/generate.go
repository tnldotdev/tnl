package config

//go:generate go run ./cmd/configgen
//go:generate node ../../scripts/generate-config-types.mjs
//go:generate pnpm --dir ../.. exec oxfmt --write schema/v1.json internal/tnlts/keys.gen.json packages/tnl/lib/config.d.ts
