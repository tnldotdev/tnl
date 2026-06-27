package controlv1

//go:generate oapi-codegen --config oapi-codegen.yaml ../../../api/control/v1/openapi.yaml
//go:generate node ../../../scripts/normalize-openapi-go.mjs openapi.gen.go
