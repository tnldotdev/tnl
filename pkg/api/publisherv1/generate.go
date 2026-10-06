package publisherv1

//go:generate oapi-codegen --config oapi-codegen.yaml ../../../api/publisher/v1/openapi.yaml
//go:generate node ../../../scripts/normalize-openapi-go.ts openapi.gen.go
