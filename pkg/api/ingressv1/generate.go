package ingressv1

//go:generate oapi-codegen --config oapi-codegen.yaml ../../../api/ingress/v1/openapi.yaml
//go:generate node ../../../scripts/normalize-openapi-go.ts openapi.gen.go
