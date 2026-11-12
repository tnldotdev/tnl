package workload

import (
	"strings"
	"testing"
)

func TestNativeAcquisitionHasOneExplicitSourceAndNoFallbackFields(t *testing.T) {
	for _, test := range []struct {
		name string
		source Acquisition
		valid bool
	}{
		{"explicit file", Acquisition{Method:"token-file",TokenFile:"/run/identity.jwt"},true},
		{"relative file must be resolved by caller", Acquisition{Method:"token-file",TokenFile:"identity.jwt"},false},
		{"missing file", Acquisition{Method:"token-file"},false},
		{"file and environment", Acquisition{Method:"token-file",TokenFile:"/run/identity.jwt",TokenEnv:"TOKEN"},false},
		{"file with irrelevant audience", Acquisition{Method:"token-file",TokenFile:"/run/identity.jwt",Audience:"not-a-source-selector"},false},
		{"file newline", Acquisition{Method:"token-file",TokenFile:"/run/identity\njwt"},false},
		{"file nul", Acquisition{Method:"token-file",TokenFile:"/run/identity\x00jwt"},false},
		{"oversized file", Acquisition{Method:"token-file",TokenFile:"/"+strings.Repeat("a",4096)},false},
		{"explicit environment", Acquisition{Method:"token-env",TokenEnv:"JOB_ID_TOKEN"},true},
		{"maximum environment name", Acquisition{Method:"token-env",TokenEnv:strings.Repeat("A",128)},true},
		{"oversized environment name", Acquisition{Method:"token-env",TokenEnv:strings.Repeat("A",129)},false},
		{"missing environment", Acquisition{Method:"token-env"},false},
		{"invalid environment", Acquisition{Method:"token-env",TokenEnv:"JOB=TOKEN"},false},
		{"environment and file", Acquisition{Method:"token-env",TokenEnv:"JOB_ID_TOKEN",TokenFile:"/run/identity.jwt"},false},
		{"environment with irrelevant audience", Acquisition{Method:"token-env",TokenEnv:"JOB_ID_TOKEN",Audience:"audience"},false},
		{"GitHub", Acquisition{Method:"github-actions",Audience:"https://control.example"},true},
		{"GitHub explicit provider audience", Acquisition{Method:"github-actions",Audience:"approved-audience"},true},
		{"GitHub file fallback", Acquisition{Method:"github-actions",Audience:"https://control.example",TokenFile:"/run/fallback.jwt"},false},
		{"GitHub environment fallback", Acquisition{Method:"github-actions",Audience:"https://control.example",TokenEnv:"TOKEN"},false},
		{"Vercel", Acquisition{Method:"vercel-oidc"},true},
		{"Vercel invented audience", Acquisition{Method:"vercel-oidc",Audience:"unexpected"},false},
		{"Vercel file override must be explicit", Acquisition{Method:"vercel-oidc",TokenFile:"/run/override.jwt"},false},
		{"Fly", Acquisition{Method:"fly-machine-api",Audience:"https://fly.io/approved-app"},true},
		{"Google", Acquisition{Method:"google-metadata",Audience:"approved-audience"},true},
		{"Google missing audience", Acquisition{Method:"google-metadata"},false},
		{"wildcard audience", Acquisition{Method:"google-metadata",Audience:"audience-*"},false},
		{"unknown method", Acquisition{Method:"other"},false},
		{"callback is a separate shared reply lane", Acquisition{Method:"callback"},false},
	} {t.Run(test.name,func(t *testing.T){
		if err:=ValidateAcquisition(test.source);(err==nil)!=test.valid{t.Fatalf("explicit source validation changed: %v",err)}
	})}
}
