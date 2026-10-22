package project

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestTypeScriptServiceDiscoveryAndPlacementValidation(t *testing.T) {
	for _, test := range []struct {
		name, source string
		valid        bool
	}{
		{"app default", `{services:{web:{}}}`, true},
		{"removed HTTP publisher pool", `{services:{web:{publisherPool:true}}}`, false},
		{"removed private publisher pool", `{services:{db:{publisherPool:true,protocol:"tcp",target:{type:"address",address:5432}}}}`, false},
		{"remote group", `{publisherGroups:{cloud:{description:"database"}},services:{db:{publisherGroup:"cloud",protocol:"postgres",target:{type:"address",address:"db.internal:5432"},access:{team:true}}}}`, true},
		{"no root pool default", `{publisherPool:true,services:{web:{}}}`, false},
		{"no public URL pool", `{services:{web:{publicURL:{publisherPool:true,access:"anonymous"}}}}`, false},
		{"no duplicated public URL name", `{services:{web:{name:"site",publicURL:{name:"other",access:"anonymous"}}}}`, false},
		{"removed directory", `{services:{web:{directory:"apps/web"}}}`, false},
		{"removed publisher placement", `{publisher:{type:"compose",service:"publisher"},services:{web:{target:{type:"app"}}}}`, false},
		{"mixed public defaults", `{publicURL:{access:"anonymous"},services:{web:{},db:{protocol:"tcp",target:{type:"address",address:5432}}}}`, true},
		{"private TLS", `{services:{db:{protocol:"mysql",target:{type:"address",address:"db.internal:3306",tls:{serverName:"db.internal",caFile:"./ca.pem"}}}}}`, true},
		{"Postgres pass-through", `{services:{db:{protocol:"postgres",target:{type:"address",address:"db.internal:5432"}}}}`, true},
		{"bad CA URL", `{services:{db:{protocol:"postgres",target:{type:"address",address:5432},tls:{ca:"http://certs.example.com/ca.pem"}}}}`, false},
		{"compose", `{services:{web:{target:{type:"compose",project:"shop",file:"compose.yml",service:"web",port:3000}}}}`, true},
		{"docker", `{services:{cache:{protocol:"tcp",target:{type:"docker",container:"shop-cache",port:6379}}}}`, true},
		{"explicit private name", `{services:{orders:{protocol:"tcp",name:"database",target:{type:"address",address:5432}}}}`, true},
		{"conflicting private names", `{services:{orders:{protocol:"tcp",target:{type:"address",address:5432}},database:{protocol:"tcp",name:"orders",target:{type:"address",address:3306}}}}`, false},
		{"service public URL", `{services:{db:{protocol:"tcp",publicURL:{hostname:"db.example"},target:{type:"address",address:5432}}}}`, false},
		{"inspection", `{inspection:{mode:"summary",retention:"24h",maxBytes:"64MiB"}}`, true},
		{"traffic", `{publicURL:{limits:{traffic:{connections:8,rate:5,ratePer:"1s",burst:10,uploadBytes:1048576,downloadBytes:2097152,totalUploadBytes:4194304}}}}`, true},
		{"old root", `{publish:{target:3000}}`, false},
		{"old readiness", `{readiness:{path:"/"}}`, false},
		{"old service", `{services:{web:{publish:{target:3000}}}}`, false},
		{"old limits", `{publicURL:{limits:{requests:3}}}`, false},
		{"visitor TLS", `{services:{web:{target:{type:"address",address:3000,tls:{passthrough:true}}}}}`, false},
		{"target variant", `{services:{web:{target:{type:"app",address:3000}}}}`, false},
		{"Docker filter", `{services:{db:{target:{type:"docker",container:"label=app",port:5432}}}}`, false},
		{"Compose path", `{services:{web:{target:{type:"compose",project:"shop",file:"../compose.yml",service:"web",port:3000}}}}`, false},
		{"retention bound", `{inspection:{retention:"721h"}}`, false},
		{"storage bound", `{inspection:{maxBytes:"2GiB"}}`, false},
		{"integer bound", `{publicURL:{limits:{tcp:{total:9007199254740992}}}}`, false},
		{"removed publisher port", `{publisher:{type:"compose",service:"publisher",port:8765}}`, false},
		{"removed publisher root", `{publisher:{type:"compose",service:"publisher",projectRoot:"/project"}}`, false},
		{"removed publisher descriptors", `{publisher:{type:"compose",service:"publisher",appEndpoints:{web:"/run/web.json"}}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			file := filepath.Join(root, "tnl.config.ts")
			if err := os.WriteFile(file, []byte("export default "+test.source), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadTypeScript(t.Context(), file, root, Worktree{Root: root})
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, want %v: %v", err == nil, test.valid, err)
			}
		})
	}
}

func TestComposeFileStaysWithinProjectAndMustExist(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "compose.yml")
	if err := os.WriteFile(outside, []byte("services: {}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.yml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "compose.yml"), []byte("services: {}"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		file  string
		valid bool
	}{{"compose.yml", true}, {"escape.yml", false}, {"missing.yml", false}, {".", false}} {
		project, service, port := "shop", "db", 5432
		p := Project{Root: root, Config: config.TNL{Services: config.Services{"db": {Target: &config.ServiceTarget{Type: "compose", Project: &project, File: &test.file, Service: &service, Port: &port}}}}}
		file, err := p.ComposeFile("db")
		if (err == nil) != test.valid {
			t.Fatalf("%s valid=%v: %v", test.file, err == nil, err)
		}
		if test.valid && !filepath.IsAbs(file) {
			t.Fatal("Compose file is not absolute")
		}
	}
}

func TestComposeDefaultsUseSelectedWorktreeAndProject(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "compose.yaml"), []byte("services: {}"), 0600); err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	service, protocol, port := "db", "tcp", 5432
	project := Project{Root: root, Worktree: Worktree{Label: WorktreeLabel{FullLabel: "shop-worktree-a12345"}}, Config: config.TNL{
		Services: config.Services{"db": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "compose", Service: &service, Port: &port}}},
	}}
	file, err := project.ComposeFile("db")
	if err != nil || file != filepath.Join(canonicalRoot, "compose.yaml") {
		t.Fatalf("target Compose file = %q: %v", file, err)
	}
	name, err := project.ComposeProject("db")
	if err != nil || name != "shop-worktree-a12345" {
		t.Fatalf("derived Compose project = %q: %v", name, err)
	}
	project.Worktree.Label.FullLabel = "shop-worktree-b67890"
	other, err := project.ComposeProject("db")
	if err != nil || other == name {
		t.Fatalf("second worktree reused Compose project %q: %v", other, err)
	}
	selected := "existing-project"
	target := project.Config.Services["db"]
	target.Target.Project = &selected
	project.Config.Services["db"] = target
	if explicit, err := project.ComposeProject("db"); err != nil || explicit != selected {
		t.Fatalf("explicit Compose project = %q: %v", explicit, err)
	}
}

func TestResolveFillsComposeTargetDefaultsPerProject(t *testing.T) {
	var names []string
	for range 2 {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "compose.yml"), []byte("services: {}"), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "tnl.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"services":{"db":{"protocol":"tcp","target":{"type":"compose","service":"db","port":5432}}}}}`), 0600); err != nil {
			t.Fatal(err)
		}
		project, err := Resolve(t.Context(), Selection{Path: path}, root, [32]byte{})
		if err != nil {
			t.Fatal(err)
		}
		target := project.Config.Services["db"].Target
		if got := config.ServiceName("db", project.Config.Services["db"]); got != "db" {
			t.Fatalf("default service name = %q", got)
		}
		if target.Project == nil || target.File == nil || *target.Project != project.Worktree.Label.FullLabel || *target.File != "compose.yml" {
			t.Fatalf("Compose target defaults = %+v", target)
		}
		names = append(names, *target.Project)
		static, err := project.StaticMap()
		if err != nil {
			t.Fatal(err)
		}
		declaration := static["services"].(map[string]any)["db"].(map[string]any)["target"].(map[string]any)
		if _, exists := declaration["project"]; exists {
			t.Fatal("static API shape contains a worktree Compose project")
		}
		if _, exists := declaration["file"]; exists {
			t.Fatal("static API shape contains a discovered Compose file")
		}
	}
	if names[0] == names[1] {
		t.Fatalf("distinct project roots selected the same Compose project %q", names[0])
	}
}

func TestEffectiveServiceKeepsAppAndAddressTargetsIndependent(t *testing.T) {
	protocol := "postgres"
	target := config.Target("db.internal:5432")
	ca := "ca.pem"
	p := Project{Config: config.TNL{Services: config.Services{
		"web": {}, "db": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "address", Address: &target, TLS: &config.TargetTLS{CAFile: &ca}}},
	}}}
	if err := config.ValidateTNL(p.Config); err != nil {
		t.Fatalf("mixed HTTP and private TCP services: %v", err)
	}
	web, err := p.EffectiveService("web")
	if err != nil {
		t.Fatal(err)
	}
	db, err := p.EffectiveService("db")
	if err != nil {
		t.Fatal(err)
	}
	if config.ServiceProtocol(web.Publish) != "http" || web.Publish.Target != nil || web.Publish.TargetCAFile != nil || config.ServiceProtocol(db.Publish) != "postgres" || db.Publish.Target != &target || db.Publish.TargetTLS == nil || !*db.Publish.TargetTLS {
		t.Fatal("service resolution mixed app and address settings")
	}
}

func TestAppServiceRequiresExplicitNameForMultipleApps(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "apps", "web", "src")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	address := config.Target("4000")
	p := Project{Root: root, Config: config.TNL{Services: config.Services{
		"web": {}, "manual": {Target: &config.ServiceTarget{Type: "address", Address: &address}},
	}}}
	if name, err := p.AppService(nested, ""); err != nil || name != "web" {
		t.Fatalf("inferred app=%s: %v", name, err)
	}
	if _, err := p.AppService(nested, "manual"); err == nil {
		t.Fatal("manual target accepted an app registration")
	}
	p.Config.Services["other"] = config.Service{}
	if _, err := p.AppService(nested, ""); err == nil {
		t.Fatal("multiple apps were inferred")
	}
	if name, err := p.AppService(nested, "web"); err != nil || name != "web" {
		t.Fatalf("explicit app=%s: %v", name, err)
	}
	if _, err := p.AppService(t.TempDir(), "web"); err == nil {
		t.Fatal("app outside project was accepted")
	}
}

func TestResolvePublishNormalizesDiscoveryAndProjectCAPaths(t *testing.T) {
	root := t.TempDir()
	project, service, file, port, ca := "shop", "web", "compose.yml", 3000, "certs/ca.pem"
	p := Project{Root: root, Config: config.TNL{Services: config.Services{
		"web": {Tunnel: &config.Tunnel{}, Target: &config.ServiceTarget{Type: "compose", Project: &project, Service: &service, File: &file, Port: &port, TLS: &config.TargetTLS{CAFile: &ca}}},
	}}}
	resolved, err := p.ResolvePublish("web", "127.0.0.1:49152")
	if err != nil {
		t.Fatal(err)
	}
	if string(*resolved.Target) != "https://127.0.0.1:49152" || *resolved.TargetCAFile != filepath.Join(root, ca) || resolved.TargetTLS == nil || !*resolved.TargetTLS {
		t.Fatalf("publication=%+v", resolved)
	}
	if _, err := p.ResolvePublish("web", ""); err == nil {
		t.Fatal("missing discovery result was accepted")
	}
	if ca != "certs/ca.pem" {
		t.Fatal("resolving a target changed configuration")
	}
}

func TestPublicHTTPSUpstreamTLSNameSurvivesConfigurationResolution(t *testing.T) {
	for _, source := range []string{
		`{services:{web:{publicURL:{},protocol:"http",target:{type:"address",address:"https://127.0.0.1:3000",tls:{serverName:"web.internal",caFile:"certs/ca.pem"}}}}}`,
		`{services:{web:{publicURL:{},target:{type:"compose",project:"shop",file:"compose.yml",service:"web",port:3000,tls:{serverName:"web.internal",caFile:"certs/ca.pem"}}}}}`,
	} {
		root := t.TempDir()
		file := filepath.Join(root, "tnl.config.ts")
		if err := os.WriteFile(file, []byte("export default "+source), 0600); err != nil {
			t.Fatal(err)
		}
		value, err := loadTypeScript(t.Context(), file, root, Worktree{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		project := Project{Root: root, Config: value}
		effective, err := project.EffectiveService("web")
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := project.ResolvePublish("web", "127.0.0.1:3000")
		if err != nil {
			t.Fatal(err)
		}
		if effective.Publish.TargetTLSName == nil || *effective.Publish.TargetTLSName != "web.internal" || resolved.TargetTLSName == nil || *resolved.TargetTLSName != "web.internal" || resolved.TargetTLS == nil || !*resolved.TargetTLS || resolved.Target == nil || string(*resolved.Target) != "https://127.0.0.1:3000" || resolved.TargetCAFile == nil || *resolved.TargetCAFile != filepath.Join(root, "certs/ca.pem") {
			t.Fatalf("HTTP private TLS settings were lost: effective=%+v resolved=%+v", effective.Publish, resolved)
		}
	}
}
