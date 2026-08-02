package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
)

const runManifestSchemaVersion = 1

type runCommand struct {
	Suite        string `name:"suite" env:"BENCH_SUITE" required:"" help:"Explicit suite to execute: smoke, scout, or confirm."`
	ProfileFile  string `name:"profile" env:"BENCH_PROFILE" default:"benchmarks/suites/fly-production.json" type:"path" help:"Production-candidate benchmark profile."`
	Routes       int    `name:"routes" env:"BENCH_ROUTES" help:"Route count override; required for confirm."`
	FreshRate    int    `name:"fresh-connections-per-second" env:"BENCH_FRESH_CONNECTIONS_PER_SECOND" help:"Fresh visitor connection rate override; required for confirm."`
	HeldStreams  int    `name:"held-streams" env:"BENCH_HELD_STREAMS" help:"Held-open stream override; required for confirm."`
	Repetitions  int    `name:"repetitions" env:"BENCH_REPETITIONS" help:"Repetition override."`
	Approved     string `name:"approved" env:"BENCH_APPROVED" required:"" help:"Paid-resource approval; must be exactly 1."`
	FlyOrg       string `name:"fly-org" env:"BENCH_FLY_ORG" required:"" help:"Fly organization slug."`
	FlyBinary    string `name:"fly-binary" env:"BENCH_FLY_BINARY" default:"flyctl" help:"Fly CLI executable."`
	ParentDomain string `name:"parent-domain" env:"BENCH_PARENT_DOMAIN" required:"" help:"Existing public Route 53 parent domain."`
	ParentZoneID string `name:"parent-zone-id" env:"BENCH_PARENT_ZONE_ID" required:"" help:"Bare Route 53 hosted-zone ID for the parent domain."`
	ACMEEmail    string `name:"acme-email" env:"BENCH_ACME_EMAIL" required:"" help:"ACME account contact email."`
	ResultsRoot  string `name:"results-root" env:"BENCH_RESULTS_ROOT" default:"bench-results" type:"path" help:"Directory for run manifests and results."`
}

type cleanupCommand struct {
	RunDirectory string `name:"run" env:"BENCH_RUN" type:"path" required:"" help:"Interrupted benchmark run directory."`
	FlyBinary    string `name:"fly-binary" env:"BENCH_FLY_BINARY" default:"flyctl" help:"Fly CLI executable."`
}

type runManifest struct {
	SchemaVersion int                     `json:"schema_version"`
	RunID         string                  `json:"run_id"`
	Status        string                  `json:"status"`
	CreatedAt     time.Time               `json:"created_at"`
	UpdatedAt     time.Time               `json:"updated_at"`
	FlyOrg        string                  `json:"fly_org"`
	Region        string                  `json:"region"`
	ParentDomain  string                  `json:"parent_domain"`
	ParentZoneID  string                  `json:"parent_zone_id"`
	ServerDomain  string                  `json:"server_domain"`
	ManagedDomain string                  `json:"managed_domain"`
	Image         string                  `json:"image,omitempty"`
	Apps          []manifestApp           `json:"apps"`
	Zones         []manifestZone          `json:"zones"`
	Addresses     map[string]flyAddresses `json:"addresses,omitempty"`
	Volume        *manifestVolume         `json:"volume,omitempty"`
	Cells         []manifestCell          `json:"cells,omitempty"`
	CleanupErrors []string                `json:"cleanup_errors,omitempty"`
}

type manifestApp struct {
	Role    string `json:"role"`
	Name    string `json:"name"`
	Removed bool   `json:"removed,omitempty"`
}

type manifestZone struct {
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	ID           string   `json:"id"`
	ParentName   string   `json:"parent_name"`
	ParentZoneID string   `json:"parent_zone_id"`
	NameServers  []string `json:"name_servers"`
	Delegated    bool     `json:"delegated"`
	Removed      bool     `json:"removed,omitempty"`
}

type manifestVolume struct {
	App     string `json:"app"`
	ID      string `json:"id"`
	Removed bool   `json:"removed,omitempty"`
}

type manifestCell struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	ResultRows  int       `json:"result_rows"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type runSecrets struct {
	LoginToken       string
	ClusterSecret    string
	StorageKey       string
	DatabasePassword string
	CoordinatorToken string
	AWSAccessKeyID   string
	AWSSecretKey     string
	AWSSessionToken  string
}

type provisionedBenchmark struct {
	apps          map[string]string
	addresses     map[string]flyAddresses
	metricsURLs   []string
	image         string
	secrets       runSecrets
	serverDomain  string
	managedDomain string
}

func (c runCommand) Validate() error {
	if c.Approved != "1" {
		return errors.New("BENCH_APPROVED must be exactly 1; planning does not grant execution approval")
	}
	if value, found := os.LookupEnv("BENCH_SUITE"); !found || value == "" || value != c.Suite {
		return errors.New("execution requires an explicit BENCH_SUITE environment variable")
	}
	canonical, err := naming.CanonicalizeHostname(c.ParentDomain)
	if err != nil || canonical != c.ParentDomain {
		return errors.New("BENCH_PARENT_DOMAIN must be a canonical hostname")
	}
	if c.ParentZoneID == "" || canonicalZoneID(c.ParentZoneID) != c.ParentZoneID || strings.ContainsAny(c.ParentZoneID, " /\t\r\n") {
		return errors.New("BENCH_PARENT_ZONE_ID must be a canonical bare hosted-zone ID")
	}
	address, err := mail.ParseAddress(c.ACMEEmail)
	if err != nil || address.Address != c.ACMEEmail {
		return errors.New("BENCH_ACME_EMAIL must be a canonical email address")
	}
	return nil
}

func (c runCommand) run(ctx context.Context, stdout io.Writer) (retErr error) {
	if err := c.Validate(); err != nil {
		return err
	}
	plan, err := (planCommand{
		Suite: c.Suite, ProfileFile: c.ProfileFile, Routes: c.Routes, FreshRate: c.FreshRate,
		HeldStreams: c.HeldStreams, Repetitions: c.Repetitions, Format: "json",
	}).build(time.Now())
	if err != nil {
		return err
	}
	runID, err := newRunID(time.Now().UTC())
	if err != nil {
		return err
	}
	runDirectory := filepath.Join(c.ResultsRoot, runID)
	if err := os.MkdirAll(runDirectory, 0o700); err != nil {
		return fmt.Errorf("create benchmark run directory: %w", err)
	}
	manifest := runManifest{
		SchemaVersion: runManifestSchemaVersion, RunID: runID, Status: "provisioning",
		CreatedAt: time.Now().UTC(), FlyOrg: c.FlyOrg, Region: plan.Region,
		ParentDomain: c.ParentDomain, ParentZoneID: c.ParentZoneID,
		ServerDomain: runID + "." + c.ParentDomain, ManagedDomain: "routes." + runID + "." + c.ParentDomain,
		Addresses: make(map[string]flyAddresses),
	}
	manifestPath := filepath.Join(runDirectory, "manifest.json")
	if err := saveManifest(manifestPath, &manifest); err != nil {
		return err
	}
	if err := writeIndentedJSON(filepath.Join(runDirectory, "plan.json"), plan); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Run: %s\nDirectory: %s\n", runID, runDirectory)

	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"))
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	awsCredentials, err := awsConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("retrieve AWS credentials: %w", err)
	}
	dns := benchmarkDNS{client: route53.NewFromConfig(awsConfig)}
	fly := flyPlatform{binary: c.FlyBinary, org: c.FlyOrg, region: plan.Region, executor: osCommandExecutor{}}
	cleanupNeeded := true
	defer func() {
		if !cleanupNeeded {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		if cleanupErr := cleanupRun(cleanupCtx, fly, dns, manifestPath, &manifest); cleanupErr != nil {
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()
	if err := fly.preflight(ctx); err != nil {
		return err
	}
	if err := dns.validateParentZone(ctx, c.ParentZoneID, c.ParentDomain); err != nil {
		return err
	}
	secrets, err := generateRunSecrets()
	if err != nil {
		return err
	}
	secrets.AWSAccessKeyID = awsCredentials.AccessKeyID
	secrets.AWSSecretKey = awsCredentials.SecretAccessKey
	secrets.AWSSessionToken = awsCredentials.SessionToken
	benchmark, err := provisionBenchmark(ctx, stdout, fly, dns, plan, c, manifestPath, &manifest, secrets)
	if err != nil {
		return err
	}
	manifest.Status = "running"
	if err := saveManifest(manifestPath, &manifest); err != nil {
		return err
	}
	resultsPath := filepath.Join(runDirectory, "results.jsonl")
	for _, cell := range plan.Cells {
		fmt.Fprintf(stdout, "Cell: %s\n", cell.ID)
		status, rows, err := executeCell(ctx, fly, benchmark, plan, cell, resultsPath)
		manifest.Cells = append(manifest.Cells, manifestCell{
			ID: cell.ID, Status: status, ResultRows: rows, CompletedAt: time.Now().UTC(),
		})
		if saveErr := saveManifest(manifestPath, &manifest); saveErr != nil {
			return errors.Join(err, saveErr)
		}
		if err != nil {
			return err
		}
	}
	manifest.Status = "reporting"
	if err := saveManifest(manifestPath, &manifest); err != nil {
		return err
	}
	if err := (reportCommand{RunDirectory: runDirectory}).run(stdout); err != nil {
		return err
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cleanupCancel()
	if err := cleanupRun(cleanupCtx, fly, dns, manifestPath, &manifest); err != nil {
		return err
	}
	cleanupNeeded = false
	fmt.Fprintln(stdout, "Cleanup: complete")
	return nil
}

func (c cleanupCommand) run(ctx context.Context, stdout io.Writer) error {
	manifestPath := filepath.Join(c.RunDirectory, "manifest.json")
	manifest, err := loadManifest(manifestPath)
	if err != nil {
		return err
	}
	if err := validateManifestResources(manifest); err != nil {
		return err
	}
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"))
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	fly := flyPlatform{binary: c.FlyBinary, org: manifest.FlyOrg, region: manifest.Region, executor: osCommandExecutor{}}
	dns := benchmarkDNS{client: route53.NewFromConfig(awsConfig)}
	if err := cleanupRun(ctx, fly, dns, manifestPath, &manifest); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Cleanup: complete")
	return nil
}

func provisionBenchmark(
	ctx context.Context,
	stdout io.Writer,
	fly flyPlatform,
	dns benchmarkDNS,
	plan benchmarkPlan,
	command runCommand,
	manifestPath string,
	manifest *runManifest,
	secrets runSecrets,
) (provisionedBenchmark, error) {
	serverZone, err := dns.createZone(ctx, manifest.ServerDomain, manifest.RunID+"-server")
	if err != nil {
		return provisionedBenchmark{}, err
	}
	serverZone.Kind, serverZone.ParentName, serverZone.ParentZoneID = "server", manifest.ParentDomain, manifest.ParentZoneID
	manifest.Zones = append(manifest.Zones, serverZone)
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}
	if err := dns.upsertDelegation(ctx, serverZone.ParentZoneID, serverZone); err != nil {
		return provisionedBenchmark{}, err
	}
	manifest.Zones[0].Delegated = true
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}
	managedZone, err := dns.createZone(ctx, manifest.ManagedDomain, manifest.RunID+"-managed")
	if err != nil {
		return provisionedBenchmark{}, err
	}
	managedZone.Kind, managedZone.ParentName, managedZone.ParentZoneID = "managed", serverZone.Name, serverZone.ID
	manifest.Zones = append(manifest.Zones, managedZone)
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}
	if err := dns.upsertDelegation(ctx, managedZone.ParentZoneID, managedZone); err != nil {
		return provisionedBenchmark{}, err
	}
	manifest.Zones[1].Delegated = true
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}

	apps := benchmarkAppNames(manifest.RunID)
	for _, role := range []string{"postgres", "control", "ingress", "relay-a", "relay-b", "coordinator", "publisher", "load"} {
		if err := fly.createApp(ctx, apps[role]); err != nil {
			return provisionedBenchmark{}, err
		}
		manifest.Apps = append(manifest.Apps, manifestApp{Role: role, Name: apps[role]})
		if err := saveManifest(manifestPath, manifest); err != nil {
			return provisionedBenchmark{}, err
		}
	}
	image, err := fly.buildImage(ctx, apps["control"], manifest.RunID)
	if err != nil {
		return provisionedBenchmark{}, err
	}
	manifest.Image = image
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}

	for _, role := range []string{"control", "ingress", "relay-a", "relay-b"} {
		addresses, err := fly.allocateAddresses(ctx, apps[role], false)
		if err != nil {
			return provisionedBenchmark{}, err
		}
		manifest.Addresses[role] = addresses
		if err := saveManifest(manifestPath, manifest); err != nil {
			return provisionedBenchmark{}, err
		}
	}
	coordinatorAddresses, err := fly.allocateAddresses(ctx, apps["coordinator"], true)
	if err != nil {
		return provisionedBenchmark{}, err
	}
	manifest.Addresses["coordinator"] = coordinatorAddresses
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}
	for role, hostname := range map[string]string{
		"control": "control." + manifest.ServerDomain, "ingress": "ingress." + manifest.ServerDomain,
		"relay-a": "relay-a." + manifest.ServerDomain, "relay-b": "relay-b." + manifest.ServerDomain,
	} {
		addresses := manifest.Addresses[role]
		if err := dns.upsertAddress(ctx, serverZone.ID, hostname, addresses.IPv4, addresses.IPv6); err != nil {
			return provisionedBenchmark{}, err
		}
	}

	databaseURL := "postgres://tnl:" + secrets.DatabasePassword + "@" + apps["postgres"] + ".internal:5432/tnl?sslmode=disable"
	appSecrets := map[string]map[string]string{
		"postgres": {"POSTGRES_PASSWORD": secrets.DatabasePassword},
		"control": {
			"TNLD_DATABASE_URL": databaseURL, "TNLD_DATABASE_DIRECT_URL": databaseURL,
			"TNLD_LOGIN_TOKEN": secrets.LoginToken, "TNLD_CLUSTER_SECRET": secrets.ClusterSecret,
			"TNLD_STORAGE_KEY": secrets.StorageKey, "AWS_ACCESS_KEY_ID": secrets.AWSAccessKeyID,
			"AWS_SECRET_ACCESS_KEY": secrets.AWSSecretKey, "AWS_SESSION_TOKEN": secrets.AWSSessionToken,
		},
		"ingress":     {"TNLD_CLUSTER_SECRET": secrets.ClusterSecret},
		"relay-a":     {"TNLD_CLUSTER_SECRET": secrets.ClusterSecret},
		"relay-b":     {"TNLD_CLUSTER_SECRET": secrets.ClusterSecret},
		"coordinator": {"TNL_BENCH_COORDINATOR_TOKEN": secrets.CoordinatorToken},
		"publisher": {
			"TNL_BENCH_COORDINATOR_TOKEN": secrets.CoordinatorToken, "TNL_BENCH_LOGIN_TOKEN": secrets.LoginToken,
		},
		"load": {"TNL_BENCH_COORDINATOR_TOKEN": secrets.CoordinatorToken},
	}
	for role, values := range appSecrets {
		if err := fly.setSecrets(ctx, apps[role], values); err != nil {
			return provisionedBenchmark{}, err
		}
	}
	volumeID, err := fly.createVolume(ctx, apps["postgres"], "postgres_data", 1)
	if err != nil {
		return provisionedBenchmark{}, err
	}
	manifest.Volume = &manifestVolume{App: apps["postgres"], ID: volumeID}
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}
	postgres, err := fly.runMachine(ctx, machineSpec{
		App: apps["postgres"], Name: "postgres-1", Image: "postgres:18-alpine", Size: plan.Machines.Postgres,
		Restart: "always", Env: map[string]string{"POSTGRES_USER": "tnl", "POSTGRES_DB": "tnl"},
		Volume: volumeID, MountPath: "/var/lib/postgresql/data",
	})
	if err != nil {
		return provisionedBenchmark{}, err
	}
	if err := fly.waitPostgres(ctx, apps["postgres"], postgres.ID); err != nil {
		return provisionedBenchmark{}, err
	}
	if err := fly.runEphemeral(ctx, machineSpec{
		App: apps["control"], Name: "migrate", Image: image, Command: "/tnld migrate", Size: "shared-cpu-1x",
	}); err != nil {
		return provisionedBenchmark{}, err
	}

	var serverMachines []struct {
		role    string
		machine flyMachine
	}
	controlEnvironment := map[string]string{
		"TNLD_MODE": "control", "TNLD_SERVER_DOMAIN": manifest.ServerDomain,
		"TNLD_MANAGED_DEPLOYMENT_DOMAIN": manifest.ManagedDomain, "TNLD_CONTROL_LISTEN": ":8443",
		"TNLD_PRIVATE_CONTROL_LISTEN": ":9443", "TNLD_METRICS_LISTEN": ":9090",
		"TNLD_ACME_EMAIL": command.ACMEEmail, "TNLD_ACME_ACCEPT_TERMS": "true",
		"TNLD_ROUTE53_REGION": "us-east-1", "TNLD_ROUTE53_SERVER_ZONE_ID": serverZone.ID,
		"TNLD_ROUTE53_MANAGED_ZONE_ID": managedZone.ID,
		"TNLD_INGRESS_IPV4_ADDRESSES":  strings.Join(manifest.Addresses["ingress"].IPv4, ","),
		"TNLD_INGRESS_IPV6_ADDRESSES":  strings.Join(manifest.Addresses["ingress"].IPv6, ","),
	}
	for index := range plan.Topology.ControlProcesses {
		machine, err := fly.runMachine(ctx, machineSpec{
			App: apps["control"], Name: fmt.Sprintf("control-%d", index+1), Image: image,
			Command: "/tnld serve", Size: plan.Machines.Control, Restart: "always", Env: controlEnvironment,
			Ports: []string{"443:8443/tcp"},
		})
		if err != nil {
			return provisionedBenchmark{}, err
		}
		serverMachines = append(serverMachines, struct {
			role    string
			machine flyMachine
		}{"control", machine})
	}
	if err := waitHTTPSReady(ctx, "https://control."+manifest.ServerDomain+"/v1/ready", 15*time.Minute); err != nil {
		return provisionedBenchmark{}, err
	}
	ingressEnvironment := map[string]string{
		"TNLD_MODE": "ingress", "TNLD_CONTROL_HOSTNAME": "control." + manifest.ServerDomain,
		"TNLD_PRIVATE_CONTROL_ADDRESS": apps["control"] + ".internal:9443",
		"TNLD_INGRESS_LISTEN":          ":8443", "TNLD_METRICS_LISTEN": ":9090",
		"TNLD_REQUIRE_PROXY_HEADER": "true",
	}
	for index := range plan.Topology.IngressProcesses {
		machine, err := fly.runMachine(ctx, machineSpec{
			App: apps["ingress"], Name: fmt.Sprintf("ingress-%d", index+1), Image: image,
			Command: "/tnld serve", Size: plan.Machines.Ingress, Restart: "always", Env: ingressEnvironment,
			MachineConfig: ingressFlyMachineConfig,
		})
		if err != nil {
			return provisionedBenchmark{}, err
		}
		serverMachines = append(serverMachines, struct {
			role    string
			machine flyMachine
		}{"ingress", machine})
	}
	for _, role := range []string{"relay-a", "relay-b"} {
		relayEnvironment := map[string]string{
			"TNLD_MODE": "relay", "TNLD_CONTROL_HOSTNAME": "control." + manifest.ServerDomain,
			"TNLD_PRIVATE_CONTROL_ADDRESS": apps["control"] + ".internal:9443",
			"TNLD_RELAY_SERVICE_ID":        role, "TNLD_RELAY_ADDRESS": role + "." + manifest.ServerDomain + ":443",
			"TNLD_RELAY_TCP_LISTEN": ":8443", "TNLD_RELAY_UDP_LISTEN": ":8443",
			"TNLD_INTERNAL_RELAY_LISTEN": ":9445", "TNLD_METRICS_LISTEN": ":9090",
		}
		for index := range plan.Topology.RelayProcessesPerService {
			machine, err := fly.runMachine(ctx, machineSpec{
				App: apps[role], Name: fmt.Sprintf("%s-%d", role, index+1), Image: image,
				Command: "/tnld serve", Size: plan.Machines.Relay, Restart: "always", Env: relayEnvironment,
				Ports: []string{"443:8443/tcp", "443:8443/udp"},
			})
			if err != nil {
				return provisionedBenchmark{}, err
			}
			serverMachines = append(serverMachines, struct {
				role    string
				machine flyMachine
			}{role, machine})
		}
	}
	metricsURLs := make([]string, 0, len(serverMachines))
	for _, item := range serverMachines {
		metricsURLs = append(metricsURLs, "http://"+item.machine.ID+".vm."+apps[item.role]+".internal:9090/metrics#"+item.role)
	}
	fmt.Fprintf(stdout, "Topology: %d control, %d ingress, %dx%d relay processes ready\n",
		plan.Topology.ControlProcesses, plan.Topology.IngressProcesses,
		plan.Topology.RelayServices, plan.Topology.RelayProcessesPerService)
	return provisionedBenchmark{
		apps: apps, addresses: manifest.Addresses, metricsURLs: metricsURLs, image: image, secrets: secrets,
		serverDomain: manifest.ServerDomain, managedDomain: manifest.ManagedDomain,
	}, nil
}

const ingressFlyMachineConfig = `{"services":[{"protocol":"tcp","internal_port":8443,"ports":[{"port":443,"handlers":["proxy_proto"],"proxy_proto_options":{"version":"v2"}}]}]}`

func executeCell(
	ctx context.Context,
	fly flyPlatform,
	benchmark provisionedBenchmark,
	plan benchmarkPlan,
	cell planCell,
	resultsPath string,
) (string, int, error) {
	for _, role := range []string{"coordinator", "publisher", "load"} {
		if err := fly.destroyMachines(ctx, benchmark.apps[role]); err != nil {
			return "failed", 0, err
		}
	}
	coordinatorURL := "https://" + benchmark.apps["coordinator"] + ".fly.dev"
	_, err := fly.runMachine(ctx, machineSpec{
		App: benchmark.apps["coordinator"], Name: "coordinator-" + shortCellID(cell.ID), Image: benchmark.image,
		Command: "/tnlbench coordinator", Size: plan.Machines.Coordinator, Restart: "no",
		Env: map[string]string{
			"TNL_BENCH_CELL_ID": cell.ID, "TNL_BENCH_PUBLISHER_WORKERS": fmt.Sprint(cell.PublisherWorkers),
			"TNL_BENCH_LOAD_WORKERS": fmt.Sprint(cell.LoadWorkers), "TNL_BENCH_COORDINATOR_LISTEN": ":8080",
		},
		Ports: []string{"443:8080/tcp:http:tls"},
	})
	if err != nil {
		return "failed", 0, err
	}
	coordinator, _ := newCoordinatorClient(coordinatorURL, benchmark.secrets.CoordinatorToken)
	if err := waitCoordinator(ctx, coordinator, 5*time.Minute); err != nil {
		return "failed", 0, err
	}
	routeOffset := 0
	for index := range cell.PublisherWorkers {
		assigned := balancedAssignment(cell.Routes, cell.PublisherWorkers, index)
		environment := map[string]string{
			"TNL_BENCH_CELL_ID": cell.ID, "TNL_BENCH_SUITE": plan.Suite,
			"TNL_BENCH_REPETITION": fmt.Sprint(cell.Repetition), "TNL_BENCH_SEQUENCE": fmt.Sprint(cell.Sequence),
			"TNL_BENCH_COORDINATOR_URL": coordinatorURL, "TNL_BENCH_WORKER_INDEX": fmt.Sprint(index),
			"TNL_BENCH_WORKER_COUNT":    fmt.Sprint(cell.PublisherWorkers),
			"TNL_BENCH_SERVER":          "https://control." + benchmark.serverDomain,
			"TNL_BENCH_HOSTNAME_SUFFIX": benchmark.managedDomain, "TNL_BENCH_ROUTES": fmt.Sprint(cell.Routes),
			"TNL_BENCH_ROUTE_OFFSET": fmt.Sprint(routeOffset), "TNL_BENCH_ASSIGNED_ROUTES": fmt.Sprint(assigned),
			"TNL_BENCH_FRESH_CONNECTIONS_PER_SECOND": fmt.Sprint(cell.FreshConnectionsPerSecond),
			"TNL_BENCH_HELD_STREAMS":                 fmt.Sprint(cell.HeldStreams),
			"TNL_BENCH_TIMEOUT":                      (time.Duration(cell.TimeoutSeconds) * time.Second).String(),
		}
		if index == 0 {
			environment["TNL_BENCH_METRICS_URLS"] = strings.Join(benchmark.metricsURLs, ",")
		}
		if _, err := fly.runMachine(ctx, machineSpec{
			App: benchmark.apps["publisher"], Name: fmt.Sprintf("publisher-%s-%d", shortCellID(cell.ID), index),
			Image: benchmark.image, Command: "/tnlbench publisher", Size: plan.Machines.Publisher, Restart: "no", Env: environment,
		}); err != nil {
			return "failed", 0, err
		}
		routeOffset += assigned
	}
	for index := range cell.LoadWorkers {
		fresh := balancedAssignment(cell.FreshConnectionsPerSecond, cell.LoadWorkers, index)
		held := balancedAssignment(cell.HeldStreams, cell.LoadWorkers, index)
		if _, err := fly.runMachine(ctx, machineSpec{
			App: benchmark.apps["load"], Name: fmt.Sprintf("load-%s-%d", shortCellID(cell.ID), index),
			Image: benchmark.image, Command: "/tnlbench load", Size: plan.Machines.Load, Restart: "no",
			Env: map[string]string{
				"TNL_BENCH_CELL_ID": cell.ID, "TNL_BENCH_SUITE": plan.Suite,
				"TNL_BENCH_REPETITION": fmt.Sprint(cell.Repetition), "TNL_BENCH_SEQUENCE": fmt.Sprint(cell.Sequence),
				"TNL_BENCH_COORDINATOR_URL": coordinatorURL, "TNL_BENCH_WORKER_INDEX": fmt.Sprint(index),
				"TNL_BENCH_WORKER_COUNT": fmt.Sprint(cell.LoadWorkers), "TNL_BENCH_ROUTES": fmt.Sprint(cell.Routes),
				"TNL_BENCH_HOSTNAME_SUFFIX":                    benchmark.managedDomain,
				"TNL_BENCH_TOTAL_FRESH_CONNECTIONS_PER_SECOND": fmt.Sprint(cell.FreshConnectionsPerSecond),
				"TNL_BENCH_TOTAL_HELD_STREAMS":                 fmt.Sprint(cell.HeldStreams),
				"TNL_BENCH_FRESH_CONNECTIONS_PER_SECOND":       fmt.Sprint(fresh), "TNL_BENCH_HELD_STREAMS": fmt.Sprint(held),
				"TNL_BENCH_WARMUP":   (time.Duration(cell.WarmupSeconds) * time.Second).String(),
				"TNL_BENCH_DURATION": (time.Duration(cell.DurationSeconds) * time.Second).String(),
				"TNL_BENCH_TIMEOUT":  (time.Duration(cell.TimeoutSeconds) * time.Second).String(),
			},
		}); err != nil {
			return "failed", 0, err
		}
	}
	status, err := waitCell(ctx, coordinator, time.Duration(cell.TimeoutSeconds)*time.Second)
	if err != nil {
		return "failed", 0, err
	}
	results, err := coordinatorResults(ctx, coordinator)
	if err != nil {
		return "failed", 0, err
	}
	rows := 0
	for _, line := range strings.Split(strings.TrimSpace(string(results)), "\n") {
		if line != "" {
			rows++
		}
	}
	if err := appendResults(resultsPath, results); err != nil {
		return "failed", rows, err
	}
	for _, role := range []string{"publisher", "load", "coordinator"} {
		if err := fly.destroyMachines(ctx, benchmark.apps[role]); err != nil {
			return status.Status, rows, err
		}
	}
	return status.Status, rows, nil
}

func waitCoordinator(ctx context.Context, client *coordinatorClient, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := coordinatorStatusRequest(requestCtx, client)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("coordinator did not become ready: %w", err)
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

func waitCell(ctx context.Context, client *coordinatorClient, timeout time.Duration) (coordinatorStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		status, err := coordinatorStatusRequest(ctx, client)
		if err == nil && status.Complete {
			return status, nil
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return coordinatorStatus{}, errors.Join(err, ctx.Err())
		}
	}
}

func coordinatorStatusRequest(ctx context.Context, client *coordinatorClient) (coordinatorStatus, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/v1/status", nil)
	if err != nil {
		return coordinatorStatus{}, err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return coordinatorStatus{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return coordinatorStatus{}, fmt.Errorf("coordinator status: HTTP %d", response.StatusCode)
	}
	var status coordinatorStatus
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&status); err != nil {
		return coordinatorStatus{}, err
	}
	return status, nil
}

func coordinatorResults(ctx context.Context, client *coordinatorClient) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/v1/results", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("coordinator results: HTTP %d: %s", response.StatusCode, data)
	}
	return data, nil
}

func cleanupRun(ctx context.Context, fly flyPlatform, dns benchmarkDNS, manifestPath string, manifest *runManifest) error {
	if err := validateManifestResources(*manifest); err != nil {
		return err
	}
	manifest.Status = "cleaning"
	manifest.CleanupErrors = nil
	_ = saveManifest(manifestPath, manifest)
	var cleanupErr error
	for index := len(manifest.Apps) - 1; index >= 0; index-- {
		app := &manifest.Apps[index]
		if app.Removed {
			continue
		}
		if err := fly.destroyApp(ctx, app.Name); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			manifest.CleanupErrors = append(manifest.CleanupErrors, err.Error())
			continue
		}
		app.Removed = true
		if manifest.Volume != nil && manifest.Volume.App == app.Name {
			manifest.Volume.Removed = true
		}
		_ = saveManifest(manifestPath, manifest)
	}
	for index := len(manifest.Zones) - 1; index >= 0; index-- {
		zone := &manifest.Zones[index]
		if zone.Removed {
			continue
		}
		if err := dns.deleteZone(ctx, *zone); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			manifest.CleanupErrors = append(manifest.CleanupErrors, err.Error())
			continue
		}
		zone.Removed = true
		_ = saveManifest(manifestPath, manifest)
	}
	if cleanupErr != nil {
		manifest.Status = "cleanup_failed"
	} else {
		manifest.Status = "cleaned"
	}
	return errors.Join(cleanupErr, saveManifest(manifestPath, manifest))
}

func validateManifestResources(manifest runManifest) error {
	parentDomain, parentDomainErr := naming.CanonicalizeHostname(manifest.ParentDomain)
	if manifest.SchemaVersion != runManifestSchemaVersion || !validRunID(manifest.RunID) ||
		parentDomainErr != nil || parentDomain != manifest.ParentDomain ||
		manifest.ParentZoneID == "" || canonicalZoneID(manifest.ParentZoneID) != manifest.ParentZoneID ||
		strings.ContainsAny(manifest.ParentZoneID, " /\t\r\n") {
		return errors.New("benchmark manifest has an invalid schema or identity")
	}
	if manifest.ServerDomain != manifest.RunID+"."+manifest.ParentDomain || manifest.ManagedDomain != "routes."+manifest.ServerDomain {
		return errors.New("benchmark manifest has invalid generated domains")
	}
	expectedApps := benchmarkAppNames(manifest.RunID)
	seenApps := make(map[string]struct{}, len(manifest.Apps))
	for _, app := range manifest.Apps {
		if expectedApps[app.Role] != app.Name {
			return fmt.Errorf("refuse to clean unowned Fly app %q", app.Name)
		}
		if _, exists := seenApps[app.Role]; exists {
			return fmt.Errorf("benchmark manifest repeats Fly app role %q", app.Role)
		}
		seenApps[app.Role] = struct{}{}
	}
	var serverZoneID string
	seenZones := make(map[string]struct{}, len(manifest.Zones))
	for _, zone := range manifest.Zones {
		if _, exists := seenZones[zone.Kind]; exists {
			return fmt.Errorf("benchmark manifest repeats hosted-zone kind %q", zone.Kind)
		}
		seenZones[zone.Kind] = struct{}{}
		if zone.ID == "" || canonicalZoneID(zone.ID) != zone.ID || strings.ContainsAny(zone.ID, " /\t\r\n") || len(zone.NameServers) < 2 {
			return fmt.Errorf("benchmark hosted zone %q has an invalid identity", zone.Name)
		}
		seenNameServers := make(map[string]struct{}, len(zone.NameServers))
		for _, nameServer := range zone.NameServers {
			canonical, err := naming.CanonicalizeHostname(nameServer)
			if err != nil || canonical != nameServer {
				return fmt.Errorf("benchmark hosted zone %q has an invalid name server", zone.Name)
			}
			if _, exists := seenNameServers[nameServer]; exists {
				return fmt.Errorf("benchmark hosted zone %q repeats a name server", zone.Name)
			}
			seenNameServers[nameServer] = struct{}{}
		}
		switch zone.Kind {
		case "server":
			if zone.Name != manifest.ServerDomain || zone.ParentName != manifest.ParentDomain || zone.ParentZoneID != manifest.ParentZoneID {
				return fmt.Errorf("refuse to clean unowned hosted zone %q", zone.Name)
			}
			serverZoneID = zone.ID
		case "managed":
			if zone.Name != manifest.ManagedDomain || zone.ParentName != manifest.ServerDomain {
				return fmt.Errorf("refuse to clean unowned hosted zone %q", zone.Name)
			}
		default:
			return fmt.Errorf("refuse to clean unowned hosted zone %q", zone.Name)
		}
	}
	for _, zone := range manifest.Zones {
		if zone.Kind == "managed" && (serverZoneID == "" || zone.ParentZoneID != serverZoneID) {
			return errors.New("benchmark managed zone does not belong to the recorded server zone")
		}
	}
	if manifest.Volume != nil && (manifest.Volume.App != expectedApps["postgres"] || manifest.Volume.ID == "") {
		return errors.New("benchmark manifest has an invalid PostgreSQL volume")
	}
	return nil
}

func saveManifest(path string, manifest *runManifest) error {
	manifest.UpdatedAt = time.Now().UTC()
	return writeIndentedJSON(path, manifest)
}

func loadManifest(path string) (runManifest, error) {
	var manifest runManifest
	if err := decodeJSONFile(path, &manifest); err != nil {
		return runManifest{}, fmt.Errorf("read benchmark manifest: %w", err)
	}
	return manifest, nil
}

func writeIndentedJSON(path string, value any) error {
	file, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(value)
	closeErr := file.Close()
	if err := errors.Join(encodeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func appendResults(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if len(data) != 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Close())
}

func generateRunSecrets() (runSecrets, error) {
	login, err := credentials.NewLoginToken()
	if err != nil {
		return runSecrets{}, err
	}
	cluster, err := randomBase64(32)
	if err != nil {
		return runSecrets{}, err
	}
	storage, err := randomBase64(32)
	if err != nil {
		return runSecrets{}, err
	}
	database, err := randomBase64(24)
	if err != nil {
		return runSecrets{}, err
	}
	coordinator, err := randomBase64(32)
	if err != nil {
		return runSecrets{}, err
	}
	return runSecrets{
		LoginToken: string(login), ClusterSecret: cluster, StorageKey: storage,
		DatabasePassword: database, CoordinatorToken: coordinator,
	}, nil
}

func randomBase64(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func newRunID(now time.Time) (string, error) {
	suffix, err := randomBase64(6)
	if err != nil {
		return "", err
	}
	suffix = strings.ToLower(strings.NewReplacer("_", "a", "-", "b").Replace(suffix))
	return "bench-" + now.Format("20060102-150405") + "-" + suffix, nil
}

func validRunID(value string) bool {
	const timestampLength = len("20060102-150405")
	if len(value) != len("bench-")+timestampLength+1+8 || !strings.HasPrefix(value, "bench-") {
		return false
	}
	timestamp := value[len("bench-") : len("bench-")+timestampLength]
	if _, err := time.Parse("20060102-150405", timestamp); err != nil {
		return false
	}
	if value[len("bench-")+timestampLength] != '-' {
		return false
	}
	for _, character := range value[len("bench-")+timestampLength+1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func benchmarkAppNames(runID string) map[string]string {
	prefix := "tnl-bench-" + runID + "-"
	return map[string]string{
		"postgres": prefix + "pg", "control": prefix + "ctl", "ingress": prefix + "ing",
		"relay-a": prefix + "ra", "relay-b": prefix + "rb", "coordinator": prefix + "coord",
		"publisher": prefix + "pub", "load": prefix + "load",
	}
}

func balancedAssignment(total, workers, index int) int {
	base, remainder := total/workers, total%workers
	if index < remainder {
		return base + 1
	}
	return base
}

func shortCellID(value string) string {
	if len(value) <= 24 {
		return value
	}
	return value[len(value)-24:]
}

func waitHTTPSReady(ctx context.Context, endpoint string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 10 * time.Second}
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("endpoint %s did not become ready (last error: %v)", endpoint, err)
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}
