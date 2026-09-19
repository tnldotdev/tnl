package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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

const (
	runManifestSchemaVersion       = 3
	benchmarkDNSPropagationTimeout = 5 * time.Minute
)

type runCommand struct {
	Suite        string `name:"suite" env:"BENCH_SUITE" required:"" help:"Explicit suite to execute: smoke, scout, confirm, or compatibility."`
	ProfileFile  string `name:"profile" env:"BENCH_PROFILE" default:"benchmarks/suites/fly-production.json" type:"path" help:"Production-candidate benchmark profile."`
	Routes       int    `name:"routes" env:"BENCH_ROUTES" help:"Route count override; required for confirm."`
	FreshRate    int    `name:"fresh-connections-per-second" env:"BENCH_FRESH_CONNECTIONS_PER_SECOND" help:"Fresh visitor connection rate override; required for confirm."`
	HeldStreams  int    `name:"held-streams" env:"BENCH_HELD_STREAMS" help:"Held-open stream override; required for confirm."`
	ChurnRate    int    `name:"lifecycle-churn-per-second" env:"BENCH_LIFECYCLE_CHURN_PER_SECOND" help:"Route-session lifecycle churn override."`
	PayloadBytes int    `name:"payload-bytes" env:"BENCH_PAYLOAD_BYTES" help:"Fresh-response payload override."`
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
	SchemaVersion        int                      `json:"schema_version"`
	RunID                string                   `json:"run_id"`
	Status               string                   `json:"status"`
	CreatedAt            time.Time                `json:"created_at"`
	UpdatedAt            time.Time                `json:"updated_at"`
	FlyOrg               string                   `json:"fly_org"`
	Region               string                   `json:"region"`
	Topology             benchmarkTopology        `json:"topology"`
	CertificateAuthority string                   `json:"certificate_authority"`
	ParentDomain         string                   `json:"parent_domain"`
	ParentZoneID         string                   `json:"parent_zone_id"`
	ServerDomain         string                   `json:"server_domain"`
	ManagedDomain        string                   `json:"managed_domain"`
	Image                string                   `json:"image,omitempty"`
	Apps                 []manifestApp            `json:"apps"`
	Volumes              []manifestVolume         `json:"volumes,omitempty"`
	Zones                []manifestZone           `json:"zones"`
	Addresses            map[string]flyAddresses  `json:"addresses,omitempty"`
	ManagedPostgres      *manifestManagedPostgres `json:"managed_postgres,omitempty"`
	Cells                []manifestCell           `json:"cells,omitempty"`
	CleanupErrors        []string                 `json:"cleanup_errors,omitempty"`
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
	Index   int    `json:"index"`
	Name    string `json:"name"`
	ID      string `json:"id"`
	Region  string `json:"region"`
	SizeGB  int    `json:"size_gb"`
	Removed bool   `json:"removed,omitempty"`
}

type manifestManagedPostgres struct {
	ID                   string    `json:"id,omitempty"`
	Name                 string    `json:"name"`
	Region               string    `json:"region"`
	Plan                 string    `json:"plan"`
	PostgresMajorVersion int       `json:"postgres_major_version"`
	StorageGB            int       `json:"storage_gb"`
	CreationStarted      bool      `json:"creation_started,omitempty"`
	RemovedAt            time.Time `json:"removed_at,omitempty"`
	Removed              bool      `json:"removed,omitempty"`
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
	CoordinatorToken string
	AWSAccessKeyID   string
	AWSSecretKey     string
	AWSSessionToken  string
}

type provisionedBenchmark struct {
	apps             map[string]string
	addresses        map[string]flyAddresses
	metricsURLs      []string
	image            string
	manifestPath     string
	secrets          runSecrets
	database         flyManagedPostgresCredentials
	serverDomain     string
	managedDomain    string
	resolverEnv      map[string]string
	publisherVolumes []flyVolume
}

type benchmarkProgress struct {
	output    io.Writer
	startedAt time.Time
	now       func() time.Time
}

func newBenchmarkProgress(output io.Writer) *benchmarkProgress {
	return &benchmarkProgress{output: output, startedAt: time.Now(), now: time.Now}
}

func (p *benchmarkProgress) printf(format string, arguments ...any) {
	if p == nil || p.output == nil {
		return
	}
	elapsed := p.now().Sub(p.startedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	fmt.Fprintf(p.output, "[+%s] %s\n", elapsed.Truncate(time.Second), fmt.Sprintf(format, arguments...))
}

func (c runCommand) Validate() error {
	if c.Approved != "1" {
		return errors.New("BENCH_APPROVED must be exactly 1; planning does not grant execution approval")
	}
	if value, found := os.LookupEnv("BENCH_SUITE"); !found || value == "" || value != c.Suite {
		return errors.New("execution requires an explicit BENCH_SUITE environment variable")
	}
	if !validFlySlug(c.FlyOrg) {
		return errors.New("BENCH_FLY_ORG must be a canonical Fly organization slug")
	}
	return validateBenchmarkInfrastructure(c.ParentDomain, c.ParentZoneID, c.ACMEEmail)
}

func validateBenchmarkInfrastructure(parentDomain, parentZoneID, acmeEmail string) error {
	canonical, err := naming.CanonicalizeHostname(parentDomain)
	if err != nil || canonical != parentDomain {
		return errors.New("BENCH_PARENT_DOMAIN must be a canonical hostname")
	}
	if parentZoneID == "" || canonicalZoneID(parentZoneID) != parentZoneID || strings.ContainsAny(parentZoneID, " /\t\r\n") {
		return errors.New("BENCH_PARENT_ZONE_ID must be a canonical bare hosted-zone ID")
	}
	address, err := mail.ParseAddress(acmeEmail)
	if err != nil || address.Address != acmeEmail {
		return errors.New("BENCH_ACME_EMAIL must be a canonical email address")
	}
	return nil
}

func (c runCommand) run(ctx context.Context, stdout io.Writer) (retErr error) {
	progress := newBenchmarkProgress(stdout)
	if err := c.Validate(); err != nil {
		return err
	}
	plan, err := (planCommand{
		Suite: c.Suite, ProfileFile: c.ProfileFile, Routes: c.Routes, FreshRate: c.FreshRate,
		HeldStreams: c.HeldStreams, ChurnRate: c.ChurnRate, PayloadBytes: c.PayloadBytes,
		Repetitions: c.Repetitions, Format: "json",
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
		CreatedAt: time.Now().UTC(), FlyOrg: c.FlyOrg, Region: plan.Region, Topology: plan.Topology,
		CertificateAuthority: plan.CertificateAuthority,
		ParentDomain:         c.ParentDomain, ParentZoneID: c.ParentZoneID,
		ServerDomain: runID + "." + c.ParentDomain, ManagedDomain: "routes." + runID + "." + c.ParentDomain,
		Addresses: make(map[string]flyAddresses), ManagedPostgres: &manifestManagedPostgres{
			Name: benchmarkDatabaseName(runID), Region: plan.Region,
			Plan: plan.ManagedPostgres.Plan, PostgresMajorVersion: plan.ManagedPostgres.PostgresMajorVersion,
			StorageGB: plan.ManagedPostgres.StorageGB,
		},
	}
	manifestPath := filepath.Join(runDirectory, "manifest.json")
	if err := saveManifest(manifestPath, &manifest); err != nil {
		return err
	}
	if err := writeIndentedJSON(filepath.Join(runDirectory, "plan.json"), plan); err != nil {
		return err
	}
	resultsPath := filepath.Join(runDirectory, "results.jsonl")
	reportWritten := false
	defer func() {
		if retErr == nil || reportWritten {
			return
		}
		progress.printf("report: writing partial result artifacts after failure")
		if reportErr := (reportCommand{RunDirectory: runDirectory, allowIncomplete: true}).run(stdout); reportErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("write partial benchmark report: %w", reportErr))
		}
	}()
	progress.printf("run: %s", runID)
	progress.printf("output: %s", runDirectory)

	progress.printf("access: checking Fly, Managed Postgres, and Route 53")
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"))
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	awsCredentials, err := awsConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("retrieve AWS credentials: %w", err)
	}
	dns := benchmarkDNS{client: route53.NewFromConfig(awsConfig)}
	fly := flyPlatform{
		binary: c.FlyBinary, org: c.FlyOrg, region: plan.Region, executor: osCommandExecutor{}, progress: progress,
	}
	cleanupNeeded := true
	defer func() {
		if !cleanupNeeded {
			return
		}
		progress.printf("cleanup: starting after failure")
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		if cleanupErr := cleanupRun(cleanupCtx, fly, dns, manifestPath, &manifest, progress); cleanupErr != nil {
			progress.printf("cleanup: failed; retained resources are recorded in the manifest")
			retErr = errors.Join(retErr, cleanupErr)
		} else {
			progress.printf("cleanup: complete")
		}
	}()
	if err := fly.preflight(ctx); err != nil {
		return err
	}
	if err := fly.validateOrg(ctx); err != nil {
		return err
	}
	if err := fly.validateManagedPostgresAccess(ctx); err != nil {
		return err
	}
	if err := dns.validateParentZone(ctx, c.ParentZoneID, c.ParentDomain); err != nil {
		return err
	}
	progress.printf("access: ready")
	secrets, err := generateRunSecrets()
	if err != nil {
		return err
	}
	secrets.AWSAccessKeyID = awsCredentials.AccessKeyID
	secrets.AWSSecretKey = awsCredentials.SecretAccessKey
	secrets.AWSSessionToken = awsCredentials.SessionToken
	benchmark, err := provisionBenchmark(ctx, progress, fly, dns, plan, c, manifestPath, &manifest, secrets)
	if err != nil {
		return err
	}
	manifest.Status = "running"
	if err := saveManifest(manifestPath, &manifest); err != nil {
		return err
	}
	campaignFailed, err := executeCampaignCells(progress, plan.Cells, manifestPath, &manifest, func(cell planCell) (string, int, error) {
		return executeCell(ctx, progress, fly, benchmark, plan, cell, resultsPath)
	})
	if err != nil {
		return err
	}
	manifest.Status = "reporting"
	if err := saveManifest(manifestPath, &manifest); err != nil {
		return err
	}
	progress.printf("report: writing result artifacts")
	if err := (reportCommand{RunDirectory: runDirectory}).run(stdout); err != nil {
		return err
	}
	reportWritten = true
	progress.printf("report: complete")
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cleanupCancel()
	progress.printf("cleanup: starting")
	if err := cleanupRun(cleanupCtx, fly, dns, manifestPath, &manifest, progress); err != nil {
		return err
	}
	cleanupNeeded = false
	progress.printf("cleanup: complete")
	if campaignFailed {
		return fmt.Errorf("benchmark completed with failed cells; see %s", filepath.Join(runDirectory, "report.json"))
	}
	return nil
}

func (c cleanupCommand) run(ctx context.Context, stdout io.Writer) error {
	progress := newBenchmarkProgress(stdout)
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
	progress.printf("cleanup: starting run %s", manifest.RunID)
	if err := cleanupRun(ctx, fly, dns, manifestPath, &manifest, progress); err != nil {
		return err
	}
	progress.printf("cleanup: complete")
	return nil
}

func provisionBenchmark(
	ctx context.Context,
	progress *benchmarkProgress,
	fly flyPlatform,
	dns benchmarkDNS,
	plan benchmarkPlan,
	command runCommand,
	manifestPath string,
	manifest *runManifest,
	secrets runSecrets,
) (provisionedBenchmark, error) {
	progress.printf("database: creating Managed Postgres (%s, %d GiB)", plan.ManagedPostgres.Plan, plan.ManagedPostgres.StorageGB)
	manifest.ManagedPostgres.CreationStarted = true
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}
	databaseCtx, cancelDatabase := context.WithTimeout(
		ctx, time.Duration(plan.ManagedPostgres.ProvisionTimeoutSeconds)*time.Second,
	)
	database, databaseCredentials, databaseErr := fly.createManagedPostgres(
		databaseCtx, manifest.ManagedPostgres.Name, plan.ManagedPostgres,
	)
	cancelDatabase()
	if database.ID != "" {
		manifest.ManagedPostgres.ID = database.ID
		if err := saveManifest(manifestPath, manifest); err != nil {
			return provisionedBenchmark{}, errors.Join(databaseErr, err)
		}
	}
	if databaseErr != nil {
		return provisionedBenchmark{}, databaseErr
	}
	progress.printf("database: ready")

	progress.printf("dns: creating server zone %s", manifest.ServerDomain)
	parentNameServers, err := dns.hostedZoneNameServers(ctx, manifest.ParentZoneID)
	if err != nil {
		return provisionedBenchmark{}, err
	}
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
	if err := dns.waitDelegation(ctx, parentNameServers, serverZone, benchmarkDNSPropagationTimeout); err != nil {
		return provisionedBenchmark{}, err
	}
	progress.printf("dns: server zone delegated")
	progress.printf("dns: creating managed deployment zone %s", manifest.ManagedDomain)
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
	if err := dns.waitDelegation(ctx, serverZone.NameServers, managedZone, benchmarkDNSPropagationTimeout); err != nil {
		return provisionedBenchmark{}, err
	}
	progress.printf("dns: managed deployment zone delegated")

	apps := benchmarkAppNames(manifest.RunID, plan.Topology.RelayServices)
	var roles []string
	if plan.CertificateAuthority == benchmarkCertificateAuthorityPebble {
		roles = append(roles, "pebble")
	}
	roles = append(roles, "control", "ingress")
	roles = append(roles, benchmarkRelayRoles(plan.Topology.RelayServices)...)
	roles = append(roles, "coordinator", "publisher", "load")
	progress.printf("apps: creating %d Fly apps", len(roles))
	for index, role := range roles {
		if err := fly.createApp(ctx, apps[role]); err != nil {
			return provisionedBenchmark{}, err
		}
		manifest.Apps = append(manifest.Apps, manifestApp{Role: role, Name: apps[role]})
		if err := saveManifest(manifestPath, manifest); err != nil {
			return provisionedBenchmark{}, err
		}
		progress.printf("apps: %d/%d %s ready", index+1, len(roles), role)
	}
	progress.printf("image: building and pushing benchmark image")
	image, err := fly.buildImage(ctx, apps["control"], manifest.RunID)
	if err != nil {
		return provisionedBenchmark{}, err
	}
	manifest.Image = image
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}
	progress.printf("image: ready")
	publisherVolumes := make([]flyVolume, 0, plan.WorkerLimits.PublisherMachines)
	progress.printf("storage: creating %d publisher volumes", plan.WorkerLimits.PublisherMachines)
	for index := range plan.WorkerLimits.PublisherMachines {
		volume, err := fly.createVolume(
			ctx, apps["publisher"], benchmarkPublisherVolumeName(index), plan.WorkerLimits.PublisherVolumeGB,
		)
		if err != nil {
			return provisionedBenchmark{}, err
		}
		publisherVolumes = append(publisherVolumes, volume)
		manifest.Volumes = append(manifest.Volumes, manifestVolume{
			Index: index, Name: volume.Name, ID: volume.ID, Region: volume.Region, SizeGB: volume.SizeGB,
		})
		if err := saveManifest(manifestPath, manifest); err != nil {
			return provisionedBenchmark{}, err
		}
		progress.printf("storage: volume %d/%d ready", index+1, plan.WorkerLimits.PublisherMachines)
	}
	serverRoles := append([]string{"control", "ingress"}, benchmarkRelayRoles(plan.Topology.RelayServices)...)
	for _, role := range serverRoles {
		progress.printf("network: allocating addresses for %s", role)
		addresses, err := fly.allocateAddresses(ctx, apps[role], false)
		if err != nil {
			return provisionedBenchmark{}, err
		}
		manifest.Addresses[role] = addresses
		if err := saveManifest(manifestPath, manifest); err != nil {
			return provisionedBenchmark{}, err
		}
		progress.printf("network: %s addresses ready", role)
	}
	progress.printf("network: allocating coordinator address")
	coordinatorAddresses, err := fly.allocateAddresses(ctx, apps["coordinator"], true)
	if err != nil {
		return provisionedBenchmark{}, err
	}
	manifest.Addresses["coordinator"] = coordinatorAddresses
	if err := saveManifest(manifestPath, manifest); err != nil {
		return provisionedBenchmark{}, err
	}
	progress.printf("network: coordinator address ready")
	records := []struct{ role, hostname string }{
		{"control", "control." + manifest.ServerDomain},
		{"ingress", "ingress." + manifest.ServerDomain},
	}
	for _, role := range benchmarkRelayRoles(plan.Topology.RelayServices) {
		records = append(records, struct{ role, hostname string }{role, role + "." + manifest.ServerDomain})
	}
	for _, record := range records {
		progress.printf("dns: publishing %s", record.hostname)
		addresses := manifest.Addresses[record.role]
		if err := dns.upsertAddress(ctx, serverZone.ID, record.hostname, addresses.IPv4, addresses.IPv6); err != nil {
			return provisionedBenchmark{}, err
		}
		if err := dns.waitAddresses(
			ctx, serverZone.NameServers, record.hostname, addresses.IPv4, addresses.IPv6, benchmarkDNSPropagationTimeout,
		); err != nil {
			return provisionedBenchmark{}, err
		}
		progress.printf("dns: %s ready on every authoritative name server", record.hostname)
	}
	trustRoots := ""
	if plan.CertificateAuthority == benchmarkCertificateAuthorityPebble {
		progress.printf("certificates: starting private Pebble ACME service")
		var err error
		trustRoots, err = provisionBenchmarkPebble(
			ctx, fly, apps["pebble"], image, plan.Machines.Pebble, serverZone, managedZone,
		)
		if err != nil {
			return provisionedBenchmark{}, machineProvisionFailure(
				fly, manifestPath, "pebble", apps["pebble"], nil, secrets, databaseCredentials, err,
			)
		}
		progress.printf("certificates: Pebble ready with real DNS validation")
	}

	appSecrets := map[string]map[string]string{
		"control": {
			"TNLD_DATABASE_URL": databaseCredentials.PooledURL, "TNLD_DATABASE_DIRECT_URL": databaseCredentials.DirectURL,
			"TNLD_LOGIN_TOKEN": secrets.LoginToken, "TNLD_CLUSTER_SECRET": secrets.ClusterSecret,
			"TNLD_STORAGE_KEY": secrets.StorageKey, "AWS_ACCESS_KEY_ID": secrets.AWSAccessKeyID,
			"AWS_SECRET_ACCESS_KEY": secrets.AWSSecretKey, "AWS_SESSION_TOKEN": secrets.AWSSessionToken,
		},
		"ingress":     {"TNLD_CLUSTER_SECRET": secrets.ClusterSecret},
		"coordinator": {"TNL_BENCH_COORDINATOR_TOKEN": secrets.CoordinatorToken},
		"publisher": {
			"TNL_BENCH_COORDINATOR_TOKEN": secrets.CoordinatorToken,
			"TNL_BENCH_LOGIN_TOKEN":       secrets.LoginToken,
		},
		"load": {"TNL_BENCH_COORDINATOR_TOKEN": secrets.CoordinatorToken},
	}
	for _, role := range benchmarkRelayRoles(plan.Topology.RelayServices) {
		appSecrets[role] = map[string]string{"TNLD_CLUSTER_SECRET": secrets.ClusterSecret}
	}
	if trustRoots != "" {
		for _, values := range appSecrets {
			values["TNL_BENCH_EXTRA_ROOTS_B64"] = base64.StdEncoding.EncodeToString([]byte(trustRoots))
		}
	}
	progress.printf("configuration: staging secrets for %d apps", len(appSecrets))
	configuredRoles := append([]string{"control", "ingress"}, benchmarkRelayRoles(plan.Topology.RelayServices)...)
	configuredRoles = append(configuredRoles, "coordinator", "publisher", "load")
	for index, role := range configuredRoles {
		values := appSecrets[role]
		if err := fly.setSecrets(ctx, apps[role], values); err != nil {
			return provisionedBenchmark{}, err
		}
		progress.printf("configuration: %d/%d %s ready", index+1, len(configuredRoles), role)
	}
	progress.printf("database: running migrations")
	if err := fly.runEphemeral(ctx, machineSpec{
		App: apps["control"], Name: "migrate", Image: image,
		Command: "/tnld migrate; status=$?; sleep 10; exit $status", Size: "shared-cpu-1x",
	}); err != nil {
		return provisionedBenchmark{}, machineProvisionFailure(
			fly, manifestPath, "migration", apps["control"], nil, secrets, databaseCredentials, err,
		)
	}
	progress.printf("database: migrations complete")

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
	if plan.CertificateAuthority == benchmarkCertificateAuthorityPebble {
		controlEnvironment["TNLD_ACME_DIRECTORY_URL"] = "https://" + apps["pebble"] + ".internal:14000/dir"
	}
	certificateDiagnostics := []benchmarkDiagnosticApp{{name: "control", app: apps["control"]}}
	if plan.CertificateAuthority == benchmarkCertificateAuthorityPebble {
		certificateDiagnostics = append(certificateDiagnostics, benchmarkDiagnosticApp{name: "pebble", app: apps["pebble"]})
	}
	controlMachines := make([]flyMachine, 0, plan.Topology.ControlProcesses)
	startControl := func(index int) error {
		progress.printf("control: starting process %d/%d", index+1, plan.Topology.ControlProcesses)
		machine, err := fly.runMachine(ctx, machineSpec{
			App: apps["control"], Name: fmt.Sprintf("control-%d", index+1), Image: image,
			Command: "/tnld serve", Size: plan.Machines.Control, Restart: "always", Env: controlEnvironment,
			Ports: []string{"443:8443/tcp"},
		})
		if machine.ID != "" {
			controlMachines = append(controlMachines, machine)
			serverMachines = append(serverMachines, struct {
				role    string
				machine flyMachine
			}{"control", machine})
		}
		if err != nil {
			return err
		}
		return nil
	}
	if err := startControl(0); err != nil {
		return provisionedBenchmark{}, controlProvisionFailure(
			fly, manifestPath, apps["control"], controlMachines, secrets, databaseCredentials, err,
			certificateDiagnostics[1:]...,
		)
	}
	if err := waitHTTPSReady(ctx, "https://control."+manifest.ServerDomain+"/v1/ready", trustRoots, 15*time.Minute); err != nil {
		return provisionedBenchmark{}, controlProvisionFailure(
			fly, manifestPath, apps["control"], controlMachines, secrets, databaseCredentials, err,
			certificateDiagnostics[1:]...,
		)
	}
	progress.printf("control: process 1/%d ready with public certificate", plan.Topology.ControlProcesses)
	for index := 1; index < plan.Topology.ControlProcesses; index++ {
		if err := startControl(index); err != nil {
			return provisionedBenchmark{}, controlProvisionFailure(
				fly, manifestPath, apps["control"], controlMachines, secrets, databaseCredentials, err,
				certificateDiagnostics[1:]...,
			)
		}
		machine := controlMachines[len(controlMachines)-1]
		if err := fly.waitMachineReady(ctx, apps["control"], machine.ID, 5*time.Minute); err != nil {
			return provisionedBenchmark{}, controlProvisionFailure(
				fly, manifestPath, apps["control"], controlMachines, secrets, databaseCredentials, err,
				certificateDiagnostics[1:]...,
			)
		}
		progress.printf("control: process %d/%d ready", index+1, plan.Topology.ControlProcesses)
	}
	ingressEnvironment := map[string]string{
		"TNLD_MODE": "ingress", "TNLD_CONTROL_HOSTNAME": "control." + manifest.ServerDomain,
		"TNLD_PRIVATE_CONTROL_ADDRESS": apps["control"] + ".internal:9443",
		"TNLD_INGRESS_LISTEN":          ":8443", "TNLD_METRICS_LISTEN": ":9090",
		"TNLD_REQUIRE_PROXY_HEADER": "true",
	}
	ingressMachines := make([]flyMachine, 0, plan.Topology.IngressProcesses)
	for index := range plan.Topology.IngressProcesses {
		progress.printf("ingress: starting process %d/%d", index+1, plan.Topology.IngressProcesses)
		machine, err := fly.runMachine(ctx, machineSpec{
			App: apps["ingress"], Name: fmt.Sprintf("ingress-%d", index+1), Image: image,
			Command: "/tnld serve", Size: plan.Machines.Ingress, Restart: "always", Env: ingressEnvironment,
			MachineConfig: ingressFlyMachineConfig,
		})
		if machine.ID != "" {
			ingressMachines = append(ingressMachines, machine)
			serverMachines = append(serverMachines, struct {
				role    string
				machine flyMachine
			}{"ingress", machine})
		}
		if err != nil {
			return provisionedBenchmark{}, machineProvisionFailure(
				fly, manifestPath, "ingress", apps["ingress"], ingressMachines, secrets, databaseCredentials, err,
				certificateDiagnostics...,
			)
		}
		if err := fly.waitMachineReady(ctx, apps["ingress"], machine.ID, 5*time.Minute); err != nil {
			return provisionedBenchmark{}, machineProvisionFailure(
				fly, manifestPath, "ingress", apps["ingress"], ingressMachines, secrets, databaseCredentials, err,
				certificateDiagnostics...,
			)
		}
		progress.printf("ingress: process %d/%d ready", index+1, plan.Topology.IngressProcesses)
	}
	for _, role := range benchmarkRelayRoles(plan.Topology.RelayServices) {
		relayEnvironment := map[string]string{
			"TNLD_MODE": "relay", "TNLD_CONTROL_HOSTNAME": "control." + manifest.ServerDomain,
			"TNLD_PRIVATE_CONTROL_ADDRESS": apps["control"] + ".internal:9443",
			"TNLD_RELAY_SERVICE_ID":        role, "TNLD_RELAY_ADDRESS": role + "." + manifest.ServerDomain + ":443",
			"TNLD_RELAY_TCP_LISTEN": ":8443", "TNLD_RELAY_UDP_LISTEN": ":8443",
			"TNLD_INTERNAL_RELAY_LISTEN": ":9445", "TNLD_METRICS_LISTEN": ":9090",
		}
		relayMachines := make([]flyMachine, 0, plan.Topology.RelayProcessesPerService)
		for index := range plan.Topology.RelayProcessesPerService {
			progress.printf("%s: starting process %d/%d", role, index+1, plan.Topology.RelayProcessesPerService)
			machine, err := fly.runMachine(ctx, machineSpec{
				App: apps[role], Name: fmt.Sprintf("%s-%d", role, index+1), Image: image,
				Command: "/tnld serve", Size: plan.Machines.Relay, Restart: "always", Env: relayEnvironment,
				Ports: []string{"443:8443/tcp", "443:8443/udp"},
			})
			if machine.ID != "" {
				relayMachines = append(relayMachines, machine)
				serverMachines = append(serverMachines, struct {
					role    string
					machine flyMachine
				}{role, machine})
			}
			if err != nil {
				return provisionedBenchmark{}, machineProvisionFailure(
					fly, manifestPath, role, apps[role], relayMachines, secrets, databaseCredentials, err,
					certificateDiagnostics...,
				)
			}
			if err := fly.waitMachineReady(ctx, apps[role], machine.ID, 5*time.Minute); err != nil {
				return provisionedBenchmark{}, machineProvisionFailure(
					fly, manifestPath, role, apps[role], relayMachines, secrets, databaseCredentials, err,
					certificateDiagnostics...,
				)
			}
			progress.printf("%s: process %d/%d ready", role, index+1, plan.Topology.RelayProcessesPerService)
		}
	}
	metricsURLs := make([]string, 0, len(serverMachines))
	for _, item := range serverMachines {
		metricsURLs = append(metricsURLs, "http://"+item.machine.ID+".vm."+apps[item.role]+".internal:9090/metrics#"+item.role)
	}
	progress.printf("topology: %d control, %d ingress, %dx%d relay processes ready",
		plan.Topology.ControlProcesses, plan.Topology.IngressProcesses,
		plan.Topology.RelayServices, plan.Topology.RelayProcessesPerService)
	return provisionedBenchmark{
		apps: apps, addresses: manifest.Addresses, metricsURLs: metricsURLs, image: image,
		manifestPath: manifestPath, secrets: secrets, database: databaseCredentials,
		serverDomain: manifest.ServerDomain, managedDomain: manifest.ManagedDomain,
		resolverEnv: benchmarkResolverEnvironment(serverZone, managedZone, nil), publisherVolumes: publisherVolumes,
	}, nil
}

type benchmarkDiagnosticApp struct {
	name string
	app  string
}

func controlProvisionFailure(
	fly flyPlatform,
	manifestPath, app string,
	machines []flyMachine,
	secrets runSecrets,
	database flyManagedPostgresCredentials,
	cause error,
	relatedApps ...benchmarkDiagnosticApp,
) error {
	return machineProvisionFailure(fly, manifestPath, "control", app, machines, secrets, database, cause, relatedApps...)
}

func machineProvisionFailure(
	fly flyPlatform,
	manifestPath, diagnosticName, app string,
	machines []flyMachine,
	secrets runSecrets,
	database flyManagedPostgresCredentials,
	cause error,
	relatedApps ...benchmarkDiagnosticApp,
) error {
	path, err := captureMachineDiagnostics(fly, manifestPath, diagnosticName, app, machines, secrets, database, relatedApps...)
	if err != nil {
		return errors.Join(cause, err)
	}
	return fmt.Errorf("%w (%s diagnostics: %s)", cause, diagnosticName, path)
}

func captureMachineDiagnostics(
	fly flyPlatform,
	manifestPath, diagnosticName, app string,
	machines []flyMachine,
	secrets runSecrets,
	database flyManagedPostgresCredentials,
	relatedApps ...benchmarkDiagnosticApp,
) (string, error) {
	diagnosticsCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	listed, err := fly.listMachines(diagnosticsCtx, app)
	if err == nil && len(listed) != 0 {
		machines = listed
	}
	diagnostics := fly.machineDiagnostics(diagnosticsCtx, app, machines)
	for _, related := range relatedApps {
		listed, err := fly.listMachines(diagnosticsCtx, related.app)
		if err != nil {
			diagnostics += fmt.Sprintf("\n[%s related diagnostics]\n%s\n", related.name, err)
			continue
		}
		diagnostics += fmt.Sprintf("\n[%s related diagnostics]\n%s", related.name, fly.machineDiagnostics(diagnosticsCtx, related.app, listed))
	}
	diagnostics = redactSensitiveText(diagnostics, map[string]string{
		"login_token": secrets.LoginToken, "cluster_secret": secrets.ClusterSecret,
		"storage_key": secrets.StorageKey, "coordinator_token": secrets.CoordinatorToken,
		"aws_access_key_id": secrets.AWSAccessKeyID, "aws_secret_key": secrets.AWSSecretKey,
		"aws_session_token": secrets.AWSSessionToken, "database_url": database.PooledURL,
		"database_direct_url": database.DirectURL,
	})
	directory := filepath.Join(filepath.Dir(manifestPath), "diagnostics")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create %s diagnostics directory: %w", diagnosticName, err)
	}
	path := filepath.Join(directory, diagnosticName+".txt")
	if err := os.WriteFile(path, []byte(diagnostics), 0o600); err != nil {
		return "", fmt.Errorf("write %s diagnostics: %w", diagnosticName, err)
	}
	return path, nil
}

const ingressFlyMachineConfig = `{"services":[{"protocol":"tcp","internal_port":8443,"ports":[{"port":443,"handlers":["proxy_proto"],"proxy_proto_options":{"version":"v2"}}]}]}`

func executeCell(
	ctx context.Context,
	progress *benchmarkProgress,
	fly flyPlatform,
	benchmark provisionedBenchmark,
	plan benchmarkPlan,
	cell planCell,
	resultsPath string,
) (string, int, error) {
	progress.printf("cell %s: clearing workers from the previous cell", cell.ID)
	for _, role := range []string{"coordinator", "publisher", "load"} {
		if err := fly.destroyMachines(ctx, benchmark.apps[role]); err != nil {
			return "failed", 0, err
		}
	}
	coordinatorURL := "https://" + benchmark.apps["coordinator"] + ".fly.dev"
	progress.printf("cell %s: starting coordinator", cell.ID)
	coordinatorMachine, err := fly.runMachine(ctx, machineSpec{
		App: benchmark.apps["coordinator"], Name: "coordinator-" + shortCellID(cell.ID), Image: benchmark.image,
		Command: "/tnlbench coordinator", Size: plan.Machines.Coordinator, Restart: "no",
		Env: map[string]string{
			"TNL_BENCH_CELL_ID": cell.ID, "TNL_BENCH_PUBLISHER_WORKERS": fmt.Sprint(cell.PublisherWorkers),
			"TNL_BENCH_LOAD_WORKERS": fmt.Sprint(cell.LoadWorkers), "TNL_BENCH_ROUTES": fmt.Sprint(cell.Routes),
			"TNL_BENCH_COORDINATOR_LISTEN": ":8080",
		},
		Ports: []string{"443:8080/tcp:http:tls"},
	})
	if err != nil {
		return "failed", 0, cellMachineProvisionFailure(progress, fly, benchmark, "coordinator", coordinatorMachine, err)
	}
	coordinator, _ := newCoordinatorClient(coordinatorURL, benchmark.secrets.CoordinatorToken)
	if err := waitCoordinator(ctx, coordinator, 5*time.Minute); err != nil {
		return "failed", 0, cellMachineProvisionFailure(progress, fly, benchmark, "coordinator", coordinatorMachine, err)
	}
	progress.printf("cell %s: coordinator ready", cell.ID)
	for index := range cell.PublisherWorkers {
		assigned := len(benchmarkRouteIndexes(
			cell.Routes, plan.WorkerLimits.RoutesPerPublisher, cell.PublisherWorkers, index,
		))
		churn := benchmarkPublisherChurnAssignment(cell.LifecycleChurnPerSecond, cell.PublisherWorkers, index)
		environment := map[string]string{
			"TNL_BENCH_CELL_ID": cell.ID, "TNL_BENCH_SUITE": plan.Suite, "TNL_BENCH_AXIS": cell.Axis,
			"TNL_BENCH_REPETITION": fmt.Sprint(cell.Repetition), "TNL_BENCH_SEQUENCE": fmt.Sprint(cell.Sequence),
			"TNL_BENCH_COORDINATOR_URL": coordinatorURL, "TNL_BENCH_WORKER_INDEX": fmt.Sprint(index),
			"TNL_BENCH_WORKER_COUNT":    fmt.Sprint(cell.PublisherWorkers),
			"TNL_BENCH_SERVER":          "https://control." + benchmark.serverDomain,
			"TNL_BENCH_HOSTNAME_SUFFIX": benchmark.managedDomain, "TNL_BENCH_ROUTES": fmt.Sprint(cell.Routes),
			"TNL_BENCH_ASSIGNED_ROUTES":                     fmt.Sprint(assigned),
			"TNL_BENCH_ROUTES_PER_PUBLISHER":                fmt.Sprint(plan.WorkerLimits.RoutesPerPublisher),
			"TNL_BENCH_ROUTES_PER_CHURN_ROUTE":              fmt.Sprint(plan.WorkerLimits.RoutesPerChurnRoute),
			"TNL_BENCH_STATE_ROOT":                          "/state",
			"TNL_BENCH_FRESH_CONNECTIONS_PER_SECOND":        fmt.Sprint(cell.FreshConnectionsPerSecond),
			"TNL_BENCH_HELD_STREAMS":                        fmt.Sprint(cell.HeldStreams),
			"TNL_BENCH_LIFECYCLE_CHURN_PER_SECOND":          fmt.Sprint(cell.LifecycleChurnPerSecond),
			"TNL_BENCH_ASSIGNED_LIFECYCLE_CHURN_PER_SECOND": fmt.Sprint(churn),
			"TNL_BENCH_PAYLOAD_BYTES":                       fmt.Sprint(cell.PayloadBytes),
			"TNL_BENCH_TIMEOUT":                             (time.Duration(cell.TimeoutSeconds) * time.Second).String(),
		}
		if index == 0 {
			environment["TNL_BENCH_METRICS_URLS"] = strings.Join(benchmark.metricsURLs, ",")
		}
		var diagnosticURLs []string
		for _, endpoint := range benchmark.metricsURLs {
			if strings.HasSuffix(endpoint, "#control") {
				diagnosticURLs = append(diagnosticURLs, strings.TrimSuffix(endpoint, "/metrics#control")+"/debug/database")
			}
		}
		environment["TNL_BENCH_DATABASE_DIAGNOSTICS_URLS"] = strings.Join(diagnosticURLs, ",")
		progress.printf(
			"cell %s: starting publisher %d/%d (%d routes, %d churn/s)",
			cell.ID, index+1, cell.PublisherWorkers, assigned, churn,
		)
		machine, err := fly.runMachine(ctx, machineSpec{
			App: benchmark.apps["publisher"], Name: fmt.Sprintf("publisher-%s-%d", shortCellID(cell.ID), index),
			Image: benchmark.image, Command: "/tnlbench publisher", Size: plan.Machines.Publisher, Restart: "no", Env: environment,
			Volumes: []string{benchmark.publisherVolumes[index].ID + ":/state"},
		})
		if err != nil {
			return "failed", 0, cellMachineProvisionFailure(progress, fly, benchmark, "publisher", machine, err)
		}
		progress.printf("cell %s: publisher %d/%d started", cell.ID, index+1, cell.PublisherWorkers)
	}
	for index := range cell.LoadWorkers {
		fresh := balancedAssignment(cell.FreshConnectionsPerSecond, cell.LoadWorkers, index)
		held := balancedAssignment(cell.HeldStreams, cell.LoadWorkers, index)
		environment := map[string]string{
			"TNL_BENCH_CELL_ID": cell.ID, "TNL_BENCH_SUITE": plan.Suite, "TNL_BENCH_AXIS": cell.Axis,
			"TNL_BENCH_REPETITION": fmt.Sprint(cell.Repetition), "TNL_BENCH_SEQUENCE": fmt.Sprint(cell.Sequence),
			"TNL_BENCH_COORDINATOR_URL": coordinatorURL, "TNL_BENCH_WORKER_INDEX": fmt.Sprint(index),
			"TNL_BENCH_WORKER_COUNT": fmt.Sprint(cell.LoadWorkers), "TNL_BENCH_ROUTES": fmt.Sprint(cell.Routes),
			"TNL_BENCH_TOTAL_FRESH_CONNECTIONS_PER_SECOND": fmt.Sprint(cell.FreshConnectionsPerSecond),
			"TNL_BENCH_TOTAL_HELD_STREAMS":                 fmt.Sprint(cell.HeldStreams),
			"TNL_BENCH_LIFECYCLE_CHURN_PER_SECOND":         fmt.Sprint(cell.LifecycleChurnPerSecond),
			"TNL_BENCH_FRESH_CONNECTIONS_PER_SECOND":       fmt.Sprint(fresh), "TNL_BENCH_HELD_STREAMS": fmt.Sprint(held),
			"TNL_BENCH_PAYLOAD_BYTES":    fmt.Sprint(cell.PayloadBytes),
			"TNL_BENCH_WARMUP":           (time.Duration(cell.WarmupSeconds) * time.Second).String(),
			"TNL_BENCH_DURATION":         (time.Duration(cell.DurationSeconds) * time.Second).String(),
			"TNL_BENCH_TIMEOUT":          (time.Duration(cell.TimeoutSeconds) * time.Second).String(),
			"TNL_BENCH_RESOLVER_ADDRESS": benchmarkAuthoritativeDNSAddress,
		}
		for name, value := range benchmark.resolverEnv {
			environment[name] = value
		}
		progress.printf(
			"cell %s: starting load worker %d/%d (%d fresh/s, %d held)",
			cell.ID, index+1, cell.LoadWorkers, fresh, held,
		)
		machine, err := fly.runMachine(ctx, machineSpec{
			App: benchmark.apps["load"], Name: fmt.Sprintf("load-%s-%d", shortCellID(cell.ID), index),
			Image: benchmark.image, Command: benchmarkLoadCommand, Size: plan.Machines.Load, Restart: "no", Env: environment,
		})
		if err != nil {
			return "failed", 0, cellMachineProvisionFailure(progress, fly, benchmark, "load", machine, err)
		}
		progress.printf("cell %s: load worker %d/%d started", cell.ID, index+1, cell.LoadWorkers)
	}
	progress.printf(
		"cell %s: waiting for workload results (warmup %ds, measure %ds, timeout %ds)",
		cell.ID, cell.WarmupSeconds, cell.DurationSeconds, cell.TimeoutSeconds,
	)
	status, waitErr := waitCell(ctx, progress, coordinator, time.Duration(cell.TimeoutSeconds)*time.Second)
	progress.printf("cell %s: collecting results", cell.ID)
	results, resultsErr := coordinatorResults(ctx, coordinator, status.AbortCampaign)
	if resultsErr != nil {
		cause := errors.Join(waitErr, resultsErr)
		return "failed", 0, cellExecutionFailure(progress, fly, benchmark, cell, cause)
	}
	resultStatus, rows, err := summarizeCellResults(results)
	if err != nil {
		return "failed", 0, cellExecutionFailure(progress, fly, benchmark, cell, errors.Join(waitErr, err))
	}
	if waitErr != nil && !status.AbortCampaign {
		progress.printf("cell %s: recovered complete results after status polling failed", cell.ID)
	}
	status.Status = resultStatus
	if err := appendResults(resultsPath, results); err != nil {
		return "failed", rows, err
	}
	continuationErr := cellContinuationError(results)
	if status.AbortCampaign {
		continuationErr = errors.Join(waitErr, continuationErr)
	}
	if status.Status != "passed" {
		progress.printf("cell %s: capturing workload diagnostics", cell.ID)
		if path, err := captureCellDiagnostics(fly, benchmark, cell); err != nil {
			progress.printf("cell %s: diagnostics failed: %v", cell.ID, err)
		} else {
			progress.printf("cell %s: diagnostics written to %s", cell.ID, path)
		}
	}
	progress.printf("cell %s: stopping workers", cell.ID)
	for _, role := range []string{"publisher", "load", "coordinator"} {
		if err := fly.destroyMachines(ctx, benchmark.apps[role]); err != nil {
			return status.Status, rows, err
		}
	}
	return status.Status, rows, continuationErr
}

// A failed setup cannot establish a capacity boundary. Measured saturation can
// continue only when every load worker has demonstrated post-load recovery.
func cellContinuationError(data []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	failed, loads, recovered := false, 0, 0
	for {
		var result benchmarkResult
		if err := decoder.Decode(&result); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if result.Status != "passed" {
			failed = true
			if stage := resultFailureStage(result); stage != "measurement" {
				return fmt.Errorf("cell %s %s failed; stopping campaign before the next cell", result.CellID, stage)
			}
		}
		if result.Worker.Kind == "load" {
			loads++
			for _, phase := range result.Phases {
				if phase.Name == "recovery" && phase.Successes > 0 {
					recovered++
					break
				}
			}
		}
	}
	if failed && (loads == 0 || loads != recovered) {
		return errors.New("cell failed without successful recovery from every load worker; stopping campaign")
	}
	return nil
}

func summarizeCellResults(data []byte) (string, int, error) {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	status, rows := "passed", 0
	for {
		var result benchmarkResult
		err := decoder.Decode(&result)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "failed", rows, fmt.Errorf("decode cell result %d: %w", rows+1, err)
		}
		if err := validateResultIdentity(result); err != nil {
			return "failed", rows, fmt.Errorf("validate cell result %d: %w", rows+1, err)
		}
		rows++
		if result.Status != "passed" {
			status = "failed"
		}
	}
	if rows == 0 {
		return "failed", 0, errors.New("coordinator returned no result rows")
	}
	return status, rows, nil
}

func executeCampaignCells(progress *benchmarkProgress, cells []planCell, manifestPath string, manifest *runManifest,
	execute func(planCell) (string, int, error),
) (bool, error) {
	failed := false
	for _, cell := range cells {
		progress.printf("cell %s: starting", cell.ID)
		status, rows, err := execute(cell)
		manifest.Cells = append(manifest.Cells, manifestCell{ID: cell.ID, Status: status, ResultRows: rows, CompletedAt: time.Now().UTC()})
		if saveErr := saveManifest(manifestPath, manifest); saveErr != nil {
			return true, errors.Join(err, saveErr)
		}
		if err != nil {
			progress.printf("cell %s: failed; details will follow after cleanup", cell.ID)
			return true, err
		}
		progress.printf("cell %s: %s (%d result rows)", cell.ID, status, rows)
		failed = failed || status != "passed"
	}
	return failed, nil
}

func cellMachineProvisionFailure(
	progress *benchmarkProgress,
	fly flyPlatform,
	benchmark provisionedBenchmark,
	role string,
	machine flyMachine,
	cause error,
) error {
	progress.printf("cell: capturing %s diagnostics", role)
	machines := []flyMachine(nil)
	if machine.ID != "" {
		machines = append(machines, machine)
	}
	related := []benchmarkDiagnosticApp(nil)
	if role != "coordinator" {
		related = append(related, benchmarkDiagnosticApp{name: "coordinator", app: benchmark.apps["coordinator"]})
	}
	return machineProvisionFailure(
		fly, benchmark.manifestPath, role, benchmark.apps[role], machines,
		benchmark.secrets, benchmark.database, cause, related...,
	)
}

func cellExecutionFailure(
	progress *benchmarkProgress,
	fly flyPlatform,
	benchmark provisionedBenchmark,
	cell planCell,
	cause error,
) error {
	progress.printf("cell %s: capturing failure diagnostics", cell.ID)
	path, err := captureCellDiagnostics(fly, benchmark, cell)
	if err != nil {
		return errors.Join(cause, err)
	}
	return fmt.Errorf("%w (cell diagnostics: %s)", cause, path)
}

func captureCellDiagnostics(fly flyPlatform, benchmark provisionedBenchmark, cell planCell) (string, error) {
	return captureMachineDiagnostics(
		fly, benchmark.manifestPath, "cell-"+cell.ID,
		benchmark.apps["coordinator"], nil, benchmark.secrets, benchmark.database,
		benchmarkDiagnosticApp{name: "publisher", app: benchmark.apps["publisher"]},
		benchmarkDiagnosticApp{name: "load", app: benchmark.apps["load"]},
		benchmarkDiagnosticApp{name: "control", app: benchmark.apps["control"]},
	)
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

func waitCell(
	ctx context.Context,
	progress *benchmarkProgress,
	client *coordinatorClient,
	timeout time.Duration,
) (coordinatorStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lastSummary := ""
	nextHeartbeat := time.Time{}
	for {
		status, err := coordinatorStatusRequest(ctx, client)
		now := time.Now()
		if err == nil {
			summary := fmt.Sprintf(
				"publishers %d/%d ready, publisher results %d/%d, load results %d/%d",
				status.PublishersReady, status.PublisherWorkers, status.PublisherResults, status.PublisherWorkers,
				status.LoadResults, status.LoadWorkers,
			)
			if summary != lastSummary || !now.Before(nextHeartbeat) {
				progress.printf("cell %s: %s", status.CellID, summary)
				lastSummary = summary
				nextHeartbeat = now.Add(15 * time.Second)
			}
			if status.Complete {
				return status, nil
			}
			if status.AbortCampaign {
				return status, errors.New("worker setup failed; collecting partial results and stopping campaign")
			}
		} else if !now.Before(nextHeartbeat) {
			progress.printf("cell: coordinator status temporarily unavailable; retrying")
			nextHeartbeat = now.Add(15 * time.Second)
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

func coordinatorResults(ctx context.Context, client *coordinatorClient, partial bool) ([]byte, error) {
	endpoint := client.baseURL + "/v1/results"
	if partial {
		endpoint += "?partial=1"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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

func cleanupRun(
	ctx context.Context,
	fly flyPlatform,
	dns benchmarkDNS,
	manifestPath string,
	manifest *runManifest,
	progress *benchmarkProgress,
) error {
	if err := validateManifestResources(*manifest); err != nil {
		return err
	}
	manifest.Status = "cleaning"
	manifest.CleanupErrors = nil
	_ = saveManifest(manifestPath, manifest)
	var cleanupErr error
	publisherStorageRemoved := true
	if len(manifest.Volumes) != 0 {
		publisherApp := benchmarkAppNames(manifest.RunID, manifest.Topology.RelayServices)["publisher"]
		progress.printf("cleanup: stopping publisher machines")
		if err := fly.destroyMachines(ctx, publisherApp); err != nil {
			progress.printf("cleanup: publisher machines failed")
			publisherStorageRemoved = false
			cleanupErr = errors.Join(cleanupErr, err)
			manifest.CleanupErrors = append(manifest.CleanupErrors, err.Error())
		} else {
			for index := len(manifest.Volumes) - 1; index >= 0; index-- {
				volume := &manifest.Volumes[index]
				if volume.Removed {
					continue
				}
				progress.printf("cleanup: removing publisher volume %d", volume.Index+1)
				if err := fly.destroyVolume(ctx, publisherApp, volume.ID); err != nil {
					progress.printf("cleanup: publisher volume %d failed", volume.Index+1)
					publisherStorageRemoved = false
					cleanupErr = errors.Join(cleanupErr, err)
					manifest.CleanupErrors = append(manifest.CleanupErrors, err.Error())
					continue
				}
				volume.Removed = true
				_ = saveManifest(manifestPath, manifest)
				progress.printf("cleanup: publisher volume %d removed", volume.Index+1)
			}
		}
	}
	controlRemoved := true
	for index := len(manifest.Apps) - 1; index >= 0; index-- {
		app := &manifest.Apps[index]
		if app.Removed {
			continue
		}
		if app.Role == "publisher" && !publisherStorageRemoved {
			err := errors.New("preserve publisher app because its state volumes were not removed")
			cleanupErr = errors.Join(cleanupErr, err)
			manifest.CleanupErrors = append(manifest.CleanupErrors, err.Error())
			continue
		}
		progress.printf("cleanup: removing %s app", app.Role)
		if err := fly.destroyApp(ctx, app.Name); err != nil {
			progress.printf("cleanup: %s app failed", app.Role)
			cleanupErr = errors.Join(cleanupErr, err)
			manifest.CleanupErrors = append(manifest.CleanupErrors, err.Error())
			if app.Role == "control" {
				controlRemoved = false
			}
			continue
		}
		app.Removed = true
		_ = saveManifest(manifestPath, manifest)
		progress.printf("cleanup: %s app removed", app.Role)
	}
	if !controlRemoved {
		err := errors.New("preserve Fly Managed Postgres because the control app was not removed")
		cleanupErr = errors.Join(cleanupErr, err)
		manifest.CleanupErrors = append(manifest.CleanupErrors, err.Error())
	} else {
		progress.printf("cleanup: removing Managed Postgres")
		if err := cleanupManagedPostgres(ctx, fly, manifestPath, manifest); err != nil {
			progress.printf("cleanup: Managed Postgres failed")
			cleanupErr = errors.Join(cleanupErr, err)
			manifest.CleanupErrors = append(manifest.CleanupErrors, err.Error())
		} else {
			progress.printf("cleanup: Managed Postgres removed")
		}
	}
	for index := len(manifest.Zones) - 1; index >= 0; index-- {
		zone := &manifest.Zones[index]
		if zone.Removed {
			continue
		}
		progress.printf("cleanup: removing %s DNS zone", zone.Kind)
		if err := dns.deleteZone(ctx, *zone); err != nil {
			progress.printf("cleanup: %s DNS zone failed", zone.Kind)
			cleanupErr = errors.Join(cleanupErr, err)
			manifest.CleanupErrors = append(manifest.CleanupErrors, err.Error())
			continue
		}
		zone.Removed = true
		_ = saveManifest(manifestPath, manifest)
		progress.printf("cleanup: %s DNS zone removed", zone.Kind)
	}
	if cleanupErr != nil {
		manifest.Status = "cleanup_failed"
	} else {
		manifest.Status = "cleaned"
	}
	return errors.Join(cleanupErr, saveManifest(manifestPath, manifest))
}

func cleanupManagedPostgres(
	ctx context.Context,
	fly flyPlatform,
	manifestPath string,
	manifest *runManifest,
) error {
	database := manifest.ManagedPostgres
	if database == nil || database.Removed {
		return nil
	}
	if !database.CreationStarted && database.ID == "" {
		database.Removed = true
		return saveManifest(manifestPath, manifest)
	}
	cluster, found, err := discoverManagedPostgresForCleanup(ctx, fly, *database, manifest.FlyOrg)
	if err != nil {
		return err
	}
	if !found {
		database.Removed = true
		return saveManifest(manifestPath, manifest)
	}
	if database.ID == "" {
		database.ID = cluster.ID
		if err := saveManifest(manifestPath, manifest); err != nil {
			return err
		}
	}
	details, err := fly.managedPostgresStatus(ctx, cluster.ID)
	if err != nil {
		return err
	}
	if details.ID != database.ID || details.Name != database.Name || details.Region != database.Region ||
		!strings.EqualFold(details.Plan, database.Plan) || details.StorageGB != database.StorageGB {
		return fmt.Errorf("refuse to clean unowned Fly Managed Postgres cluster %q", details.Name)
	}
	if err := fly.destroyManagedPostgres(ctx, cluster.ID); err != nil {
		return err
	}
	database.Removed = true
	database.RemovedAt = time.Now().UTC()
	return saveManifest(manifestPath, manifest)
}

func discoverManagedPostgresForCleanup(
	ctx context.Context,
	fly flyPlatform,
	expected manifestManagedPostgres,
	flyOrg string,
) (flyManagedPostgresCluster, bool, error) {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		clusters, err := fly.listManagedPostgres(ctx)
		if err != nil {
			return flyManagedPostgresCluster{}, false, err
		}
		cluster, found, err := selectManagedPostgresForCleanup(expected, flyOrg, clusters)
		if err != nil || found || expected.ID != "" || time.Now().After(deadline) {
			return cluster, found, err
		}
		if err := sleepContext(ctx, 5*time.Second); err != nil {
			return flyManagedPostgresCluster{}, false, fmt.Errorf("discover Fly Managed Postgres cluster %q: %w", expected.Name, err)
		}
	}
}

func selectManagedPostgresForCleanup(
	expected manifestManagedPostgres,
	flyOrg string,
	clusters []flyManagedPostgresCluster,
) (flyManagedPostgresCluster, bool, error) {
	var matches []flyManagedPostgresCluster
	for _, cluster := range clusters {
		if cluster.Name == expected.Name || expected.ID != "" && cluster.ID == expected.ID {
			matches = append(matches, cluster)
		}
	}
	if len(matches) == 0 {
		return flyManagedPostgresCluster{}, false, nil
	}
	if len(matches) != 1 {
		return flyManagedPostgresCluster{}, false, errors.New("refuse to clean ambiguous Fly Managed Postgres clusters")
	}
	cluster := matches[0]
	if expected.ID != "" && cluster.ID != expected.ID || cluster.Name != expected.Name ||
		cluster.Organization.Slug != flyOrg || cluster.Region != expected.Region ||
		!strings.EqualFold(cluster.Plan, expected.Plan) {
		return flyManagedPostgresCluster{}, false, fmt.Errorf("refuse to clean unowned Fly Managed Postgres cluster %q", cluster.Name)
	}
	return cluster, true, nil
}

func validateManifestResources(manifest runManifest) error {
	parentDomain, parentDomainErr := naming.CanonicalizeHostname(manifest.ParentDomain)
	if manifest.SchemaVersion != runManifestSchemaVersion || !validRunID(manifest.RunID) ||
		!validFlySlug(manifest.FlyOrg) || len(manifest.Region) != 3 || !validFlySlug(manifest.Region) ||
		parentDomainErr != nil || parentDomain != manifest.ParentDomain ||
		manifest.ParentZoneID == "" || canonicalZoneID(manifest.ParentZoneID) != manifest.ParentZoneID ||
		strings.ContainsAny(manifest.ParentZoneID, " /\t\r\n") {
		return errors.New("benchmark manifest has an invalid schema or identity")
	}
	if manifest.ServerDomain != manifest.RunID+"."+manifest.ParentDomain || manifest.ManagedDomain != "routes."+manifest.ServerDomain {
		return errors.New("benchmark manifest has invalid generated domains")
	}
	if manifest.Topology.ControlProcesses <= 0 || manifest.Topology.ControlProcesses > 10 ||
		manifest.Topology.IngressProcesses <= 0 || manifest.Topology.IngressProcesses > 10 ||
		manifest.Topology.RelayServices < 2 || manifest.Topology.RelayServices > 26 ||
		manifest.Topology.RelayProcessesPerService <= 0 || manifest.Topology.RelayProcessesPerService > 10 {
		return errors.New("benchmark manifest has an invalid topology")
	}
	if manifest.CertificateAuthority != benchmarkCertificateAuthorityPebble &&
		manifest.CertificateAuthority != benchmarkCertificateAuthorityLetsEncrypt {
		return errors.New("benchmark manifest has an invalid certificate authority")
	}
	expectedApps := benchmarkAppNames(manifest.RunID, manifest.Topology.RelayServices)
	if manifest.CertificateAuthority != benchmarkCertificateAuthorityPebble {
		delete(expectedApps, "pebble")
	}
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
	seenVolumes := make(map[string]struct{}, len(manifest.Volumes))
	seenVolumeIndexes := make(map[int]struct{}, len(manifest.Volumes))
	for _, volume := range manifest.Volumes {
		if volume.Index < 0 || volume.Index >= 16 || volume.Name != benchmarkPublisherVolumeName(volume.Index) ||
			!validResourceID(volume.ID) || volume.Region != manifest.Region || volume.SizeGB <= 0 || volume.SizeGB > 10 {
			return fmt.Errorf("benchmark manifest has an invalid publisher volume %q", volume.ID)
		}
		if _, exists := seenVolumes[volume.ID]; exists {
			return fmt.Errorf("benchmark manifest repeats publisher volume %q", volume.ID)
		}
		if _, exists := seenVolumeIndexes[volume.Index]; exists {
			return fmt.Errorf("benchmark manifest repeats publisher volume index %d", volume.Index)
		}
		seenVolumes[volume.ID] = struct{}{}
		seenVolumeIndexes[volume.Index] = struct{}{}
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
	database := manifest.ManagedPostgres
	if database == nil || database.Name != benchmarkDatabaseName(manifest.RunID) || database.Region != manifest.Region ||
		database.Plan == "" || database.Plan != strings.ToLower(database.Plan) ||
		(database.PostgresMajorVersion != 16 && database.PostgresMajorVersion != 17) ||
		database.StorageGB < 10 || database.StorageGB > 500 ||
		database.ID != "" && !validResourceID(database.ID) {
		return errors.New("benchmark manifest has an invalid Fly Managed Postgres identity")
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
	coordinator, err := randomBase64(32)
	if err != nil {
		return runSecrets{}, err
	}
	return runSecrets{
		LoginToken: string(login), ClusterSecret: cluster, StorageKey: storage,
		CoordinatorToken: coordinator,
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

func benchmarkAppNames(runID string, relayServices int) map[string]string {
	prefix := "tnl-bench-" + runID + "-"
	apps := map[string]string{
		"control": prefix + "ctl", "ingress": prefix + "ing", "coordinator": prefix + "coord",
		"publisher": prefix + "pub", "load": prefix + "load", "pebble": prefix + "pebble",
	}
	for index, role := range benchmarkRelayRoles(relayServices) {
		apps[role] = fmt.Sprintf("%sr%c", prefix, 'a'+rune(index))
	}
	return apps
}

func benchmarkRelayRoles(services int) []string {
	roles := make([]string, services)
	for index := range services {
		roles[index] = fmt.Sprintf("relay-%c", 'a'+rune(index))
	}
	return roles
}

func benchmarkDatabaseName(runID string) string {
	return "tnl-bench-" + runID + "-pg"
}

func benchmarkPublisherVolumeName(index int) string {
	return fmt.Sprintf("publisher_state_%d", index)
}

func benchmarkRouteIndexes(routes, routesPerPublisher, workers, worker int) []int {
	if routes <= 0 || routesPerPublisher <= 0 || workers != divideRoundUp(routes, routesPerPublisher) || worker < 0 || worker >= workers {
		return nil
	}
	first := worker * routesPerPublisher
	last := min(first+routesPerPublisher, routes)
	indexes := make([]int, last-first)
	for index := range indexes {
		indexes[index] = first + index
	}
	return indexes
}

func benchmarkPublisherChurnAssignment(total, workers, worker int) int {
	if total < 0 || workers <= 0 || worker < 0 || worker >= workers {
		return 0
	}
	return balancedAssignment(total, workers, worker)
}

func validResourceID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validFlySlug(value string) bool {
	if value == "" || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
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

func waitHTTPSReady(ctx context.Context, endpoint, trustRoots string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if trustRoots != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(trustRoots)) {
			return errors.New("benchmark trust roots contain no certificates")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("http status %s", response.Status)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("endpoint %s did not become ready (last error: %v)", endpoint, err)
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}
