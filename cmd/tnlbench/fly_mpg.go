package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type flyManagedPostgresOrganization struct {
	Slug string `json:"slug"`
}

type flyManagedPostgresCluster struct {
	ID           string                         `json:"id"`
	Name         string                         `json:"name"`
	Status       string                         `json:"status"`
	Plan         string                         `json:"plan"`
	Region       string                         `json:"region"`
	Organization flyManagedPostgresOrganization `json:"organization"`
	StorageGB    int                            `json:"disk"`
}

type flyManagedPostgresCredentials struct {
	PooledURL string
	DirectURL string
}

var (
	databaseURLPattern          = regexp.MustCompile(`(?i)postgres(?:ql)?://[^\s]+`)
	databasePasswordJSONPattern = regexp.MustCompile(`(?i)("password"\s*:\s*")[^"]*(")`)
)

func (f flyPlatform) validateManagedPostgresAccess(ctx context.Context) error {
	if _, err := f.listManagedPostgres(ctx); err != nil {
		return fmt.Errorf("access Fly Managed Postgres: %w", err)
	}
	return nil
}

func (f flyPlatform) createManagedPostgres(
	ctx context.Context,
	name string,
	spec benchmarkManagedPostgres,
) (flyManagedPostgresCluster, flyManagedPostgresCredentials, error) {
	output, commandErr := f.executor.Run(
		ctx, f.binary, "mpg", "create", "--name", name, "--org", f.org, "--region", f.region,
		"--plan", spec.Plan, "--volume-size", strconv.Itoa(spec.StorageGB),
		"--pg-major-version", strconv.Itoa(spec.PostgresMajorVersion),
	)
	cluster, pooledURL := parseManagedPostgresCreateOutput(output, name)
	if commandErr != nil {
		return cluster, flyManagedPostgresCredentials{}, fmt.Errorf(
			"create Fly Managed Postgres cluster: %w", redactManagedPostgresError(commandErr),
		)
	}
	if cluster.ID == "" || cluster.Name != name || cluster.Organization.Slug != f.org || cluster.Region != f.region ||
		!strings.EqualFold(cluster.Plan, spec.Plan) || cluster.StorageGB != spec.StorageGB {
		return cluster, flyManagedPostgresCredentials{}, errors.New("unexpected cluster identity returned by Fly Managed Postgres")
	}
	pooled, direct, err := managedPostgresURLs(pooledURL)
	if err != nil {
		return cluster, flyManagedPostgresCredentials{}, err
	}
	return cluster, flyManagedPostgresCredentials{PooledURL: pooled, DirectURL: direct}, nil
}

func parseManagedPostgresCreateOutput(output []byte, expectedName string) (flyManagedPostgresCluster, string) {
	var cluster flyManagedPostgresCluster
	var pooledURL string
	for _, rawLine := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(rawLine)
		waitingPrefix := "Waiting for cluster " + expectedName + " ("
		if strings.HasPrefix(line, waitingPrefix) {
			if id, _, found := strings.Cut(strings.TrimPrefix(line, waitingPrefix), ")"); found {
				cluster.ID, cluster.Name = strings.TrimSpace(id), expectedName
			}
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "ID":
			cluster.ID = value
		case "Name":
			cluster.Name = value
		case "Organization":
			cluster.Organization.Slug = value
		case "Region":
			cluster.Region = value
		case "Plan":
			cluster.Plan = strings.ToLower(value)
		case "Disk":
			cluster.StorageGB, _ = strconv.Atoi(strings.TrimSuffix(value, "GB"))
		case "Connection string":
			pooledURL = value
		}
	}
	return cluster, pooledURL
}

func managedPostgresURLs(raw string) (string, string, error) {
	pooled, err := url.Parse(raw)
	if err != nil {
		return "", "", errors.New("invalid pooled database URL returned by Fly Managed Postgres")
	}
	password, passwordPresent := "", false
	if pooled.User != nil {
		password, passwordPresent = pooled.User.Password()
	}
	if pooled.Scheme != "postgres" && pooled.Scheme != "postgresql" || pooled.User == nil ||
		pooled.User.Username() == "" || !passwordPresent || password == "" || pooled.Hostname() == "" ||
		!strings.HasPrefix(pooled.Hostname(), "pgbouncer.") || !strings.HasSuffix(pooled.Hostname(), ".flympg.net") ||
		strings.TrimPrefix(pooled.EscapedPath(), "/") == "" || pooled.Fragment != "" {
		return "", "", errors.New("invalid pooled database URL returned by Fly Managed Postgres")
	}
	direct := *pooled
	directHost := "direct." + strings.TrimPrefix(pooled.Hostname(), "pgbouncer.")
	if port := pooled.Port(); port != "" {
		directHost = net.JoinHostPort(directHost, port)
	}
	direct.Host = directHost
	return pooled.String(), direct.String(), nil
}

func (f flyPlatform) listManagedPostgres(ctx context.Context) ([]flyManagedPostgresCluster, error) {
	output, err := f.executor.Run(ctx, f.binary, "mpg", "list", "--org", f.org, "--json")
	if err != nil {
		return nil, fmt.Errorf("list Fly Managed Postgres clusters: %w", err)
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" || strings.HasPrefix(trimmed, "No managed postgres clusters found") {
		return nil, nil
	}
	var clusters []flyManagedPostgresCluster
	if err := json.Unmarshal(output, &clusters); err != nil {
		return nil, fmt.Errorf("decode Fly Managed Postgres clusters: %w", err)
	}
	return clusters, nil
}

func (f flyPlatform) managedPostgresStatus(ctx context.Context, id string) (flyManagedPostgresCluster, error) {
	output, err := f.executor.Run(ctx, f.binary, "mpg", "status", id, "--json")
	if err != nil {
		return flyManagedPostgresCluster{}, fmt.Errorf("read Fly Managed Postgres cluster %s status: command failed", id)
	}
	var response struct {
		Data flyManagedPostgresCluster `json:"data"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return flyManagedPostgresCluster{}, fmt.Errorf("decode Fly Managed Postgres cluster %s status: %w", id, err)
	}
	return response.Data, nil
}

func (f flyPlatform) destroyManagedPostgres(ctx context.Context, id string) error {
	_, err := f.executor.Run(ctx, f.binary, "mpg", "destroy", id, "--yes")
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") {
		return fmt.Errorf("destroy Fly Managed Postgres cluster %s: %w", id, err)
	}
	for {
		clusters, err := f.listManagedPostgres(ctx)
		if err != nil {
			return err
		}
		found := false
		for _, cluster := range clusters {
			if cluster.ID == id {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		if err := sleepContext(ctx, 5*time.Second); err != nil {
			return fmt.Errorf("wait for Fly Managed Postgres cluster %s deletion: %w", id, err)
		}
	}
}

func redactManagedPostgresError(err error) error {
	return errors.New(redactDatabaseText(err.Error()))
}

func redactDatabaseText(message string) string {
	message = databaseURLPattern.ReplaceAllString(message, "[REDACTED_DATABASE_URL]")
	message = databasePasswordJSONPattern.ReplaceAllString(message, `${1}[REDACTED]${2}`)
	return message
}
