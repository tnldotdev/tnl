package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const databaseTLSHostname = "db.fixture.test"

type databaseTLSFixture struct {
	Flags     []string
	container testcontainers.Container
	directory string
}

func (f *databaseTLSFixture) Close() {
	if f.container != nil {
		terminate(f.container)
	}
	_ = os.RemoveAll(f.directory)
}

// startDatabaseTLS provides real protocol negotiation and password auth. the
// DNS-only certificate forces visitors dialing loopback to verify the explicit
// provider hostname. no system roots, keychain changes, or external DB is used.
func startDatabaseTLS(ctx context.Context, service string) (_ *databaseTLSFixture, retErr error) {
	directory, err := os.MkdirTemp("", "tnl-database-tls-")
	if err != nil {
		return nil, err
	}
	fixture := &databaseTLSFixture{directory: directory}
	defer func() {
		if retErr != nil {
			fixture.Close()
		}
	}()
	if err := writeDatabaseCertificates(directory); err != nil {
		return nil, err
	}
	files := []testcontainers.ContainerFile{}
	for _, file := range []string{"ca.pem", "server.pem", "server.key"} {
		files = append(files, testcontainers.ContainerFile{HostFilePath: filepath.Join(directory, file), ContainerFilePath: "/tnl-fixture/" + file, FileMode: 0600})
	}
	protocol, port := "postgres", "5432/tcp"
	nativeClientHost := testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
		config.ExtraHosts = append(config.ExtraHosts, "orders.production.storefront.example.test:host-gateway")
	})
	if service == "postgres-tls" {
		hba := "local all all trust\nhostnossl all all all reject\nhostssl all all all scram-sha-256\n"
		files = append(files, testcontainers.ContainerFile{Reader: strings.NewReader(hba), ContainerFilePath: "/tnl-fixture/pg_hba.conf", FileMode: 0644})
		container, err := postgres.Run(ctx, postgresImage,
			postgres.WithUsername("tnl_client"), postgres.WithPassword("testpass"), postgres.WithDatabase("tnl_fixture"),
			testcontainers.WithFiles(files...), loopbackPort("5432"), nativeClientHost,
			testcontainers.WithEntrypoint("sh", "-ec"),
			testcontainers.WithCmd(`chown -R postgres:postgres /tnl-fixture && chmod 600 /tnl-fixture/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tnl-fixture/server.pem -c ssl_key_file=/tnl-fixture/server.key -c ssl_ca_file=/tnl-fixture/ca.pem -c hba_file=/tnl-fixture/pg_hba.conf -c password_encryption=scram-sha-256`),
			postgres.BasicWaitStrategies(),
		)
		if container != nil {
			fixture.container = container
		}
		if err != nil {
			return nil, fmt.Errorf("start disposable TLS PostgreSQL: %w", err)
		}
	} else {
		protocol, port = "mysql", "3306/tcp"
		container, err := mysql.Run(ctx, mysqlImage,
			mysql.WithUsername("root"), mysql.WithPassword("testpass"), mysql.WithDatabase("tnl_fixture"),
			testcontainers.WithEnv(map[string]string{"MYSQL_ROOT_HOST": "%"}),
			testcontainers.WithFiles(files...), reservedLoopbackPort("3306"), nativeClientHost,
			testcontainers.WithEntrypoint("sh", "-ec"),
			testcontainers.WithCmd(`chown -R mysql:mysql /tnl-fixture && exec docker-entrypoint.sh mysqld --require_secure_transport=ON --ssl-ca=/tnl-fixture/ca.pem --ssl-cert=/tnl-fixture/server.pem --ssl-key=/tnl-fixture/server.key --auto_generate_certs=OFF --tls-version=TLSv1.2,TLSv1.3`),
			testcontainers.WithAdditionalWaitStrategy(wait.ForListeningPort("3306/tcp")),
		)
		if container != nil {
			fixture.container = container
		}
		if err != nil {
			return nil, fmt.Errorf("start disposable TLS MySQL: %w", err)
		}
		// create a fresh caching_sha2 user and clear the server cache immediately
		// before the test. its first login must perform full authentication.
		code, output, err := container.Exec(ctx, []string{"mysql", "--protocol=socket", "--user=root", "--password=testpass", "--execute=CREATE USER 'tnl_client'@'%' IDENTIFIED WITH caching_sha2_password BY 'testpass' REQUIRE SSL; GRANT ALL ON tnl_fixture.* TO 'tnl_client'@'%'; FLUSH PRIVILEGES;"})
		if err != nil || code != 0 {
			var message []byte
			if output != nil {
				message, _ = io.ReadAll(io.LimitReader(output, 4096))
			}
			return nil, fmt.Errorf("configure TLS MySQL full authentication: exit %d: %s: %v", code, strings.TrimSpace(string(message)), err)
		}
	}
	host, err := fixture.container.Host(ctx)
	if err != nil {
		return nil, err
	}
	mapped, err := fixture.container.MappedPort(ctx, port)
	if err != nil {
		return nil, err
	}
	prefix := "-tnl-test-" + protocol
	fixture.Flags = []string{
		prefix + "-address=" + net.JoinHostPort(host, mapped.Port()),
		prefix + "-ca-file=" + filepath.Join(directory, "ca.pem"),
		prefix + "-tls-hostname=" + databaseTLSHostname,
		prefix + "-client-container=" + fixture.container.GetContainerID(),
	}
	return fixture, nil
}

func writeDatabaseCertificates(directory string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial := func() *big.Int { value, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); return value }
	now := time.Now()
	root := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "tnl disposable database CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		return err
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: databaseTLSHostname}, DNSNames: []string{databaseTLSHostname},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &serverKey.PublicKey, key)
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{
		"ca.pem":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		"server.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"server.key": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			return err
		}
	}
	return nil
}
