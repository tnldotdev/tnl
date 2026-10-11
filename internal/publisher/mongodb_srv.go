package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/mongosrv"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/tcpport"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type mongoDNSResolver interface {
	LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error)
	LookupTXT(context.Context, string) ([]string, error)
}

type mongoSRVTarget struct {
	seed     string
	resolver mongoDNSResolver
	roots    *x509.CertPool
	dial     func(context.Context, string, string) (net.Conn, error)
}

func parseMongoSRVTarget(target string, roots *x509.CertPool) (*mongoSRVTarget, error) {
	seed, err := mongosrv.Parse(target)
	if err != nil {
		return nil, err
	}
	return &mongoSRVTarget{seed: seed, resolver: net.DefaultResolver, roots: roots,
		dial: (&net.Dialer{}).DialContext}, nil
}

func (s *mongoSRVTarget) hosts(ctx context.Context) ([]string, string, error) {
	_, records, err := s.resolver.LookupSRV(ctx, "mongodb", "tcp", s.seed)
	if err != nil {
		return nil, "", fmt.Errorf("resolve mongodb SRV records: %w", err)
	}
	if len(records) == 0 || len(records) > 32 {
		return nil, "", errors.New("mongodb SRV record count must be between 1 and 32")
	}
	parent := s.seed[strings.IndexByte(s.seed, '.')+1:]
	seen := make(map[string]struct{}, len(records))
	hosts := make([]string, 0, len(records))
	for _, record := range records {
		if record == nil || !tcpport.ValidNetwork(int(record.Port)) {
			return nil, "", errors.New("mongodb SRV record has an invalid port")
		}
		host := strings.TrimSuffix(record.Target, ".")
		canonical, err := naming.CanonicalizeHostname(host)
		if err != nil || canonical != host || host == s.seed || !strings.HasSuffix(host, "."+parent) {
			return nil, "", errors.New("mongodb SRV record is outside the seed's parent domain")
		}
		address := net.JoinHostPort(host, strconv.Itoa(int(record.Port)))
		if _, duplicate := seen[address]; duplicate {
			return nil, "", errors.New("mongodb SRV record duplicates a target")
		}
		seen[address] = struct{}{}
		hosts = append(hosts, address)
	}
	txt, err := s.resolver.LookupTXT(ctx, s.seed)
	var notFound *net.DNSError
	if err != nil && (!errors.As(err, &notFound) || !notFound.IsNotFound) {
		return nil, "", fmt.Errorf("resolve mongodb SRV options: %w", err)
	}
	if len(txt) > 1 {
		return nil, "", errors.New("mongodb SRV seed has multiple TXT records")
	}
	setName := ""
	if len(txt) == 1 {
		options, err := url.ParseQuery(txt[0])
		if err != nil {
			return nil, "", errors.New("mongodb SRV seed has invalid TXT options")
		}
		for name, values := range options {
			if name != "authSource" && name != "replicaSet" || len(values) != 1 || values[0] == "" {
				return nil, "", errors.New("mongodb SRV seed has unsupported TXT options")
			}
		}
		setName = options.Get("replicaSet")
	}
	return hosts, setName, nil
}

// connect probes fresh, certificate-verified connections until it finds a
// writable replica-set primary or a mongos. the visitor gets a new connection
// so its own mongodb hello remains the first message on that connection.
func (s *mongoSRVTarget) connect(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hosts, setName, err := s.hosts(ctx)
	if err != nil {
		return nil, err
	}
	var last error
	for _, address := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		probe, err := s.dialVerified(ctx, address)
		if err != nil {
			last = err
			continue
		}
		err = probeMongoPrimary(probe, setName)
		_ = probe.Close()
		if err == nil {
			visitor, dialErr := s.dialVerified(ctx, address)
			if dialErr == nil {
				_ = visitor.SetDeadline(time.Time{})
				return visitor, nil
			}
			err = dialErr
		}
		last = err
	}
	return nil, fmt.Errorf("connect mongodb SRV primary: %w", last)
}

func (s *mongoSRVTarget) dialVerified(ctx context.Context, address string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(address)
	connection, err := s.dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	secured := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: s.roots})
	if err := secured.Handshake(); err != nil {
		_ = secured.Close()
		return nil, err
	}
	return secured, nil
}

func probeMongoPrimary(connection net.Conn, setName string) error {
	document, err := bson.Marshal(bson.D{{Key: "hello", Value: 1}, {Key: "$db", Value: "admin"}})
	if err != nil {
		return err
	}
	message := make([]byte, 16+4+1+len(document))
	binary.LittleEndian.PutUint32(message[:4], uint32(len(message)))
	binary.LittleEndian.PutUint32(message[4:8], 1)
	binary.LittleEndian.PutUint32(message[12:16], 2013) // OP_MSG
	copy(message[21:], document)
	if _, err := io.Copy(connection, bytes.NewReader(message)); err != nil {
		return err
	}
	var header [21]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return err
	}
	length := binary.LittleEndian.Uint32(header[:4])
	if length < 26 || length > 1<<20 || binary.LittleEndian.Uint32(header[8:12]) != 1 ||
		binary.LittleEndian.Uint32(header[12:16]) != 2013 || binary.LittleEndian.Uint32(header[16:20]) != 0 || header[20] != 0 {
		return errors.New("mongodb target returned an invalid hello frame")
	}
	payload := make([]byte, length-21)
	if _, err := io.ReadFull(connection, payload); err != nil {
		return err
	}
	var response bson.Raw = payload
	if binary.LittleEndian.Uint32(payload[:4]) != uint32(len(payload)) || response.Validate() != nil {
		return errors.New("mongodb target returned invalid hello BSON")
	}
	ok, valid := response.Lookup("ok").DoubleOK()
	if !valid || ok != 1 {
		return errors.New("mongodb target rejected hello")
	}
	if setName != "" {
		actual, _ := response.Lookup("setName").StringValueOK()
		if actual != setName {
			return errors.New("mongodb target does not belong to the SRV replica set")
		}
	}
	if msg, _ := response.Lookup("msg").StringValueOK(); msg == "isdbgrid" {
		return nil
	}
	if primary, _ := response.Lookup("isWritablePrimary").BooleanOK(); !primary {
		return errors.New("mongodb SRV member is not writable")
	}
	return nil
}
