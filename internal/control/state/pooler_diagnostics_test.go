package controlstate

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type poolerRows struct {
	pgx.Rows
	fields []pgconn.FieldDescription
	values [][]string
	index  int
}

func (r *poolerRows) Next() bool                                   { r.index++; return r.index <= len(r.values) }
func (r *poolerRows) Close()                                       {}
func (r *poolerRows) Err() error                                   { return nil }
func (r *poolerRows) FieldDescriptions() []pgconn.FieldDescription { return r.fields }
func (r *poolerRows) RawValues() [][]byte {
	var result [][]byte
	for _, value := range r.values[r.index-1] {
		result = append(result, []byte(value))
	}
	return result
}

type poolerQuery func(context.Context, string, ...any) (pgx.Rows, error)

func (f poolerQuery) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return f(ctx, sql, args...)
}

func TestPoolerSettingsAllowlistExcludesConnectionDetails(t *testing.T) {
	rows := &poolerRows{
		fields: []pgconn.FieldDescription{{Name: "key"}, {Name: "value"}, {Name: "default"}},
		values: [][]string{
			{"auth_file", "secret-password-file", "secret-default"},
			{"pool_mode", "transaction", "session"},
			{"max_client_conn", "200", "100"},
			{"default_pool_size", "50", "20"},
			{"server_lifetime", "secret-malformed-setting", "secret-default"},
			{"max_db_connections", "-1", "0"},
		},
	}
	settings, err := readPoolerSettings(t.Context(), poolerQuery(func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
		if sql != "SHOW CONFIG" {
			t.Fatalf("unexpected query %q", sql)
		}
		return rows, nil
	}))
	if err != nil || !reflect.DeepEqual(settings, map[string]string{"pool_mode": "transaction", "max_client_conn": "200", "default_pool_size": "50"}) {
		t.Fatalf("filtered pooler settings = %+v, %v", settings, err)
	}
	encoded, _ := json.Marshal(settings)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("settings leaked secret values")
	}
}

func TestPoolerClientsBoundedAndAggregated(t *testing.T) {
	for _, count := range []int{3, 4097} {
		rows := &poolerRows{fields: []pgconn.FieldDescription{{Name: "state"}, {Name: "user"}, {Name: "addr"}}}
		states := []string{"active", "waiting", "unknown"}
		for index := range count {
			rows.values = append(rows.values, []string{states[index%3], "private-user", "private-address"})
		}
		clients, err := readPoolerClients(t.Context(), poolerQuery(func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if sql != "SHOW CLIENTS" {
				t.Fatalf("unexpected query %q", sql)
			}
			return rows, nil
		}))
		if err != nil || clients.Total != min(count, 4096) || clients.Truncated != (count > 4096) || clients.Total != clients.Active+clients.Waiting+clients.Other {
			t.Fatalf("client aggregation = %+v, %v", clients, err)
		}
		encoded, _ := json.Marshal(clients)
		if strings.Contains(string(encoded), "private") {
			t.Fatal("client identities leaked")
		}
	}
}
