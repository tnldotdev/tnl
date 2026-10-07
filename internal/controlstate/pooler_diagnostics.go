package controlstate

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// PgBouncer may deny its admin console to the runtime user. unavailable values
// remain absent and carry a sanitized error; they are never inferred from SKU.
type DatabasePoolerDiagnostics struct {
	Settings map[string]string      `json:"settings,omitempty"`
	Clients  *DatabasePoolerClients `json:"clients,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

type DatabasePoolerClients struct {
	Total     int  `json:"total"`
	Active    int  `json:"active"`
	Waiting   int  `json:"waiting"`
	Other     int  `json:"other"`
	Truncated bool `json:"truncated"`
}

func (d *Database) poolerDiagnostics(parent context.Context) (result *DatabasePoolerDiagnostics) {
	result = &DatabasePoolerDiagnostics{}
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	config := d.dedicatedConnectionConfig(poolerDiagnosticConnection)
	config.Database = "pgbouncer"
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		result.Error = databaseDiagnosticsMessage(databaseDiagnosticsError(ctx, err))
		return result
	}
	defer func() {
		closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = connection.Close(closeCtx)
	}()
	result.Settings, err = readPoolerSettings(ctx, connection)
	if err != nil {
		result.Error = "settings: " + databaseDiagnosticsMessage(databaseDiagnosticsError(ctx, err))
	}
	result.Clients, err = readPoolerClients(ctx, connection)
	if err != nil {
		if result.Error != "" {
			result.Error += "; "
		}
		result.Error += "clients: " + databaseDiagnosticsMessage(databaseDiagnosticsError(ctx, err))
	}
	return result
}

type poolerQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func readPoolerSettings(ctx context.Context, connection poolerQuerier) (map[string]string, error) {
	rows, err := connection.Query(ctx, "SHOW CONFIG")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	settings := make(map[string]string)
	count := 0
	for rows.Next() {
		count++
		if count > 512 {
			return nil, errors.New("pooler settings limit exceeded")
		}
		key, value := poolerColumn(rows, "key"), poolerColumn(rows, "value")
		switch key {
		case "pool_mode":
			if value == "session" || value == "transaction" || value == "statement" {
				settings[key] = value
			}
		case "max_client_conn", "default_pool_size", "reserve_pool_size", "max_db_connections", "max_user_connections", "server_lifetime", "client_idle_timeout":
			if number, err := strconv.ParseUint(value, 10, 32); err == nil {
				settings[key] = strconv.FormatUint(number, 10)
			}
		}
	}
	return settings, rows.Err()
}

// includes the observing admin client; client identities and addresses are
// never retained. A bounded partial count is explicitly marked as such.
func readPoolerClients(ctx context.Context, connection poolerQuerier) (*DatabasePoolerClients, error) {
	rows, err := connection.Query(ctx, "SHOW CLIENTS")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &DatabasePoolerClients{}
	for rows.Next() {
		if result.Total == 4096 {
			result.Truncated = true
			break
		}
		result.Total++
		switch poolerColumn(rows, "state") {
		case "active":
			result.Active++
		case "waiting":
			result.Waiting++
		default:
			result.Other++
		}
	}
	return result, rows.Err()
}

func poolerColumn(rows pgx.Rows, name string) string {
	for index, field := range rows.FieldDescriptions() {
		if field.Name == name {
			return string(rows.RawValues()[index])
		}
	}
	return ""
}
