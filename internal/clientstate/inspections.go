package clientstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type InspectionRecord struct {
	Number              int64                              `json:"number"`
	TunnelID            string                             `json:"tunnel_id"`
	PrimaryCheckoutRoot string                             `json:"primary_checkout_root"`
	Project             string                             `json:"project_root"`
	SharedProjectRoot   string                             `json:"shared_project_root"`
	Service             string                             `json:"service,omitempty"`
	Protocol            controlv1.PublicURLServiceProtocol `json:"protocol"`
	ReceivedAt          time.Time                          `json:"received_at"`
	Method              string                             `json:"method,omitempty"`
	Path                string                             `json:"path,omitempty"`
	Status              int                                `json:"status,omitempty"`
	DurationMS          int64                              `json:"duration_ms"`
	Origin              string                             `json:"origin"`
	Operation           inspection.Operation               `json:"operation,omitempty"`
	Result              inspection.Result                  `json:"result,omitempty"`
	RedisCommand        string                             `json:"redis_command,omitempty"`
	SQLState            string                             `json:"sql_state,omitempty"`
	Rows                int64                              `json:"rows,omitempty"`
	ResultSets          int64                              `json:"result_sets,omitempty"`
	MySQLErrorCode      int64                              `json:"mysql_error_code,omitempty"`
}

// InspectionRecorder drops observations instead of blocking visitor traffic.
type InspectionRecorder struct {
	database *Database
	items    chan InspectionRecord
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

func (t *Tunnel) NewInspectionRecorder(primary, project, shared, service string, policy inspection.Policy) *InspectionRecorder {
	ctx, cancel := context.WithCancel(context.Background())
	r := &InspectionRecorder{database: t.database, items: make(chan InspectionRecord, 256), done: make(chan struct{}), ctx: ctx, cancel: cancel}
	go r.run(t.id, primary, project, shared, service, policy)
	return r
}

func (r *InspectionRecorder) Observe(record InspectionRecord) {
	if r == nil {
		return
	}
	select {
	case r.items <- record:
	default:
	}
}

// Close drains queued records after the publisher stops and before client state closes.
func (r *InspectionRecorder) Close() {
	if r == nil {
		return
	}
	close(r.items)
	timer := time.AfterFunc(5*time.Second, r.cancel)
	<-r.done
	timer.Stop()
	r.cancel()
}

func (r *InspectionRecorder) run(tunnelID, primary, project, shared, service string, policy inspection.Policy) {
	defer close(r.done)
	for record := range r.items {
		if r.ctx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(r.ctx, time.Second)
		_ = r.database.saveInspection(ctx, tunnelID, primary, project, shared, service, record, policy)
		cancel()
	}
	if r.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = r.database.pruneInspections(ctx)
	}
}

func validInspectionRecord(record InspectionRecord) bool {
	if record.ReceivedAt.IsZero() || record.DurationMS < 0 ||
		record.SQLState != "" && !inspection.ValidSQLState(record.SQLState) || record.Rows < 0 || record.ResultSets < 0 ||
		record.MySQLErrorCode < 0 || record.MySQLErrorCode > 65535 {
		return false
	}
	if record.Protocol == controlv1.Http {
		return record.Method != "" && record.Status >= 100 && record.Status <= 599 &&
			record.Operation == "" && record.Result == "" && record.RedisCommand == "" && record.SQLState == "" &&
			record.Rows == 0 && record.ResultSets == 0 && record.MySQLErrorCode == 0
	}
	if record.Protocol == controlv1.Redis {
		if record.Operation != "" || !record.Result.Valid() || record.Method != "" || record.Path != "" || record.Status != 0 ||
			record.SQLState != "" || record.Rows != 0 || record.ResultSets != 0 || record.MySQLErrorCode != 0 || record.Origin != "tnl" ||
			len(record.RedisCommand) == 0 || len(record.RedisCommand) > 64 {
			return false
		}
		for _, value := range record.RedisCommand {
			if value < 'A' || value > 'Z' {
				if value < '0' || value > '9' {
					if value != '.' && value != '_' && value != '-' {
						return false
					}
				}
			}
		}
		return true
	}
	if record.Protocol != controlv1.Postgres && record.Protocol != controlv1.Mysql ||
		!record.Operation.Valid() || !record.Result.Valid() || record.RedisCommand != "" || record.Method != "" || record.Path != "" || record.Status != 0 ||
		record.MySQLErrorCode != 0 && record.Protocol != controlv1.Mysql ||
		record.ResultSets != 0 && record.Protocol != controlv1.Mysql {
		return false
	}
	return true
}

func (d *Database) saveInspection(ctx context.Context, tunnelID, primary, project, shared, service string,
	record InspectionRecord, policy inspection.Policy) error {
	if primary == "" || project == "" || shared == "" || tunnelID == "" ||
		policy.Retention < time.Minute || policy.Retention > inspection.MaxRetention ||
		policy.MaxBytes < inspection.MinMaxBytes || policy.MaxBytes > inspection.MaxMaxBytes {
		return errors.New("clientstate: invalid inspection scope or policy")
	}
	if record.Protocol == "" {
		record.Protocol = controlv1.Http
	}
	if !validInspectionRecord(record) {
		return errors.New("clientstate: invalid inspection observation")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("clientstate: encode inspection: %w", err)
	}
	// account for the typed record and identifying columns; SQLite's other
	// client-state tables and reusable pages are outside this inspection budget.
	storedBytes := int64(len(encoded) + len(primary) + len(project) + len(shared) + len(service) + len(tunnelID) + 128)
	if storedBytes > policy.MaxBytes {
		return errors.New("clientstate: inspection exceeds this service's byte budget")
	}
	registeredAt := d.now()
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := clientstatedb.New(tx)
	if err := queries.DeleteExpiredInspections(ctx, registeredAt.UnixNano()); err != nil {
		return err
	}
	number, err := queries.NextInspectionNumber(ctx, primary)
	if err != nil {
		return err
	}
	if err := queries.InsertInspection(ctx, clientstatedb.InsertInspectionParams{
		Number: number, PrimaryCheckoutRoot: primary, TunnelID: tunnelID,
		ProjectRoot: project, SharedProjectRoot: shared, Service: service, ServiceProtocol: string(record.Protocol),
		ReceivedAt: record.ReceivedAt.UnixNano(), ExpiresAt: registeredAt.Add(policy.Retention).UnixNano(), StoredBytes: storedBytes,
		Method: record.Method, Path: record.Path, Status: int64(record.Status), DurationMs: record.DurationMS,
		Origin: record.Origin, SqlOperation: string(record.Operation), Result: string(record.Result),
		RedisCommand: record.RedisCommand, SqlState: record.SQLState, SqlRows: record.Rows,
		MysqlResultSets: record.ResultSets, MysqlErrorCode: record.MySQLErrorCode,
	}); err != nil {
		return err
	}
	var usedBytes int64
	if err := tx.QueryRowContext(ctx, `SELECT used_bytes FROM local_inspection_usage WHERE project_root = ? AND service = ?`,
		project, service).Scan(&usedBytes); err != nil {
		return fmt.Errorf("clientstate: read service inspection budget: %w", err)
	}
	for usedBytes > policy.MaxBytes {
		var rowID, oldBytes int64
		if err := tx.QueryRowContext(ctx, `SELECT row_id, stored_bytes FROM local_inspections
			WHERE project_root = ? AND service = ? ORDER BY received_at, row_id LIMIT 1`, project, service).Scan(&rowID, &oldBytes); err != nil {
			return fmt.Errorf("clientstate: read oldest service inspection: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM local_inspections WHERE row_id = ?`, rowID); err != nil {
			return fmt.Errorf("clientstate: prune service inspection budget: %w", err)
		}
		usedBytes -= oldBytes
	}
	return tx.Commit()
}

func (d *Database) pruneInspections(ctx context.Context) error {
	return d.queries.DeleteExpiredInspections(ctx, d.now().UnixNano())
}

type InspectionFilter struct {
	Project       string
	SharedProject string
	AllWorktrees  bool
	Service       string
	Protocol      controlv1.PublicURLServiceProtocol
	Method        string
	Status        int
	Result        inspection.Result
	Since         time.Time
	Limit         int
}

func (d *Database) ListInspections(ctx context.Context, filter InspectionFilter) ([]InspectionRecord, error) {
	if filter.Project == "" || filter.SharedProject == "" || filter.Limit < 1 || filter.Limit > 500 ||
		filter.Result != "" && !filter.Result.Valid() ||
		filter.Protocol != "" && filter.Protocol != controlv1.Http && filter.Protocol != controlv1.Postgres && filter.Protocol != controlv1.Mysql && filter.Protocol != controlv1.Redis ||
		filter.Protocol != "" && filter.Protocol != controlv1.Http && (filter.Method != "" || filter.Status != 0) {
		return nil, errors.New("clientstate: invalid inspection filter")
	}
	_ = d.pruneInspections(ctx)
	column, selected := "project_root", filter.Project
	if filter.AllWorktrees {
		column, selected = "shared_project_root", filter.SharedProject
	}
	query := `SELECT number, primary_checkout_root, tunnel_id, project_root, shared_project_root,
		service, service_protocol, received_at, method, path, status, duration_ms, origin,
		sql_operation, result, redis_command, sql_state, sql_rows, mysql_result_sets, mysql_error_code
		FROM local_inspections WHERE ` + column + ` = ? AND expires_at > ? AND (? = '' OR service = ?)
		AND (? = '' OR service_protocol = ?) AND (? = '' OR method = ?) AND (? = 0 OR status = ?)
		AND (? = '' OR CASE WHEN service_protocol = 'http' THEN
		 CASE WHEN status >= 400 THEN 'error' ELSE 'ok' END ELSE result END = ?)
		AND (? = 0 OR received_at >= ?) ORDER BY received_at DESC, row_id DESC LIMIT ?`
	cutoff := int64(0)
	if !filter.Since.IsZero() {
		cutoff = filter.Since.UnixNano()
	}
	rows, err := d.db.QueryContext(ctx, query, selected, d.now().UnixNano(), filter.Service, filter.Service,
		filter.Protocol, filter.Protocol, filter.Method, filter.Method, filter.Status, filter.Status,
		filter.Result, filter.Result, cutoff, cutoff, filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("clientstate: list inspections: %w", err)
	}
	defer rows.Close()
	items := make([]InspectionRecord, 0)
	for rows.Next() {
		item, err := scanInspection(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type inspectionScanner interface{ Scan(...any) error }

func scanInspection(row inspectionScanner) (InspectionRecord, error) {
	var item InspectionRecord
	var nanos int64
	err := row.Scan(&item.Number, &item.PrimaryCheckoutRoot, &item.TunnelID, &item.Project,
		&item.SharedProjectRoot, &item.Service, &item.Protocol, &nanos, &item.Method, &item.Path, &item.Status,
		&item.DurationMS, &item.Origin,
		&item.Operation, &item.Result, &item.RedisCommand, &item.SQLState, &item.Rows, &item.ResultSets, &item.MySQLErrorCode)
	if err != nil {
		return item, fmt.Errorf("clientstate: read inspection: %w", err)
	}
	item.ReceivedAt = time.Unix(0, nanos).UTC()
	return item, nil
}

func (d *Database) GetInspection(ctx context.Context, primary string, number int64) (InspectionRecord, error) {
	_ = d.pruneInspections(ctx)
	row := d.db.QueryRowContext(ctx, `SELECT number, primary_checkout_root, tunnel_id, project_root,
		shared_project_root, service, service_protocol, received_at, method, path, status, duration_ms, origin,
		sql_operation, result, redis_command, sql_state, sql_rows, mysql_result_sets, mysql_error_code
		FROM local_inspections WHERE primary_checkout_root = ? AND number = ? AND expires_at > ?`,
		primary, number, d.now().UnixNano())
	return scanInspection(row)
}
