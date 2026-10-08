package clientstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	requestRetention      = 24 * time.Hour
	requestMaxRows        = 2000
	requestMaxDetailBytes = 64 << 20
)

type RequestRecord struct {
	RequestNumber       int64           `json:"request_number"`
	TunnelID            string          `json:"tunnel_id"`
	PrimaryCheckoutRoot string          `json:"primary_checkout_root"`
	Project             string          `json:"project_root"`
	SharedProjectRoot   string          `json:"shared_project_root"`
	Service             string          `json:"service,omitempty"`
	ReceivedAt          time.Time       `json:"received_at"`
	Method              string          `json:"method"`
	Path                string          `json:"path"`
	Status              int             `json:"status"`
	DurationMS          int64           `json:"duration_ms"`
	Origin              string          `json:"origin"`
	CaptureMode         string          `json:"capture_mode"`
	DetailAvailable     bool            `json:"detail_available"`
	Detail              json.RawMessage `json:"detail,omitempty"`
}

// RequestRecorder drops observations rather than delaying a visitor when its queue is full.
type RequestRecorder struct {
	database *Database
	items    chan RequestRecord
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

func (t *Tunnel) NewRequestRecorder(primary, project, shared, service string) *RequestRecorder {
	ctx, cancel := context.WithCancel(context.Background())
	r := &RequestRecorder{database: t.database, items: make(chan RequestRecord, 256), done: make(chan struct{}), ctx: ctx, cancel: cancel}
	go r.run(t.id, primary, project, shared, service)
	return r
}

func (r *RequestRecorder) Observe(record RequestRecord) {
	select {
	case r.items <- record:
	default:
	}
}

// Close drains queued records after the publisher stops and before client state closes.
func (r *RequestRecorder) Close() {
	close(r.items)
	timer := time.AfterFunc(5*time.Second, r.cancel)
	<-r.done
	timer.Stop()
	r.cancel()
}

func (r *RequestRecorder) run(tunnelID, primary, project, shared, service string) {
	defer close(r.done)
	count := 0
	for record := range r.items {
		if r.ctx.Err() != nil {
			break
		}
		ctx, cancel := context.WithTimeout(r.ctx, time.Second)
		_ = r.database.saveRequest(ctx, tunnelID, primary, project, shared, service, record)
		count++
		if count%100 == 0 {
			_ = r.database.pruneRequests(ctx)
		}
		cancel()
	}
	if r.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = r.database.pruneRequests(ctx)
}

func (d *Database) saveRequest(ctx context.Context, tunnelID, primary, project, shared, service string, record RequestRecord) error {
	if primary == "" || project == "" || shared == "" || record.ReceivedAt.IsZero() {
		return errors.New("clientstate: invalid request observation")
	}
	mode := record.CaptureMode
	if mode == "" {
		mode = "summary"
	}
	var detail any
	if len(record.Detail) != 0 && json.Valid(record.Detail) {
		detail = string(record.Detail)
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var number int64
	err = tx.QueryRowContext(ctx, `INSERT INTO local_request_counters (primary_checkout_root, last_number) VALUES (?, 1)
		ON CONFLICT (primary_checkout_root) DO UPDATE SET last_number = last_number + 1 RETURNING last_number`, primary).Scan(&number)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO local_requests
		(request_number, primary_checkout_root, tunnel_id, project_root, shared_project_root,
		 service, received_at, method, path, status, duration_ms, origin, capture_mode, detail_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		number, primary, tunnelID, project, shared, service, record.ReceivedAt.UnixNano(),
		record.Method, record.Path, record.Status, record.DurationMS, record.Origin, mode, detail)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (d *Database) pruneRequests(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM local_requests WHERE received_at < ?`, d.now().Add(-requestRetention).UnixNano()); err != nil {
		return err
	}
	if _, err := d.db.ExecContext(ctx, `DELETE FROM local_requests WHERE row_id NOT IN
		(SELECT row_id FROM local_requests ORDER BY received_at DESC, row_id DESC LIMIT ?)`, requestMaxRows); err != nil {
		return err
	}
	_, err := d.db.ExecContext(ctx, `DELETE FROM local_requests WHERE row_id IN
		(SELECT row_id FROM (SELECT row_id, sum(length(detail_json)) OVER
		 (ORDER BY received_at DESC, row_id DESC) AS used FROM local_requests) WHERE used > ?)`, requestMaxDetailBytes)
	return err
}

type RequestFilter struct {
	Project       string
	SharedProject string
	AllWorktrees  bool
	Service       string
	Method        string
	Status        int
	Since         time.Time
	Limit         int
}

func (d *Database) ListRequests(ctx context.Context, filter RequestFilter) ([]RequestRecord, error) {
	if filter.Project == "" || filter.SharedProject == "" || filter.Limit < 1 || filter.Limit > 500 {
		return nil, errors.New("clientstate: project and limit between 1 and 500 are required")
	}
	_ = d.pruneRequests(ctx)
	cutoff := d.now().Add(-requestRetention)
	if filter.Since.After(cutoff) {
		cutoff = filter.Since
	}
	column, selected := "project_root", filter.Project
	if filter.AllWorktrees {
		column, selected = "shared_project_root", filter.SharedProject
	}
	query := `SELECT request_number, primary_checkout_root, tunnel_id, project_root, shared_project_root,
		service, received_at, method, path, status, duration_ms, origin, capture_mode, NULL AS detail_json,
		(detail_json IS NOT NULL) AS detail_available
		FROM local_requests WHERE ` + column + ` = ? AND (? = '' OR service = ?) AND (? = '' OR method = ?)
		AND (? = 0 OR status = ?) AND received_at >= ? ORDER BY received_at DESC, row_id DESC LIMIT ?`
	rows, err := d.db.QueryContext(ctx, query, selected, filter.Service, filter.Service, filter.Method, filter.Method,
		filter.Status, filter.Status, cutoff.UnixNano(), filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("clientstate: list requests: %w", err)
	}
	defer rows.Close()
	items := make([]RequestRecord, 0)
	for rows.Next() {
		item, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type requestScanner interface{ Scan(...any) error }

func scanRequest(row requestScanner) (RequestRecord, error) {
	var item RequestRecord
	var nanos int64
	var detail sql.NullString
	var available int
	err := row.Scan(&item.RequestNumber, &item.PrimaryCheckoutRoot, &item.TunnelID, &item.Project,
		&item.SharedProjectRoot, &item.Service, &nanos, &item.Method, &item.Path, &item.Status,
		&item.DurationMS, &item.Origin, &item.CaptureMode, &detail, &available)
	if err != nil {
		return item, fmt.Errorf("clientstate: read request: %w", err)
	}
	item.ReceivedAt = time.Unix(0, nanos).UTC()
	item.DetailAvailable = available != 0
	if detail.Valid {
		item.Detail = json.RawMessage(detail.String)
	}
	return item, nil
}

func (d *Database) GetRequest(ctx context.Context, primary string, number int64) (RequestRecord, error) {
	_ = d.pruneRequests(ctx)
	row := d.db.QueryRowContext(ctx, `SELECT request_number, primary_checkout_root, tunnel_id, project_root,
		shared_project_root, service, received_at, method, path, status, duration_ms, origin, capture_mode, detail_json,
		(detail_json IS NOT NULL) AS detail_available
		FROM local_requests WHERE primary_checkout_root = ? AND request_number = ? AND received_at >= ?`,
		primary, number, d.now().Add(-requestRetention).UnixNano())
	return scanRequest(row)
}
