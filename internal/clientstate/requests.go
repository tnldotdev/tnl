package clientstate

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	requestRetention = 24 * time.Hour
	requestMaxRows   = 2000
)

type RequestRecord struct {
	ID         int64     `json:"id"`
	TunnelID   string    `json:"tunnel_id"`
	Project    string    `json:"project"`
	Service    string    `json:"service,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	DurationMS int64     `json:"duration_ms"`
	Origin     string    `json:"origin"`
}

// RequestRecorder drops observations rather than delaying a visitor when its queue is full.
type RequestRecorder struct {
	database *Database
	items    chan RequestRecord
	done     chan struct{}
}

func (t *Tunnel) NewRequestRecorder(project, service string) *RequestRecorder {
	r := &RequestRecorder{database: t.database, items: make(chan RequestRecord, 256), done: make(chan struct{})}
	go r.run(t.id, project, service)
	return r
}

func (r *RequestRecorder) Observe(record RequestRecord) {
	select {
	case r.items <- record:
	default:
	}
}

// Close drains queued records before the client database closes. call after the publisher stops.
func (r *RequestRecorder) Close() {
	close(r.items)
	<-r.done
}

func (r *RequestRecorder) run(tunnelID, project, service string) {
	defer close(r.done)
	count := 0
	for record := range r.items {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, _ = r.database.db.ExecContext(ctx, `INSERT INTO local_requests
			(tunnel_id, project_root, service, received_at, method, path, status, duration_ms, origin)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, tunnelID, project, service,
			record.ReceivedAt.UnixNano(), record.Method, record.Path, record.Status, record.DurationMS, record.Origin)
		count++
		if count%100 == 0 {
			_ = r.database.pruneRequests(ctx)
		}
		cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = r.database.pruneRequests(ctx)
}

func (d *Database) pruneRequests(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM local_requests WHERE received_at < ?`, d.now().Add(-requestRetention).UnixNano()); err != nil {
		return err
	}
	_, err := d.db.ExecContext(ctx, `DELETE FROM local_requests WHERE id NOT IN
		(SELECT id FROM local_requests ORDER BY received_at DESC, id DESC LIMIT ?)`, requestMaxRows)
	return err
}

type RequestFilter struct {
	Project string
	Service string
	Method  string
	Status  int
	Since   time.Time
	Limit   int
}

func (d *Database) ListRequests(ctx context.Context, filter RequestFilter) ([]RequestRecord, error) {
	if filter.Project == "" || filter.Limit < 1 || filter.Limit > 500 {
		return nil, errors.New("clientstate: project and limit between 1 and 500 are required")
	}
	cutoff := d.now().Add(-requestRetention)
	if filter.Since.After(cutoff) {
		cutoff = filter.Since
	}
	rows, err := d.db.QueryContext(ctx, `SELECT id, tunnel_id, project_root, service, received_at, method, path, status, duration_ms, origin
		FROM local_requests WHERE project_root = ? AND (? = '' OR service = ?) AND (? = '' OR method = ?)
		AND (? = 0 OR status = ?) AND received_at >= ? ORDER BY received_at DESC, id DESC LIMIT ?`,
		filter.Project, filter.Service, filter.Service, filter.Method, filter.Method,
		filter.Status, filter.Status, cutoff.UnixNano(), filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("clientstate: list requests: %w", err)
	}
	defer rows.Close()
	items := make([]RequestRecord, 0)
	for rows.Next() {
		var item RequestRecord
		var nanos int64
		if err := rows.Scan(&item.ID, &item.TunnelID, &item.Project, &item.Service, &nanos,
			&item.Method, &item.Path, &item.Status, &item.DurationMS, &item.Origin); err != nil {
			return nil, fmt.Errorf("clientstate: read request: %w", err)
		}
		item.ReceivedAt = time.Unix(0, nanos).UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (d *Database) GetRequest(ctx context.Context, project string, id int64) (RequestRecord, error) {
	var item RequestRecord
	var nanos int64
	err := d.db.QueryRowContext(ctx, `SELECT id, tunnel_id, project_root, service, received_at, method, path, status, duration_ms, origin
		FROM local_requests WHERE project_root = ? AND id = ? AND received_at >= ?`, project, id,
		d.now().Add(-requestRetention).UnixNano()).Scan(&item.ID, &item.TunnelID,
		&item.Project, &item.Service, &nanos, &item.Method, &item.Path, &item.Status, &item.DurationMS, &item.Origin)
	if err != nil {
		return item, fmt.Errorf("clientstate: read request: %w", err)
	}
	item.ReceivedAt = time.Unix(0, nanos).UTC()
	return item, nil
}
