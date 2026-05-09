package routeusage

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

const checkpointInterval = 10 * time.Second

type bucketKey struct {
	routeID       string
	version       uint64
	resolution    string
	startUnixNano int64
}

type usageBucket struct {
	key                   bucketKey
	observedThrough       time.Time
	connectionsOpened     uint64
	connectionNanoseconds uint64
	ingressBytes          uint64
	egressBytes           uint64
	revision              uint64
	lastPublishedThrough  time.Time
	canComplete           bool
	complete              bool
	sealed                bool
	dirty                 bool
	publish               bool
	version               uint64
}

type Collector struct {
	store    *Store
	observer Observer
	now      func() time.Time

	mu          sync.Mutex
	buckets     map[bucketKey]*usageBucket
	connections map[*Connection]struct{}
	err         error
}

type Connection struct {
	collector *Collector
	routeID   string
	version   uint64
	lastAt    time.Time
	closed    bool
}

func NewCollector(store *Store, observer Observer) *Collector {
	return &Collector{
		store: store, observer: observer, now: time.Now, buckets: make(map[bucketKey]*usageBucket),
		connections: make(map[*Connection]struct{}),
	}
}

func (c *Collector) Recover(ctx context.Context) error {
	now := c.now().UTC()
	rows, err := c.store.LoadIncompleteUsage(ctx)
	if err != nil {
		return err
	}
	var stale []UsageSnapshot
	c.mu.Lock()
	for _, row := range rows {
		start := time.Unix(0, row.BucketStart).UTC()
		bucket := &usageBucket{
			key:             bucketKey{routeID: row.RouteID, version: uint64(row.Version), resolution: row.Resolution, startUnixNano: row.BucketStart},
			observedThrough: time.Unix(0, row.ObservedThrough).UTC(), connectionsOpened: uint64(row.ConnectionsOpened),
			connectionNanoseconds: uint64(row.ConnectionNanoseconds), ingressBytes: uint64(row.IngressBytes),
			egressBytes: uint64(row.EgressBytes), revision: uint64(row.Revision),
			lastPublishedThrough: time.Unix(0, row.ObservedThrough).UTC(), canComplete: false,
		}
		if !now.Before(bucketEnd(start, row.Resolution)) {
			bucket.revision++
			stale = append(stale, bucket.snapshot(true))
			continue
		}
		c.buckets[bucket.key] = bucket
	}
	c.mu.Unlock()
	return c.store.SaveUsage(ctx, stale)
}

func (c *Collector) Open(routeID string, version uint64, at time.Time) *Connection {
	at = at.UTC()
	connection := &Connection{collector: c, routeID: routeID, version: version, lastAt: at}
	c.mu.Lock()
	c.connections[connection] = struct{}{}
	c.addConnectionOpened(routeID, version, at)
	c.mu.Unlock()
	return connection
}

func (connection *Connection) AddIngress(bytes int64, at time.Time) {
	connection.observe(bytes, 0, at)
}

func (connection *Connection) AddEgress(bytes int64, at time.Time) {
	connection.observe(0, bytes, at)
}

func (connection *Connection) Close(at time.Time) {
	c := connection.collector
	c.mu.Lock()
	defer c.mu.Unlock()
	if connection.closed {
		return
	}
	c.advanceConnection(connection, at.UTC())
	connection.closed = true
	delete(c.connections, connection)
}

func (connection *Connection) observe(ingressBytes, egressBytes int64, at time.Time) {
	if ingressBytes <= 0 && egressBytes <= 0 {
		return
	}
	c := connection.collector
	c.mu.Lock()
	defer c.mu.Unlock()
	if connection.closed {
		return
	}
	at = at.UTC()
	c.advanceConnection(connection, at)
	c.addBytes(connection.routeID, connection.version, ingressBytes, egressBytes, at)
}

func (c *Collector) Run(ctx context.Context, report func(error)) {
	ticker := time.NewTicker(checkpointInterval)
	defer ticker.Stop()
	boundary := time.NewTimer(untilNextMinute(c.now()))
	defer boundary.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := c.Checkpoint(ctx, now, false); err != nil && report != nil {
				report(err)
			}
		case now := <-boundary.C:
			if err := c.Checkpoint(ctx, now, true); err != nil && report != nil {
				report(err)
			}
			boundary.Reset(untilNextMinute(c.now()))
		}
	}
}

func (c *Collector) Checkpoint(ctx context.Context, now time.Time, publishHours bool) (result error) {
	defer func() {
		if c.observer == nil {
			return
		}
		if result != nil {
			c.observer.ObserveRouteUsageCheckpoint("error")
		} else {
			c.observer.ObserveRouteUsageCheckpoint("success")
		}
	}()
	now = now.UTC()
	c.mu.Lock()
	for connection := range c.connections {
		c.advanceConnection(connection, now)
	}
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return err
	}
	for _, bucket := range c.buckets {
		end := bucketEnd(time.Unix(0, bucket.key.startUnixNano).UTC(), bucket.key.resolution)
		through := now
		if through.After(end) {
			through = end
		}
		if through.After(bucket.observedThrough) {
			bucket.observedThrough = through
			markDirty(bucket)
		}
		if !now.Before(end) {
			bucket.sealed = true
			bucket.complete = bucket.canComplete
			bucket.observedThrough = end
			markDirty(bucket)
		}
		shouldPublish := bucket.key.resolution == "minute" && bucket.sealed
		if bucket.key.resolution == "hour" && publishHours && bucket.observedThrough.After(bucket.lastPublishedThrough) {
			shouldPublish = true
		}
		if shouldPublish && !bucket.publish {
			bucket.revision++
			bucket.publish = true
			markDirty(bucket)
		}
	}
	var snapshots []UsageSnapshot
	var saved []*usageBucket
	var versions []uint64
	for _, bucket := range c.buckets {
		if !bucket.dirty {
			continue
		}
		snapshots = append(snapshots, bucket.snapshot(bucket.publish))
		saved = append(saved, bucket)
		versions = append(versions, bucket.version)
	}
	c.mu.Unlock()

	if err := c.store.SaveUsage(ctx, snapshots); err != nil {
		return err
	}
	c.mu.Lock()
	for index, bucket := range saved {
		unchanged := bucket.version == versions[index]
		if unchanged {
			bucket.dirty = false
		}
		if snapshots[index].Publish {
			bucket.lastPublishedThrough = snapshots[index].ObservedThrough
			bucket.publish = false
		}
		if bucket.sealed && unchanged {
			delete(c.buckets, bucket.key)
		}
	}
	c.mu.Unlock()
	return nil
}

func (b *usageBucket) snapshot(publish bool) UsageSnapshot {
	return UsageSnapshot{
		RouteID: b.key.routeID, Version: b.key.version, Resolution: b.key.resolution,
		BucketStart: time.Unix(0, b.key.startUnixNano).UTC(), Revision: b.revision,
		ObservedThrough: b.observedThrough, ConnectionsOpened: b.connectionsOpened,
		ConnectionNanoseconds: b.connectionNanoseconds, IngressBytes: b.ingressBytes, EgressBytes: b.egressBytes,
		Complete: b.complete, Publish: publish,
	}
}

func (c *Collector) addConnectionOpened(routeID string, version uint64, at time.Time) {
	for _, resolution := range []string{"minute", "hour"} {
		bucket := c.bucket(routeID, version, resolution, at)
		bucket.connectionsOpened = c.add(bucket.connectionsOpened, 1)
		markDirty(bucket)
	}
}

func (c *Collector) addBytes(routeID string, version uint64, ingressBytes, egressBytes int64, at time.Time) {
	for _, resolution := range []string{"minute", "hour"} {
		bucket := c.bucket(routeID, version, resolution, at)
		if ingressBytes > 0 {
			bucket.ingressBytes = c.add(bucket.ingressBytes, uint64(ingressBytes))
		}
		if egressBytes > 0 {
			bucket.egressBytes = c.add(bucket.egressBytes, uint64(egressBytes))
		}
		if at.After(bucket.observedThrough) {
			bucket.observedThrough = at
		}
		markDirty(bucket)
	}
}

func (c *Collector) advanceConnection(connection *Connection, at time.Time) {
	if !at.After(connection.lastAt) {
		return
	}
	cursor := connection.lastAt
	for cursor.Before(at) {
		segmentEnd := cursor.Truncate(time.Minute).Add(time.Minute)
		if segmentEnd.After(at) {
			segmentEnd = at
		}
		duration := uint64(segmentEnd.Sub(cursor))
		for _, resolution := range []string{"minute", "hour"} {
			bucket := c.bucket(connection.routeID, connection.version, resolution, cursor)
			bucket.connectionNanoseconds = c.add(bucket.connectionNanoseconds, duration)
			if segmentEnd.After(bucket.observedThrough) {
				bucket.observedThrough = segmentEnd
			}
			markDirty(bucket)
		}
		cursor = segmentEnd
	}
	connection.lastAt = at
}

func (c *Collector) bucket(routeID string, version uint64, resolution string, at time.Time) *usageBucket {
	start := at.Truncate(time.Minute)
	if resolution == "hour" {
		start = at.Truncate(time.Hour)
	}
	key := bucketKey{routeID: routeID, version: version, resolution: resolution, startUnixNano: start.UnixNano()}
	bucket := c.buckets[key]
	if bucket == nil {
		bucket = &usageBucket{key: key, observedThrough: start, canComplete: true}
		c.buckets[key] = bucket
	}
	return bucket
}

func (c *Collector) add(left, right uint64) uint64 {
	if right > math.MaxInt64 || left > math.MaxInt64-right {
		c.err = errors.New("routeusage: usage counter exceeds SQLite integer range")
		return left
	}
	return left + right
}

func markDirty(bucket *usageBucket) {
	bucket.version++
	bucket.dirty = true
}

func bucketEnd(start time.Time, resolution string) time.Time {
	if resolution == "hour" {
		return start.Add(time.Hour)
	}
	return start.Add(time.Minute)
}

func untilNextMinute(now time.Time) time.Duration {
	delay := now.UTC().Truncate(time.Minute).Add(time.Minute).Sub(now)
	if delay <= 0 {
		return time.Minute
	}
	return delay
}

func (c *Collector) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprintf("route usage buckets=%d connections=%d", len(c.buckets), len(c.connections))
}
