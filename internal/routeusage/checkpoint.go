// Package routeusage defines mergeable route-usage telemetry checkpoints.
package routeusage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"math/bits"
	"net/netip"
	"slices"
	"time"
)

const (
	checkpointVersion            = 1
	durationHistogramBucketCount = 22
	durationHistogramSize        = 8 * (durationHistogramBucketCount + 1)
	visitorHLLPrecision          = 12
	visitorHLLRegisterCount      = 1 << visitorHLLPrecision
	visitorHLLCheckpointVersion  = 1
	visitorHLLSparseCheckpoint   = 0
	visitorHLLDenseCheckpoint    = 1
)

var (
	checkpointMagic              = [...]byte{'T', 'N', 'L', 'U'}
	durationHistogramUpperBounds = [...]time.Duration{
		time.Millisecond,
		5 * time.Millisecond,
		10 * time.Millisecond,
		25 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		250 * time.Millisecond,
		500 * time.Millisecond,
		time.Second,
		2500 * time.Millisecond,
		5 * time.Second,
		10 * time.Second,
		30 * time.Second,
		time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		time.Hour,
		6 * time.Hour,
		24 * time.Hour,
		3 * 24 * time.Hour,
		7 * 24 * time.Hour,
	}
)

// Checkpoint is one cumulative ingress-process contribution to a route bucket.
type Checkpoint struct {
	PublisherOpenLatency         DurationHistogram
	TimeToFirstPublisherByte     DurationHistogram
	SuccessfulConnectionDuration DurationHistogram
	VisitorNetworks              VisitorSketch
}

// Merge combines independent ingress-process checkpoints.
func (c *Checkpoint) Merge(other Checkpoint) error {
	for _, pair := range [][2]*DurationHistogram{
		{&c.PublisherOpenLatency, &other.PublisherOpenLatency},
		{&c.TimeToFirstPublisherByte, &other.TimeToFirstPublisherByte},
		{&c.SuccessfulConnectionDuration, &other.SuccessfulConnectionDuration},
	} {
		if err := pair[0].merge(*pair[1]); err != nil {
			return err
		}
	}
	c.VisitorNetworks.merge(other.VisitorNetworks)
	return nil
}

// MarshalBinary encodes a strict, versioned checkpoint.
func (c Checkpoint) MarshalBinary() []byte {
	sections := [4][]byte{
		c.PublisherOpenLatency.marshalBinary(),
		c.TimeToFirstPublisherByte.marshalBinary(),
		c.SuccessfulConnectionDuration.marshalBinary(),
		c.VisitorNetworks.marshalBinary(),
	}
	data := make([]byte, 0, len(checkpointMagic)+1+2*len(sections)+3+visitorHLLRegisterCount)
	data = append(data, checkpointMagic[:]...)
	data = append(data, checkpointVersion)
	for _, section := range sections {
		data = binary.BigEndian.AppendUint16(data, uint16(len(section)))
		data = append(data, section...)
	}
	return data
}

// ParseCheckpoint decodes and validates one ingress checkpoint.
func ParseCheckpoint(data []byte) (Checkpoint, error) {
	if len(data) < len(checkpointMagic)+1 || !slices.Equal(data[:len(checkpointMagic)], checkpointMagic[:]) ||
		data[len(checkpointMagic)] != checkpointVersion {
		return Checkpoint{}, errors.New("routeusage: invalid checkpoint header")
	}
	offset := len(checkpointMagic) + 1
	sections := [4][]byte{}
	for index := range sections {
		if len(data)-offset < 2 {
			return Checkpoint{}, errors.New("routeusage: truncated checkpoint section")
		}
		size := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if len(data)-offset < size {
			return Checkpoint{}, errors.New("routeusage: truncated checkpoint section")
		}
		sections[index] = data[offset : offset+size]
		offset += size
	}
	if offset != len(data) {
		return Checkpoint{}, errors.New("routeusage: trailing checkpoint data")
	}
	publisherOpenLatency, err := parseDurationHistogram(sections[0])
	if err != nil {
		return Checkpoint{}, err
	}
	timeToFirstPublisherByte, err := parseDurationHistogram(sections[1])
	if err != nil {
		return Checkpoint{}, err
	}
	successfulConnectionDuration, err := parseDurationHistogram(sections[2])
	if err != nil {
		return Checkpoint{}, err
	}
	visitorNetworks, err := parseVisitorSketch(sections[3])
	if err != nil {
		return Checkpoint{}, err
	}
	return Checkpoint{
		PublisherOpenLatency: publisherOpenLatency, TimeToFirstPublisherByte: timeToFirstPublisherByte,
		SuccessfulConnectionDuration: successfulConnectionDuration, VisitorNetworks: visitorNetworks,
	}, nil
}

// DurationHistogram is a cumulative histogram with the route-usage API bounds.
type DurationHistogram struct {
	sumNanoseconds uint64
	counts         [durationHistogramBucketCount]uint64
}

func (h *DurationHistogram) Observe(duration time.Duration) error {
	if duration < 0 {
		duration = 0
	}
	value := uint64(duration)
	if value > math.MaxInt64 || h.sumNanoseconds > math.MaxInt64-value {
		return errors.New("routeusage: duration histogram sum exceeds signed 64-bit range")
	}
	first := len(durationHistogramUpperBounds)
	for index, bound := range durationHistogramUpperBounds {
		if duration <= bound {
			first = index
			break
		}
	}
	for index := first; index < len(h.counts); index++ {
		if h.counts[index] == math.MaxInt64 {
			return errors.New("routeusage: duration histogram count exceeds signed 64-bit range")
		}
	}
	h.sumNanoseconds += value
	for index := first; index < len(h.counts); index++ {
		h.counts[index]++
	}
	return nil
}

func (h *DurationHistogram) merge(other DurationHistogram) error {
	if other.sumNanoseconds > math.MaxInt64 || h.sumNanoseconds > math.MaxInt64-other.sumNanoseconds {
		return errors.New("routeusage: merged duration histogram sum exceeds signed 64-bit range")
	}
	for index, count := range other.counts {
		if count > math.MaxInt64 || h.counts[index] > math.MaxInt64-count {
			return errors.New("routeusage: merged duration histogram count exceeds signed 64-bit range")
		}
	}
	h.sumNanoseconds += other.sumNanoseconds
	for index, count := range other.counts {
		h.counts[index] += count
	}
	return nil
}

func (h DurationHistogram) Count() uint64 { return h.counts[len(h.counts)-1] }

func (h DurationHistogram) SumNanoseconds() uint64 { return h.sumNanoseconds }

func (h DurationHistogram) CumulativeCounts() []uint64 { return slices.Clone(h.counts[:]) }

func (h DurationHistogram) marshalBinary() []byte {
	if h.Count() == 0 {
		return nil
	}
	data := make([]byte, durationHistogramSize)
	binary.BigEndian.PutUint64(data, h.sumNanoseconds)
	for index, count := range h.counts {
		binary.BigEndian.PutUint64(data[8*(index+1):], count)
	}
	return data
}

func parseDurationHistogram(data []byte) (DurationHistogram, error) {
	var histogram DurationHistogram
	if len(data) == 0 {
		return histogram, nil
	}
	if len(data) != durationHistogramSize {
		return histogram, errors.New("routeusage: invalid duration histogram checkpoint")
	}
	histogram.sumNanoseconds = binary.BigEndian.Uint64(data)
	if histogram.sumNanoseconds > math.MaxInt64 {
		return DurationHistogram{}, errors.New("routeusage: duration histogram sum exceeds signed 64-bit range")
	}
	var previous uint64
	for index := range histogram.counts {
		count := binary.BigEndian.Uint64(data[8*(index+1):])
		if count < previous || count > math.MaxInt64 {
			return DurationHistogram{}, errors.New("routeusage: invalid cumulative duration histogram")
		}
		histogram.counts[index] = count
		previous = count
	}
	if histogram.Count() == 0 {
		return DurationHistogram{}, errors.New("routeusage: empty duration histogram must be undefined")
	}
	return histogram, nil
}

// VisitorSketch is a mergeable precision-12 HyperLogLog sketch.
type VisitorSketch struct {
	registers [visitorHLLRegisterCount]byte
}

// Observe records an IPv4 /32 or IPv6 /64 network with a date-scoped key.
func (s *VisitorSketch) Observe(dateKey [32]byte, routeID string, source netip.Addr) bool {
	hash, ok := visitorNetworkHash(dateKey, routeID, source)
	if !ok {
		return false
	}
	index := hash >> (64 - visitorHLLPrecision)
	rank := byte(bits.LeadingZeros64(hash<<visitorHLLPrecision) + 1)
	if maximum := byte(64 - visitorHLLPrecision + 1); rank > maximum {
		rank = maximum
	}
	if rank <= s.registers[index] {
		return false
	}
	s.registers[index] = rank
	return true
}

func (s *VisitorSketch) merge(other VisitorSketch) {
	for index, register := range other.registers {
		if register > s.registers[index] {
			s.registers[index] = register
		}
	}
}

func (s VisitorSketch) Estimate() uint64 {
	var sum float64
	zeros := 0
	for _, register := range s.registers {
		sum += math.Ldexp(1, -int(register))
		if register == 0 {
			zeros++
		}
	}
	m := float64(len(s.registers))
	estimate := (0.7213 / (1 + 1.079/m)) * m * m / sum
	if estimate <= 2.5*m && zeros > 0 {
		estimate = m * math.Log(m/float64(zeros))
	}
	return uint64(math.Round(estimate))
}

func (s VisitorSketch) MarshalBinary() []byte { return s.marshalBinary() }

func (s VisitorSketch) marshalBinary() []byte {
	nonzero := 0
	for _, register := range s.registers {
		if register != 0 {
			nonzero++
		}
	}
	if 5+3*nonzero >= 3+len(s.registers) {
		data := make([]byte, 3+len(s.registers))
		data[0], data[1], data[2] = visitorHLLCheckpointVersion, visitorHLLPrecision, visitorHLLDenseCheckpoint
		copy(data[3:], s.registers[:])
		return data
	}
	data := make([]byte, 5, 5+3*nonzero)
	data[0], data[1], data[2] = visitorHLLCheckpointVersion, visitorHLLPrecision, visitorHLLSparseCheckpoint
	binary.BigEndian.PutUint16(data[3:], uint16(nonzero))
	for index, register := range s.registers {
		if register == 0 {
			continue
		}
		data = binary.BigEndian.AppendUint16(data, uint16(index))
		data = append(data, register)
	}
	return data
}

func parseVisitorSketch(data []byte) (VisitorSketch, error) {
	var sketch VisitorSketch
	if len(data) < 3 || data[0] != visitorHLLCheckpointVersion || data[1] != visitorHLLPrecision {
		return sketch, errors.New("routeusage: invalid visitor HLL checkpoint")
	}
	switch data[2] {
	case visitorHLLSparseCheckpoint:
		if len(data) < 5 {
			return sketch, errors.New("routeusage: invalid sparse visitor HLL checkpoint")
		}
		count := int(binary.BigEndian.Uint16(data[3:]))
		if len(data) != 5+3*count || count > len(sketch.registers) {
			return sketch, errors.New("routeusage: invalid sparse visitor HLL checkpoint")
		}
		previous := -1
		for offset := 5; offset < len(data); offset += 3 {
			index := int(binary.BigEndian.Uint16(data[offset:]))
			register := data[offset+2]
			if index <= previous || index >= len(sketch.registers) || register == 0 ||
				register > 64-visitorHLLPrecision+1 {
				return VisitorSketch{}, errors.New("routeusage: invalid sparse visitor HLL register")
			}
			sketch.registers[index] = register
			previous = index
		}
	case visitorHLLDenseCheckpoint:
		if len(data) != 3+len(sketch.registers) {
			return sketch, errors.New("routeusage: invalid dense visitor HLL checkpoint")
		}
		for index, register := range data[3:] {
			if register > 64-visitorHLLPrecision+1 {
				return VisitorSketch{}, errors.New("routeusage: invalid dense visitor HLL register")
			}
			sketch.registers[index] = register
		}
	default:
		return sketch, errors.New("routeusage: unknown visitor HLL checkpoint encoding")
	}
	return sketch, nil
}

func visitorNetworkHash(dateKey [32]byte, routeID string, source netip.Addr) (uint64, bool) {
	source = source.Unmap()
	if !source.IsValid() || routeID == "" {
		return 0, false
	}
	routeMAC := hmac.New(sha256.New, dateKey[:])
	_, _ = routeMAC.Write([]byte("tnl/route-usage/visitor-route/v1\x00" + routeID))
	visitorMAC := hmac.New(sha256.New, routeMAC.Sum(nil))
	_, _ = visitorMAC.Write([]byte("tnl/route-usage/visitor-network/v1\x00"))
	if source.Is4() {
		_, _ = visitorMAC.Write([]byte{4})
		address := source.As4()
		_, _ = visitorMAC.Write(address[:])
	} else {
		_, _ = visitorMAC.Write([]byte{6})
		network := netip.PrefixFrom(source, 64).Masked().Addr().As16()
		_, _ = visitorMAC.Write(network[:8])
	}
	return binary.BigEndian.Uint64(visitorMAC.Sum(nil)), true
}
