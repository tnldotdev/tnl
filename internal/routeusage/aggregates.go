package routeusage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"math/bits"
	"net/netip"
	"time"
)

const (
	durationHistogramBucketCount = 22
	durationHistogramSize        = 8 * (durationHistogramBucketCount + 1)
	visitorHLLPrecision          = 12
	visitorHLLRegisterCount      = 1 << visitorHLLPrecision
	visitorHLLCheckpointVersion  = 1
	visitorHLLSparseCheckpoint   = 0
	visitorHLLDenseCheckpoint    = 1
)

var durationHistogramUpperBounds = [...]time.Duration{
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

type durationHistogram struct {
	sumNanoseconds uint64
	counts         [durationHistogramBucketCount]uint64
}

func (h *durationHistogram) observe(duration time.Duration) bool {
	if duration < 0 {
		duration = 0
	}
	value := uint64(duration)
	if value > math.MaxInt64 || h.sumNanoseconds > math.MaxInt64-value {
		return false
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
			return false
		}
	}
	h.sumNanoseconds += value
	for index := first; index < len(h.counts); index++ {
		h.counts[index]++
	}
	return true
}

func (h durationHistogram) count() uint64 {
	return h.counts[len(h.counts)-1]
}

func (h durationHistogram) marshalBinary() []byte {
	if h.count() == 0 {
		return nil
	}
	data := make([]byte, durationHistogramSize)
	binary.BigEndian.PutUint64(data, h.sumNanoseconds)
	for index, count := range h.counts {
		binary.BigEndian.PutUint64(data[8*(index+1):], count)
	}
	return data
}

func unmarshalDurationHistogram(data []byte) (durationHistogram, error) {
	var histogram durationHistogram
	if len(data) == 0 {
		return histogram, nil
	}
	if len(data) != durationHistogramSize {
		return histogram, errors.New("routeusage: invalid duration histogram checkpoint")
	}
	histogram.sumNanoseconds = binary.BigEndian.Uint64(data)
	if histogram.sumNanoseconds > math.MaxInt64 {
		return durationHistogram{}, errors.New("routeusage: duration histogram sum exceeds SQLite integer range")
	}
	var previous uint64
	for index := range histogram.counts {
		count := binary.BigEndian.Uint64(data[8*(index+1):])
		if count < previous || count > math.MaxInt64 {
			return durationHistogram{}, errors.New("routeusage: invalid cumulative duration histogram")
		}
		histogram.counts[index] = count
		previous = count
	}
	if histogram.count() == 0 {
		return durationHistogram{}, errors.New("routeusage: empty duration histogram must be undefined")
	}
	return histogram, nil
}

type visitorSketch struct {
	registers [visitorHLLRegisterCount]byte
}

func (s *visitorSketch) insert(hash uint64) bool {
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

func (s *visitorSketch) merge(other visitorSketch) {
	for index, register := range other.registers {
		if register > s.registers[index] {
			s.registers[index] = register
		}
	}
}

func (s *visitorSketch) estimate() uint64 {
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

func (s *visitorSketch) checkpoint() []byte {
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

func visitorSketchFromCheckpoint(data []byte) (visitorSketch, error) {
	var sketch visitorSketch
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
			if index <= previous || index >= len(sketch.registers) || register == 0 || register > 64-visitorHLLPrecision+1 {
				return visitorSketch{}, errors.New("routeusage: invalid sparse visitor HLL register")
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
				return visitorSketch{}, errors.New("routeusage: invalid dense visitor HLL register")
			}
			sketch.registers[index] = register
		}
	default:
		return sketch, errors.New("routeusage: unknown visitor HLL checkpoint encoding")
	}
	return sketch, nil
}

func visitorNetworkHash(masterSecret [sha256.Size]byte, routeID string, source netip.Addr, at time.Time) (uint64, bool) {
	source = source.Unmap()
	if !source.IsValid() {
		return 0, false
	}
	dayMAC := hmac.New(sha256.New, masterSecret[:])
	_, _ = dayMAC.Write([]byte("tnl/route-usage/visitor-day/v1\x00" + at.UTC().Format(time.DateOnly)))

	routeMAC := hmac.New(sha256.New, dayMAC.Sum(nil))
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
