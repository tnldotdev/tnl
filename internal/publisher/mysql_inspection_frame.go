package publisher

// mysqlFrame captures a bounded prefix while counting whole logical packets.
// a maximal physical packet continues until a shorter packet (possibly empty).
type mysqlFrame struct {
	header         [4]byte
	headerRead     int
	left           int
	size           int
	sequence       byte
	nextSequence   byte
	firstSequence  byte
	physicalFrames int
	logicalSize    int64
	prefix         []byte
	firstPrefix    []byte
	continuation   bool
	broken         bool
	limit          int
}

const mysqlMaxContinuationFrames = 16

func (f *mysqlFrame) feed(data []byte, onPacket func(byte, []byte, int64, int)) {
	for len(data) > 0 && !f.broken {
		if f.left == 0 {
			n := min(len(data), len(f.header)-f.headerRead)
			copy(f.header[f.headerRead:], data[:n])
			f.headerRead += n
			data = data[n:]
			if f.headerRead != len(f.header) {
				return
			}
			f.size = int(f.header[0]) | int(f.header[1])<<8 | int(f.header[2])<<16
			f.sequence = f.header[3]
			if f.continuation && f.sequence != f.nextSequence {
				f.broken = true
				return
			}
			f.left = f.size
			f.prefix = f.prefix[:0]
			if f.size == 0 {
				f.finish(onPacket)
			}
			continue
		}
		n := min(len(data), f.left)
		if len(f.prefix) < f.limit && !f.continuation {
			capture := min(n, f.limit-len(f.prefix))
			f.prefix = append(f.prefix, data[:capture]...)
		}
		f.left -= n
		data = data[n:]
		if f.left == 0 {
			f.finish(onPacket)
		}
	}
}

func (f *mysqlFrame) finish(onPacket func(byte, []byte, int64, int)) {
	f.logicalSize += int64(f.size)
	f.physicalFrames++
	f.nextSequence = f.sequence + 1
	if !f.continuation {
		f.firstSequence = f.sequence
		f.firstPrefix = append(f.firstPrefix[:0], f.prefix...)
	}
	if f.size == mysqlMaxPayload {
		f.continuation = true
		if f.physicalFrames >= mysqlMaxContinuationFrames {
			f.broken = true
		}
	} else {
		onPacket(f.firstSequence, f.firstPrefix, f.logicalSize, f.physicalFrames)
		f.continuation = false
		f.physicalFrames = 0
		f.logicalSize = 0
	}
	f.headerRead = 0
	f.size = 0
}
