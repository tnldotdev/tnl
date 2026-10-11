package publisher

import "encoding/binary"

// postgresInspectionFrame skips large bodies while retaining small messages
// needed to attribute query and prepared-statement outcomes.
type postgresInspectionFrame struct {
	startup bool
	header  [5]byte
	read    int
	left    int
	kind    byte
	body    []byte
	broken  bool
}

func (f *postgresInspectionFrame) feed(data []byte, onFrame func(byte, []byte)) {
	for len(data) > 0 && !f.broken {
		if f.left == 0 {
			needed := 5
			if f.startup {
				needed = 4
			}
			count := min(len(data), needed-f.read)
			copy(f.header[f.read:], data[:count])
			f.read += count
			data = data[count:]
			if f.read < needed {
				return
			}
			lengthBytes := f.header[1:5]
			if f.startup {
				lengthBytes = f.header[:4]
			}
			length := binary.BigEndian.Uint32(lengthBytes)
			if length < 4 || length > maxPostgresInspectionFrame || f.startup && (length < 8 || length > 10_000) {
				f.broken = true
				return
			}
			f.kind = f.header[0]
			f.left = int(length) - 4
			if !f.startup && f.left <= maxPostgresCapturedFrame &&
				(f.kind == 'Q' || f.kind == 'P' || f.kind == 'B' || f.kind == 'E' || f.kind == 'C' || f.kind == 'Z') {
				f.body = make([]byte, 0, f.left)
			} else {
				f.body = nil
			}
			if f.left == 0 {
				f.complete(onFrame)
			}
			continue
		}
		count := min(len(data), f.left)
		if f.body != nil {
			f.body = append(f.body, data[:count]...)
		}
		f.left -= count
		data = data[count:]
		if f.left == 0 {
			f.complete(onFrame)
		}
	}
}

func (f *postgresInspectionFrame) complete(onFrame func(byte, []byte)) {
	if !f.startup {
		onFrame(f.kind, f.body)
	}
	f.startup = false
	f.read = 0
	f.body = nil
}
