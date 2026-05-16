// Package pcap writes the libpcap savefile format.
//
// File layout:
//   24-byte global header
//   per-packet: 16-byte record header + raw bytes
//
// Spec: https://datatracker.ietf.org/doc/html/draft-gharris-opsawg-pcap-02
package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// LinkType identifiers from the libpcap registry.
const (
	LinkTypeNull     uint32 = 0   // raw IP, no link-layer header
	LinkTypeEthernet uint32 = 1
	LinkTypeRaw      uint32 = 101
)

// Writer emits a pcap file to the underlying writer.
type Writer struct {
	w        io.Writer
	linkType uint32
	snaplen  uint32
}

// NewWriter creates a Writer and emits the file header. linkType determines
// how readers interpret packet bytes; for gsnet's L2 tap that's LinkTypeEthernet.
func NewWriter(w io.Writer, linkType uint32, snaplen uint32) (*Writer, error) {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4) // magic (microsecond resolution)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)         // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)         // version minor
	binary.LittleEndian.PutUint32(hdr[8:12], 0)        // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0)       // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], snaplen)
	binary.LittleEndian.PutUint32(hdr[20:24], linkType)
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &Writer{w: w, linkType: linkType, snaplen: snaplen}, nil
}

// WritePacket writes one packet with the given capture timestamp.
// If len(data) > snaplen, only the first snaplen bytes are stored but the
// original length is preserved in the header (so readers know it was truncated).
func (p *Writer) WritePacket(ts time.Time, data []byte) error {
	cap := uint32(len(data))
	if cap > p.snaplen {
		cap = p.snaplen
	}
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(hdr[8:12], cap)
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(data)))
	if _, err := p.w.Write(hdr); err != nil {
		return err
	}
	_, err := p.w.Write(data[:cap])
	return err
}

// Reader reads pcap savefiles, for tests.
type Reader struct {
	r        io.Reader
	LinkType uint32
	Snaplen  uint32
	little   bool
}

// NewReader consumes the global header and returns a Reader.
func NewReader(r io.Reader) (*Reader, error) {
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	magic := binary.LittleEndian.Uint32(hdr[0:4])
	little := true
	switch magic {
	case 0xa1b2c3d4:
		// little-endian microsecond
	case 0xd4c3b2a1:
		little = false
	default:
		return nil, fmt.Errorf("pcap: bad magic 0x%08x", magic)
	}
	order := binary.LittleEndian
	if !little {
		// uint32s in the header are big-endian; swap on read below
	}
	_ = order
	rd := &Reader{r: r, little: little}
	if little {
		rd.Snaplen = binary.LittleEndian.Uint32(hdr[16:20])
		rd.LinkType = binary.LittleEndian.Uint32(hdr[20:24])
	} else {
		rd.Snaplen = binary.BigEndian.Uint32(hdr[16:20])
		rd.LinkType = binary.BigEndian.Uint32(hdr[20:24])
	}
	return rd, nil
}

// Packet is a single decoded record.
type Packet struct {
	Time time.Time
	Data []byte
}

// Next returns the next packet or io.EOF when exhausted.
func (rd *Reader) Next() (Packet, error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(rd.r, hdr); err != nil {
		return Packet{}, err
	}
	var sec, usec, cap uint32
	if rd.little {
		sec = binary.LittleEndian.Uint32(hdr[0:4])
		usec = binary.LittleEndian.Uint32(hdr[4:8])
		cap = binary.LittleEndian.Uint32(hdr[8:12])
	} else {
		sec = binary.BigEndian.Uint32(hdr[0:4])
		usec = binary.BigEndian.Uint32(hdr[4:8])
		cap = binary.BigEndian.Uint32(hdr[8:12])
	}
	data := make([]byte, cap)
	if _, err := io.ReadFull(rd.r, data); err != nil {
		return Packet{}, err
	}
	return Packet{Time: time.Unix(int64(sec), int64(usec)*1000), Data: data}, nil
}
