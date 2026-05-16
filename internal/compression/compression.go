// Package compression provides packet-payload compression compatible with the
// levels tinc supports.
//
// Level mapping:
//
//	0       off (no compression)
//	1..9    zlib (1=fastest, 9=best)
//	10..11  lzo  (UNSUPPORTED — gsnet does not ship lzo bindings)
//	12      lz4
//
// gsnet's data plane is the kernel (VXLAN over WireGuard), so compression here
// is currently only useful for compressing gossip messages or for a future
// userspace data plane. The interface is stable; integration is left to
// callers that choose to use it.
package compression

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

// Codec is the compression interface. Compress and Decompress are stateless
// (each call is one full message).
type Codec interface {
	Compress(in []byte) ([]byte, error)
	Decompress(in []byte) ([]byte, error)
}

// New returns a Codec for the given tinc-compatible level. Level 0 returns
// a passthrough codec. Returns error for unsupported levels (10, 11) or out-
// of-range values.
func New(level int) (Codec, error) {
	switch {
	case level == 0:
		return passthrough{}, nil
	case level >= 1 && level <= 9:
		return &zlibCodec{level: level}, nil
	case level == 10 || level == 11:
		return nil, fmt.Errorf("compression: lzo (levels 10-11) not supported")
	case level == 12:
		return lz4Codec{}, nil
	default:
		return nil, fmt.Errorf("compression: invalid level %d", level)
	}
}

type passthrough struct{}

func (passthrough) Compress(in []byte) ([]byte, error)   { return append([]byte(nil), in...), nil }
func (passthrough) Decompress(in []byte) ([]byte, error) { return append([]byte(nil), in...), nil }

type zlibCodec struct {
	level int
}

func (z *zlibCodec) Compress(in []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, z.level)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(in); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (z *zlibCodec) Decompress(in []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

type lz4Codec struct{}

func (lz4Codec) Compress(in []byte) ([]byte, error) {
	buf := make([]byte, lz4.CompressBlockBound(len(in)))
	var c lz4.Compressor
	n, err := c.CompressBlock(in, buf)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		// Block was incompressible; lz4 spec says caller should send raw.
		// We prefix-encode 0-length to signal "stored verbatim" then send raw.
		out := make([]byte, 4+len(in))
		out[0], out[1], out[2], out[3] = 0, 0, 0, 0
		copy(out[4:], in)
		return out, nil
	}
	// Prepend the original size as a 4-byte little-endian so Decompress
	// knows how much to allocate.
	out := make([]byte, 4+n)
	sz := uint32(len(in))
	out[0] = byte(sz)
	out[1] = byte(sz >> 8)
	out[2] = byte(sz >> 16)
	out[3] = byte(sz >> 24)
	copy(out[4:], buf[:n])
	return out, nil
}

func (lz4Codec) Decompress(in []byte) ([]byte, error) {
	if len(in) < 4 {
		return nil, fmt.Errorf("lz4: short input")
	}
	sz := uint32(in[0]) | uint32(in[1])<<8 | uint32(in[2])<<16 | uint32(in[3])<<24
	body := in[4:]
	if sz == 0 {
		// Stored verbatim.
		return append([]byte(nil), body...), nil
	}
	dst := make([]byte, sz)
	n, err := lz4.UncompressBlock(body, dst)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
