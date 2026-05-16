package pcap

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestWriter_Reader_Roundtrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatal(err)
	}
	ts1 := time.Unix(1700000000, 123456000) // 123_456_000 ns = 123_456 us
	ts2 := time.Unix(1700000001, 0)
	want1 := []byte("\xaa\xbb\xcc\xdd\xee\xff" + "\x11\x22\x33\x44\x55\x66" + "\x08\x00" + "ip-payload")
	want2 := []byte{0x45, 0x00, 0x00, 0x14}
	if err := w.WritePacket(ts1, want1); err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(ts2, want2); err != nil {
		t.Fatal(err)
	}

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.LinkType != LinkTypeEthernet {
		t.Errorf("LinkType = %d, want Ethernet", r.LinkType)
	}
	if r.Snaplen != 65535 {
		t.Errorf("Snaplen = %d, want 65535", r.Snaplen)
	}
	for i, want := range [][]byte{want1, want2} {
		pkt, err := r.Next()
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(pkt.Data, want) {
			t.Errorf("packet %d: got %x, want %x", i, pkt.Data, want)
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestWriter_TruncatesAtSnaplen(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, LinkTypeEthernet, 8)
	data := []byte("0123456789abcdef")
	_ = w.WritePacket(time.Now(), data)

	r, _ := NewReader(&buf)
	pkt, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt.Data) != 8 {
		t.Errorf("captured len = %d, want 8 (snaplen)", len(pkt.Data))
	}
}
