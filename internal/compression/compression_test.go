package compression

import (
	"bytes"
	"strings"
	"testing"
)

func TestNew_LevelMapping(t *testing.T) {
	cases := []struct {
		level   int
		wantErr bool
	}{
		{0, false},
		{1, false},
		{5, false},
		{9, false},
		{10, true},
		{11, true},
		{12, false},
		{-1, true},
		{99, true},
	}
	for _, tc := range cases {
		_, err := New(tc.level)
		if (err != nil) != tc.wantErr {
			t.Errorf("New(%d) err=%v, wantErr=%v", tc.level, err, tc.wantErr)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("hello world"),
		bytes.Repeat([]byte("ABCD"), 256),       // highly compressible
		[]byte("\x00\x01\x02\x03\x04\xff\xfe"), // tiny binary
		[]byte(strings.Repeat("a", 4096)),
	}
	for _, level := range []int{0, 1, 9, 12} {
		t.Run(string([]byte{byte('0' + level%10)})+"_lvl", func(t *testing.T) {
			c, err := New(level)
			if err != nil {
				t.Fatal(err)
			}
			for i, pt := range payloads {
				ct, err := c.Compress(pt)
				if err != nil {
					t.Fatalf("Compress[%d]: %v", i, err)
				}
				got, err := c.Decompress(ct)
				if err != nil {
					t.Fatalf("Decompress[%d]: %v", i, err)
				}
				if !bytes.Equal(got, pt) {
					t.Errorf("payload %d round-trip mismatch (level=%d)", i, level)
				}
			}
		})
	}
}

func TestZlib_HighRatioOnRepetitive(t *testing.T) {
	c, _ := New(9)
	in := bytes.Repeat([]byte("ABCD"), 1024)
	out, err := c.Compress(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) >= len(in)/4 {
		t.Errorf("zlib level 9: %d → %d bytes, expected at least 4× compression", len(in), len(out))
	}
}
