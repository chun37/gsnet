package subnet

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

func TestParse_Valid(t *testing.T) {
	cases := []struct {
		in         string
		wantPrefix string // empty for MAC-typed
		wantMAC    string // empty for IP-typed
		wantWeight int
	}{
		{"192.168.1.0/24", "192.168.1.0/24", "", 10},
		{"10.0.0.0/8", "10.0.0.0/8", "", 10},
		{"192.168.1.1", "192.168.1.1/32", "", 10},
		{"fec0:0:0:1::/64", "fec0:0:0:1::/64", "", 10},
		{"fec0::1", "fec0::1/128", "", 10},
		{"0:1a:2b:3c:4d:5e", "", "00:1a:2b:3c:4d:5e", 10},
		{"00:1a:2b:3c:4d:5e", "", "00:1a:2b:3c:4d:5e", 10},
		{"192.168.1.0/24#5", "192.168.1.0/24", "", 5},
		{"10.0.0.0/8#1", "10.0.0.0/8", "", 1},
		{"fec0::/64#42", "fec0::/64", "", 42},
		{"0:1a:2b:3c:4d:5e#3", "", "00:1a:2b:3c:4d:5e", 3},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if tc.wantPrefix != "" {
				want := netip.MustParsePrefix(tc.wantPrefix)
				if got.Prefix != want {
					t.Errorf("Prefix = %v, want %v", got.Prefix, want)
				}
				if got.MAC != nil {
					t.Errorf("MAC = %v, want nil", got.MAC)
				}
			}
			if tc.wantMAC != "" {
				want, _ := net.ParseMAC(tc.wantMAC)
				if !bytes.Equal(got.MAC, want) {
					t.Errorf("MAC = %v, want %v", got.MAC, want)
				}
				if got.Prefix.IsValid() {
					t.Errorf("Prefix = %v, want invalid", got.Prefix)
				}
			}
			if got.Weight != tc.wantWeight {
				t.Errorf("Weight = %d, want %d", got.Weight, tc.wantWeight)
			}
		})
	}
}

func TestParse_RejectsInvalid(t *testing.T) {
	cases := []string{
		"",
		"hoge",
		"192.168.1/24",
		"192.168.1.1/33",
		"0:1a:2b:3c:4d",      // too few MAC groups
		"192.168.1.0/24#abc", // invalid weight
		"192.168.1.0/-1",
		"#5",
		"192.168.1.1/24", // non-zero host bits
		"10.0.0.5/8",
		"fec0::1/64",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := Parse(in); err == nil {
				t.Errorf("Parse(%q) succeeded, want error", in)
			}
		})
	}
}

func TestContainsIP(t *testing.T) {
	cases := []struct {
		subnet string
		addr   string
		want   bool
	}{
		{"192.168.1.0/24", "192.168.1.5", true},
		{"192.168.1.0/24", "192.168.2.5", false},
		{"192.168.1.1/32", "192.168.1.1", true},
		{"192.168.1.1/32", "192.168.1.2", false},
		{"fec0:0:0:1::/64", "fec0:0:0:1::abcd", true},
		{"fec0:0:0:1::/64", "fec0:0:0:2::abcd", false},
		{"0:1a:2b:3c:4d:5e", "192.168.1.5", false}, // MAC subnet, IP addr
	}
	for _, tc := range cases {
		t.Run(tc.subnet+"_"+tc.addr, func(t *testing.T) {
			sub, err := Parse(tc.subnet)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.subnet, err)
			}
			a := netip.MustParseAddr(tc.addr)
			if got := sub.ContainsIP(a); got != tc.want {
				t.Errorf("ContainsIP(%v) = %v, want %v", a, got, tc.want)
			}
		})
	}
}

func TestContainsMAC(t *testing.T) {
	cases := []struct {
		subnet string
		mac    string
		want   bool
	}{
		{"0:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e", true},
		{"0:1a:2b:3c:4d:5e", "ff:ff:ff:ff:ff:ff", false},
		{"192.168.1.0/24", "00:1a:2b:3c:4d:5e", false}, // IP subnet, MAC addr
	}
	for _, tc := range cases {
		t.Run(tc.subnet+"_"+tc.mac, func(t *testing.T) {
			sub, err := Parse(tc.subnet)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.subnet, err)
			}
			m, err := net.ParseMAC(tc.mac)
			if err != nil {
				t.Fatalf("ParseMAC(%q): %v", tc.mac, err)
			}
			if got := sub.ContainsMAC(m); got != tc.want {
				t.Errorf("ContainsMAC(%v) = %v, want %v", m, got, tc.want)
			}
		})
	}
}

func TestString_RoundTrip(t *testing.T) {
	inputs := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"192.168.1.1/32",
		"fec0:0:0:1::/64",
		"fec0::1/128",
		"00:1a:2b:3c:4d:5e",
		"192.168.1.0/24#5",
		"00:1a:2b:3c:4d:5e#3",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			s, err := Parse(in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", in, err)
			}
			if got := s.String(); got != in {
				t.Errorf("String() = %q, want %q", got, in)
			}
		})
	}
}
