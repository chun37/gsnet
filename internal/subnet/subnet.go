package subnet

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const DefaultWeight = 10

type Subnet struct {
	Prefix netip.Prefix
	MAC    net.HardwareAddr
	Weight int
}

// ContainsIP reports whether s is an IP subnet covering addr.
// Returns false for MAC-typed subnets.
func (s Subnet) ContainsIP(addr netip.Addr) bool {
	return s.Prefix.Contains(addr)
}

// ContainsMAC reports whether s is a MAC subnet matching mac exactly.
// Returns false for IP-typed subnets.
func (s Subnet) ContainsMAC(mac net.HardwareAddr) bool {
	return s.MAC != nil && bytes.Equal(s.MAC, mac)
}

func (s Subnet) String() string {
	body := s.Prefix.String()
	if s.MAC != nil {
		body = s.MAC.String()
	}
	if s.Weight != 0 && s.Weight != DefaultWeight {
		return body + "#" + strconv.Itoa(s.Weight)
	}
	return body
}

func Parse(s string) (Subnet, error) {
	body, weight, err := splitWeight(s)
	if err != nil {
		return Subnet{}, err
	}
	sub, err := parseBody(body)
	if err != nil {
		return Subnet{}, err
	}
	sub.Weight = weight
	return sub, nil
}

func splitWeight(s string) (body string, weight int, err error) {
	body, w, ok := strings.Cut(s, "#")
	if !ok {
		return s, DefaultWeight, nil
	}
	weight, err = strconv.Atoi(w)
	if err != nil {
		return "", 0, fmt.Errorf("invalid weight in %q: %w", s, err)
	}
	return body, weight, nil
}

func parseBody(s string) (Subnet, error) {
	if mac, err := parseMAC(s); err == nil {
		return Subnet{MAC: mac}, nil
	}
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return Subnet{}, err
		}
		return Subnet{Prefix: netip.PrefixFrom(addr, addr.BitLen())}, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return Subnet{}, err
	}
	if p.Masked() != p {
		return Subnet{}, fmt.Errorf("subnet %q has non-zero host bits", s)
	}
	return Subnet{Prefix: p}, nil
}

// parseMAC accepts both the strict net.ParseMAC form ("00:1a:...") and the
// lenient single-digit form ("0:1a:...").
func parseMAC(s string) (net.HardwareAddr, error) {
	if mac, err := net.ParseMAC(s); err == nil {
		return mac, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid MAC address %q", s)
	}
	mac := make(net.HardwareAddr, 6)
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return nil, fmt.Errorf("invalid MAC address %q", s)
		}
		b, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address %q: %w", s, err)
		}
		mac[i] = byte(b)
	}
	return mac, nil
}
