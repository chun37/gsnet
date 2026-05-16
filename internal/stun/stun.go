// Package stun is a minimal STUN client (RFC 5389) that sends a Binding
// Request and parses the XOR-MAPPED-ADDRESS in the response to discover the
// client's public reflexive address.
//
// Scope: this is the bare minimum needed by gsnetd to learn its public
// endpoint so it can announce it via gossip. Authentication, FINGERPRINT,
// MESSAGE-INTEGRITY, ICE etc. are out of scope.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// magicCookie is the fixed value in every STUN message after the type+length.
const magicCookie uint32 = 0x2112A442

// Message types and attribute types from RFC 5389.
const (
	bindingRequest  uint16 = 0x0001
	bindingResponse uint16 = 0x0101

	attrMappedAddress    uint16 = 0x0001
	attrXorMappedAddress uint16 = 0x0020
)

// Query sends a Binding Request to addr (host:port of a STUN server) and
// returns the public address the server saw. The supplied conn is reused for
// I/O (caller may bind to the same local socket they intend to publish).
func Query(conn *net.UDPConn, addr string, timeout time.Duration) (netip.AddrPort, error) {
	server, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return netip.AddrPort{}, err
	}

	// Build Binding Request: 20-byte header + zero attributes.
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], bindingRequest)
	binary.BigEndian.PutUint16(hdr[2:4], 0)
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	if _, err := rand.Read(hdr[8:20]); err != nil {
		return netip.AddrPort{}, err
	}
	txid := make([]byte, 12)
	copy(txid, hdr[8:20])

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.WriteToUDP(hdr, server); err != nil {
		return netip.AddrPort{}, err
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return netip.AddrPort{}, err
		}
		ap, err := parseResponse(buf[:n], txid)
		if err == errWrongTxID {
			continue
		}
		return ap, err
	}
}

// QueryOnEphemeralPort is a convenience that opens a fresh UDP socket, sends
// the query, and returns the reflexive address. The local source port is
// random so this is unsuitable for hole punching — use Query with a
// caller-owned socket for that.
func QueryOnEphemeralPort(server string, timeout time.Duration) (netip.AddrPort, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer conn.Close()
	return Query(conn, server, timeout)
}

var errWrongTxID = fmt.Errorf("stun: response for unrelated transaction")

func parseResponse(b, txid []byte) (netip.AddrPort, error) {
	if len(b) < 20 {
		return netip.AddrPort{}, fmt.Errorf("stun: short response (%d bytes)", len(b))
	}
	if binary.BigEndian.Uint16(b[0:2]) != bindingResponse {
		return netip.AddrPort{}, fmt.Errorf("stun: not a Binding Response")
	}
	if binary.BigEndian.Uint32(b[4:8]) != magicCookie {
		return netip.AddrPort{}, fmt.Errorf("stun: bad magic cookie")
	}
	for i := 0; i < 12; i++ {
		if b[8+i] != txid[i] {
			return netip.AddrPort{}, errWrongTxID
		}
	}
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	if 20+msgLen > len(b) {
		return netip.AddrPort{}, fmt.Errorf("stun: declared length exceeds packet")
	}
	attrs := b[20 : 20+msgLen]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		ln := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+ln > len(attrs) {
			return netip.AddrPort{}, fmt.Errorf("stun: attribute overruns message")
		}
		val := attrs[4 : 4+ln]
		switch typ {
		case attrXorMappedAddress:
			return decodeXorMapped(val, b[4:8])
		case attrMappedAddress:
			return decodeMapped(val)
		}
		// Advance to next attribute, accounting for 4-byte padding.
		pad := (4 - ln%4) % 4
		attrs = attrs[4+ln+pad:]
	}
	return netip.AddrPort{}, fmt.Errorf("stun: response missing mapped address")
}

func decodeXorMapped(val, magicAndTxidPrefix []byte) (netip.AddrPort, error) {
	if len(val) < 4 {
		return netip.AddrPort{}, fmt.Errorf("stun: short XOR-MAPPED")
	}
	family := val[1]
	xport := binary.BigEndian.Uint16(val[2:4])
	port := xport ^ uint16(magicCookie>>16)
	switch family {
	case 0x01: // IPv4
		if len(val) < 8 {
			return netip.AddrPort{}, fmt.Errorf("stun: short XOR-MAPPED v4")
		}
		ip4 := make([]byte, 4)
		for i := 0; i < 4; i++ {
			ip4[i] = val[4+i] ^ magicAndTxidPrefix[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip4)), port), nil
	case 0x02: // IPv6
		if len(val) < 20 {
			return netip.AddrPort{}, fmt.Errorf("stun: short XOR-MAPPED v6")
		}
		// First 4 bytes XOR'd with magic cookie; remaining 12 with txid.
		// magicAndTxidPrefix here covers only the 4-byte magic — caller passes
		// b[4:8]. For v6 we also need the txid; reconstruct here.
		ip6 := make([]byte, 16)
		copy(ip6, val[4:20])
		return netip.AddrPort{}, fmt.Errorf("stun: IPv6 XOR-MAPPED not yet supported")
	default:
		return netip.AddrPort{}, fmt.Errorf("stun: unknown family 0x%02x", family)
	}
}

func decodeMapped(val []byte) (netip.AddrPort, error) {
	if len(val) < 8 {
		return netip.AddrPort{}, fmt.Errorf("stun: short MAPPED")
	}
	family := val[1]
	port := binary.BigEndian.Uint16(val[2:4])
	switch family {
	case 0x01:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(val[4:8])), port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("stun: family 0x%02x not supported", family)
	}
}
