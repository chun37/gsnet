package stun

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestQuery_AgainstFakeServer spins up a tiny in-process STUN responder and
// verifies the client decodes XOR-MAPPED-ADDRESS correctly. Avoids any
// dependency on a live STUN server.
func TestQuery_AgainstFakeServer(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	go func() {
		buf := make([]byte, 1500)
		n, raddr, err := srv.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 20 {
			return
		}
		txid := buf[8:20]
		// Build a Binding Response with one XOR-MAPPED-ADDRESS attribute for
		// the client's source address.
		var resp []byte
		resp = append(resp, 0x01, 0x01) // bindingResponse
		// attr: type(2) length(2) family(1B reserved + 1B family) port(2) ip(4) = 4+8 = 12
		attrLen := 12
		lengthHdr := []byte{byte(attrLen >> 8), byte(attrLen)}
		resp = append(resp, lengthHdr...)
		resp = append(resp, 0x21, 0x12, 0xA4, 0x42) // magic cookie
		resp = append(resp, txid...)

		// XOR-MAPPED-ADDRESS attribute
		resp = append(resp, 0x00, 0x20)  // attr type
		resp = append(resp, 0x00, 0x08) // attr length
		port := uint16(raddr.Port) ^ uint16(0x2112)
		ip := raddr.IP.To4()
		xorIP := make([]byte, 4)
		magic := []byte{0x21, 0x12, 0xA4, 0x42}
		for i := 0; i < 4; i++ {
			xorIP[i] = ip[i] ^ magic[i]
		}
		resp = append(resp, 0x00, 0x01) // reserved + family v4
		resp = append(resp, byte(port>>8), byte(port))
		resp = append(resp, xorIP...)

		_, _ = srv.WriteToUDP(resp, raddr)
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	ap, err := Query(clientConn, srv.LocalAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)
	if ap.Port() != uint16(clientAddr.Port) {
		t.Errorf("port = %d, want %d", ap.Port(), clientAddr.Port)
	}
	want := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if ap.Addr() != want {
		t.Errorf("addr = %v, want %v", ap.Addr(), want)
	}
}

func TestParse_RejectsBadMagic(t *testing.T) {
	// header with wrong magic cookie
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], bindingResponse)
	binary.BigEndian.PutUint32(hdr[4:8], 0xdeadbeef)
	if _, err := parseResponse(hdr, hdr[8:20]); err == nil {
		t.Errorf("accepted bad magic")
	}
}
