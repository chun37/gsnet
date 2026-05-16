//go:build linux

package pcap

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// Capture opens an AF_PACKET raw socket bound to ifname and streams packets
// in pcap format to w until ctx is canceled. Requires CAP_NET_RAW or root.
func Capture(ctx context.Context, ifname string, snaplen uint32, w io.Writer) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifname, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("AF_PACKET socket: %w (need CAP_NET_RAW)", err)
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	pw, err := NewWriter(w, LinkTypeEthernet, snaplen)
	if err != nil {
		return err
	}

	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return nil
		}
		// Short read deadline so ctx cancellation is responsive.
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 200000})
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return fmt.Errorf("recv: %w", err)
		}
		if err := pw.WritePacket(time.Now(), buf[:n]); err != nil {
			return err
		}
	}
}

func htons(x uint16) uint16 {
	return (x<<8)&0xff00 | x>>8
}
