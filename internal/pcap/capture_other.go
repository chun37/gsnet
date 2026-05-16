//go:build !linux

package pcap

import (
	"context"
	"errors"
	"io"
)

// Capture is unsupported on non-Linux platforms. Use tcpdump or a Linux host.
func Capture(_ context.Context, _ string, _ uint32, _ io.Writer) error {
	return errors.New("pcap.Capture: unsupported on this platform; Linux only")
}
