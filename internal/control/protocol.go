// Package control implements the gsnet daemon's control protocol over a UNIX
// socket. Wire format follows tinc's control protocol (see doc/CONTROL in the
// tinc source tree):
//
//   - Each message is one ASCII line terminated by '\n'.
//   - The first token is a numeric "message class" (always 18 for normal
//     requests, 0 for greeting).
//   - The second token is the numeric request type.
//   - Remaining space-separated tokens are arguments. Tokens never contain
//     spaces; no escaping.
package control

import (
	"fmt"
	"strconv"
	"strings"
)

// MessageClass values from tinc's control_common.h.
const (
	ClassGreeting = 0
	ClassRequest  = 18
)

// RequestType numeric codes. Values match tinc's enum where it makes sense to
// preserve wire compatibility; new gsnet-only values use the high range.
type RequestType int

const (
	ReqStop            RequestType = 1
	ReqReload          RequestType = 2
	ReqRestart         RequestType = 3
	ReqDumpNodes       RequestType = 4
	ReqDumpEdges       RequestType = 5
	ReqDumpSubnets     RequestType = 6
	ReqDumpConnections RequestType = 7
	ReqDumpGraph       RequestType = 8
	ReqSetDebug        RequestType = 9
	ReqRetry           RequestType = 10
	ReqConnect         RequestType = 11
	ReqDisconnect      RequestType = 12
	ReqDumpTraffic     RequestType = 13
	ReqPCAP            RequestType = 14
	ReqLog             RequestType = 15
	ReqPurge           RequestType = 16
	ReqDumpInvitations RequestType = 17
)

// Message is a decoded protocol message.
type Message struct {
	Class int
	Type  RequestType
	Args  []string
}

// EncodeMessage emits a request line for the given type and args.
func EncodeMessage(t RequestType, args ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d %d", ClassRequest, t)
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(a)
	}
	b.WriteByte('\n')
	return b.String()
}

// DecodeMessage parses one line (without the trailing newline) into a Message.
func DecodeMessage(line string) (Message, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Message{}, fmt.Errorf("control: short message %q", line)
	}
	class, err := strconv.Atoi(fields[0])
	if err != nil {
		return Message{}, fmt.Errorf("control: invalid class %q: %w", fields[0], err)
	}
	t, err := strconv.Atoi(fields[1])
	if err != nil {
		return Message{}, fmt.Errorf("control: invalid type %q: %w", fields[1], err)
	}
	return Message{Class: class, Type: RequestType(t), Args: fields[2:]}, nil
}

// Greeting is the first line sent by the daemon on a control connection:
//
//	0 <name> <major>.<minor>
type Greeting struct {
	Name  string
	Major int
	Minor int
}

func (g Greeting) Encode() string {
	return fmt.Sprintf("%d %s %d.%d\n", ClassGreeting, g.Name, g.Major, g.Minor)
}

func ParseGreeting(line string) (Greeting, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "0" {
		return Greeting{}, fmt.Errorf("control: not a greeting %q", line)
	}
	ver := strings.SplitN(fields[2], ".", 2)
	if len(ver) != 2 {
		return Greeting{}, fmt.Errorf("control: bad version %q", fields[2])
	}
	major, err := strconv.Atoi(ver[0])
	if err != nil {
		return Greeting{}, err
	}
	minor, err := strconv.Atoi(ver[1])
	if err != nil {
		return Greeting{}, err
	}
	return Greeting{Name: fields[1], Major: major, Minor: minor}, nil
}

// PIDFile is the contents of a gsnet PID file. First line:
//
//	<pid> <cookie>
//
// The cookie is what tinc/gsnet CLIs use to authenticate to the control socket.
type PIDFile struct {
	PID    int
	Cookie string
}

func (p PIDFile) Encode() string {
	return fmt.Sprintf("%d %s\n", p.PID, p.Cookie)
}

func ParsePIDFile(s string) (PIDFile, error) {
	line := strings.SplitN(strings.TrimSpace(s), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return PIDFile{}, fmt.Errorf("pidfile: expected '<pid> <cookie>', got %q", s)
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return PIDFile{}, fmt.Errorf("pidfile: bad pid: %w", err)
	}
	return PIDFile{PID: pid, Cookie: fields[1]}, nil
}
