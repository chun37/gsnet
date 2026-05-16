package control

import (
	"reflect"
	"strings"
	"testing"
)

func TestEncodeMessage(t *testing.T) {
	got := EncodeMessage(ReqDumpNodes)
	want := "18 4\n"
	if got != want {
		t.Errorf("EncodeMessage(ReqDumpNodes) = %q, want %q", got, want)
	}
}

func TestEncodeMessage_WithArgs(t *testing.T) {
	got := EncodeMessage(ReqSetDebug, "3")
	want := "18 9 3\n"
	if got != want {
		t.Errorf("EncodeMessage = %q, want %q", got, want)
	}
}

func TestDecodeMessage(t *testing.T) {
	msg, err := DecodeMessage("18 4 0")
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != ReqDumpNodes {
		t.Errorf("Type = %d, want %d", msg.Type, ReqDumpNodes)
	}
	if !reflect.DeepEqual(msg.Args, []string{"0"}) {
		t.Errorf("Args = %v, want [0]", msg.Args)
	}
}

func TestDecodeMessage_Invalid(t *testing.T) {
	cases := []string{
		"",
		"notanumber rest",
		"18", // missing type
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := DecodeMessage(in); err == nil {
				t.Errorf("DecodeMessage(%q) succeeded, want error", in)
			}
		})
	}
}

func TestGreeting_RoundTrip(t *testing.T) {
	g := Greeting{Name: "alice", Major: 17, Minor: 0}
	enc := g.Encode()
	parsed, err := ParseGreeting(strings.TrimSuffix(enc, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != g {
		t.Errorf("round-trip differs: %+v vs %+v", parsed, g)
	}
}

func TestPIDFile_RoundTrip(t *testing.T) {
	p := PIDFile{PID: 1234, Cookie: "abc123def"}
	enc := p.Encode()
	parsed, err := ParsePIDFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != p {
		t.Errorf("round-trip differs: %+v vs %+v", parsed, p)
	}
}
