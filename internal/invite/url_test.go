package invite

import (
	"testing"

	"github.com/chun/gsnet/internal/keys"
)

func TestNewCookie_UniqueAndParseable(t *testing.T) {
	c1, err := NewCookie()
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := NewCookie()
	if c1 == c2 {
		t.Errorf("two cookies are equal: %s", c1)
	}
	if len(c1) < 16 {
		t.Errorf("cookie too short: %s", c1)
	}
}

func TestBuildURL_RoundTrip(t *testing.T) {
	priv, _ := keys.GenerateEd25519()
	cookie, _ := NewCookie()
	u := BuildURL("example.com", 12345, priv.Public(), cookie)
	parsed, err := ParseURL(u.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != u {
		t.Errorf("round-trip differs:\norig %+v\nparsed %+v", u, parsed)
	}
	if parsed.KeyHash != priv.Public().Hash() {
		t.Errorf("KeyHash mismatch")
	}
}

func TestParseURL_Valid(t *testing.T) {
	in := "server.example.org:12345/cW1NhLHS-1WPFlcFio8ztYHvewTTKYZp8BjEKg3vbMtDz7w4"
	u, err := ParseURL(in)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "server.example.org" {
		t.Errorf("Host = %q, want %q", u.Host, "server.example.org")
	}
	if u.Port != 12345 {
		t.Errorf("Port = %d, want 12345", u.Port)
	}
	if u.KeyHash == "" || u.Cookie == "" {
		t.Errorf("KeyHash=%q Cookie=%q, both should be non-empty", u.KeyHash, u.Cookie)
	}
	if u.KeyHash+u.Cookie != "cW1NhLHS-1WPFlcFio8ztYHvewTTKYZp8BjEKg3vbMtDz7w4" {
		t.Errorf("concatenation differs from input")
	}
}

func TestParseURL_RoundTrip(t *testing.T) {
	in := "server.example.org:12345/cW1NhLHS-1WPFlcFio8ztYHvewTTKYZp8BjEKg3vbMtDz7w4"
	u, err := ParseURL(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.String(); got != in {
		t.Errorf("round-trip differs:\ngot  %q\nwant %q", got, in)
	}
}

func TestParseURL_Invalid(t *testing.T) {
	cases := []string{
		"",
		"server.example.org",
		"server.example.org:12345",
		"server.example.org/abcd",
		"server.example.org:notport/abcdefghij",
		":12345/abcdefghij",
		"server:12345/short", // cookie+keyhash too short to split
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseURL(in); err == nil {
				t.Errorf("ParseURL(%q) succeeded, want error", in)
			}
		})
	}
}
