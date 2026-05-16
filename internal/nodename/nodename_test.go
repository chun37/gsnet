package nodename

import (
	"os"
	"testing"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"foo", true},
		{"foo_bar", true},
		{"abc123", true},
		{"ABC_123", true},
		{"_underscore", true},
		{"a", true},
		{"", false},
		{"foo-bar", false},
		{"foo bar", false},
		{"foo.bar", false},
		{"日本語", false},
		{"foo/bar", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			err := Validate(tc.in)
			got := err == nil
			if got != tc.want {
				t.Errorf("Validate(%q) ok=%v (err=%v), want ok=%v", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestExpand_NoVariable(t *testing.T) {
	got, err := Expand("foo")
	if err != nil {
		t.Fatal(err)
	}
	if got != "foo" {
		t.Errorf("Expand(foo) = %q, want %q", got, "foo")
	}
}

func TestExpand_EnvVar(t *testing.T) {
	t.Setenv("MYNODE", "alice")
	got, err := Expand("$MYNODE")
	if err != nil {
		t.Fatal(err)
	}
	if got != "alice" {
		t.Errorf("Expand($MYNODE) = %q, want %q", got, "alice")
	}
}

func TestExpand_EnvVarMissingFallsBackToHostname(t *testing.T) {
	os.Unsetenv("NOPE_NOPE_NOPE")
	got, err := Expand("$NOPE_NOPE_NOPE")
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Errorf("Expand($NOPE_NOPE_NOPE) returned empty, want hostname-derived")
	}
}

func TestExpand_InvalidCharsConvertedToUnderscore(t *testing.T) {
	t.Setenv("UGLY", "foo-bar.baz")
	got, err := Expand("$UGLY")
	if err != nil {
		t.Fatal(err)
	}
	if got != "foo_bar_baz" {
		t.Errorf("Expand($UGLY) = %q, want %q", got, "foo_bar_baz")
	}
}
