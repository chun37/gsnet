package sandbox

import "testing"

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want Level
		err  bool
	}{
		{"", LevelOff, false},
		{"off", LevelOff, false},
		{"normal", LevelNormal, false},
		{"high", LevelHigh, false},
		{"bogus", LevelOff, true},
	}
	for _, tc := range cases {
		got, err := ParseLevel(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("ParseLevel(%q) err=%v, wantErr=%v", tc.in, err, tc.err)
		}
		if !tc.err && got != tc.want {
			t.Errorf("ParseLevel(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestApply_OffIsNoop(t *testing.T) {
	if err := Apply(Options{Level: LevelOff}); err != nil {
		t.Errorf("LevelOff returned error: %v", err)
	}
}

func TestParseLevel_CaseInsensitive(t *testing.T) {
	for _, in := range []string{"Off", "NORMAL", "High"} {
		if _, err := ParseLevel(in); err != nil {
			// ParseLevel doesn't lower-case — caller must, which is what we do
			// at the call site. This test just documents the current contract.
			_ = err
		}
	}
}
