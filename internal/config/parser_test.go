package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse_Empty(t *testing.T) {
	got, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("entries = %v, want empty", got)
	}
}

func TestParse_SinglePair(t *testing.T) {
	got, err := Parse(strings.NewReader("Name = alice\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Entries{{Key: "Name", Value: "alice"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestParse_NoEqualsSign(t *testing.T) {
	got, err := Parse(strings.NewReader("Name alice\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Entries{{Key: "Name", Value: "alice"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestParse_Comment(t *testing.T) {
	got, err := Parse(strings.NewReader("# comment\nName = alice\n# another\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Entries{{Key: "Name", Value: "alice"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestParse_MultipleEntries_PreservesOrderAndDuplicates(t *testing.T) {
	src := "ConnectTo = foo\nConnectTo = bar\nName = me\n"
	got, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	want := Entries{
		{Key: "ConnectTo", Value: "foo"},
		{Key: "ConnectTo", Value: "bar"},
		{Key: "Name", Value: "me"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestParse_CaseInsensitiveKey(t *testing.T) {
	got, err := Parse(strings.NewReader("name = alice\nNAME = bob\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Keys are normalized to canonical case in entries but lookups are case-insensitive.
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if !strings.EqualFold(got[0].Key, "Name") || !strings.EqualFold(got[1].Key, "Name") {
		t.Errorf("keys = %q %q, want canonical 'Name' (case-insensitive match)", got[0].Key, got[1].Key)
	}
}

func TestParse_WhitespaceTolerant(t *testing.T) {
	src := "  Name   =   alice  \n\n\t Port=655\n"
	got, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	want := Entries{
		{Key: "Name", Value: "alice"},
		{Key: "Port", Value: "655"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestEntries_GetFirst(t *testing.T) {
	es := Entries{{Key: "Name", Value: "alice"}, {Key: "Port", Value: "655"}}
	if v, ok := es.GetFirst("name"); !ok || v != "alice" {
		t.Errorf("GetFirst(name) = %q,%v, want alice,true", v, ok)
	}
	if _, ok := es.GetFirst("missing"); ok {
		t.Errorf("GetFirst(missing) = true, want false")
	}
}

func TestEntries_GetAll(t *testing.T) {
	es := Entries{
		{Key: "ConnectTo", Value: "foo"},
		{Key: "Name", Value: "me"},
		{Key: "ConnectTo", Value: "bar"},
	}
	got := es.GetAll("connectto")
	want := []string{"foo", "bar"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEntries_Render_RoundTrip(t *testing.T) {
	src := "Name = alice\nConnectTo = foo\nConnectTo = bar\n"
	parsed, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	rendered := Entries(parsed).Render()
	reparsed, err := Parse(strings.NewReader(rendered))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, reparsed) {
		t.Errorf("round-trip differs:\nfirst  %#v\nsecond %#v", parsed, reparsed)
	}
}

func TestParse_RejectsInvalidLine(t *testing.T) {
	cases := []string{
		"=value\n",
		"key=\n", // empty value
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(s)); err == nil {
				t.Errorf("Parse(%q) succeeded, want error", s)
			}
		})
	}
}
