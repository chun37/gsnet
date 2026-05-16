package invite

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/chun/gsnet/internal/config"
)

// Block is one host config block within an invitation file.
//
// The first block represents the invitee (the new node being created). Special
// hint keys (Netname, Ifconfig, Route) are extracted from the first block and
// used to generate gsnet-up. Remaining keys are copied into the host config
// file the invitee will write for itself.
//
// Subsequent blocks are copied verbatim into hosts/<Name>.
type Block struct {
	Name      string
	Address   string
	ConnectTo []string
	Ifconfig  []string // first-block-only hints
	Route     []string // first-block-only hints
	Other     []config.Entry
}

// File is a parsed invitation file.
type File struct {
	Netname string
	Invitee Block
	Hosts   []Block
}

// ParseFile reads a gsnet invitation file from r.
//
// Blocks are separated by lines whose first non-whitespace text begins with `#`
// (the conventional `#---#` separator) OR by the start of a new `Name = ...`
// line. The first line of the file must declare a Name.
func ParseFile(r io.Reader) (File, error) {
	var blocks [][]config.Entry
	var current []config.Entry

	flush := func() {
		if len(current) > 0 {
			blocks = append(blocks, current)
			current = nil
		}
	}

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			flush()
			continue
		}
		e, err := parseConfigLine(line)
		if err != nil {
			return File{}, err
		}
		// A new Name line in the middle starts a new block too.
		if strings.EqualFold(e.Key, "Name") && len(current) > 0 {
			flush()
		}
		current = append(current, e)
	}
	if err := sc.Err(); err != nil {
		return File{}, err
	}
	flush()

	if len(blocks) == 0 {
		return File{}, fmt.Errorf("invitation file is empty")
	}

	first := blockFromEntries(blocks[0])
	if first.Name == "" {
		return File{}, fmt.Errorf("invitation file: first block missing Name")
	}

	out := File{Invitee: first}
	for _, e := range blocks[0] {
		if strings.EqualFold(e.Key, "Netname") {
			out.Netname = e.Value
			break
		}
	}

	for _, b := range blocks[1:] {
		hb := blockFromEntries(b)
		if hb.Name == "" {
			return File{}, fmt.Errorf("invitation file: host block missing Name")
		}
		out.Hosts = append(out.Hosts, hb)
	}
	return out, nil
}

func parseConfigLine(s string) (config.Entry, error) {
	es, err := config.Parse(strings.NewReader(s))
	if err != nil {
		return config.Entry{}, err
	}
	if len(es) != 1 {
		return config.Entry{}, fmt.Errorf("expected single entry, got %d", len(es))
	}
	return es[0], nil
}

func blockFromEntries(es []config.Entry) Block {
	var b Block
	for _, e := range es {
		switch {
		case strings.EqualFold(e.Key, "Name"):
			b.Name = e.Value
		case strings.EqualFold(e.Key, "Address"):
			b.Address = e.Value
		case strings.EqualFold(e.Key, "ConnectTo"):
			b.ConnectTo = append(b.ConnectTo, e.Value)
		case strings.EqualFold(e.Key, "Ifconfig"):
			b.Ifconfig = append(b.Ifconfig, e.Value)
		case strings.EqualFold(e.Key, "Route"):
			b.Route = append(b.Route, e.Value)
		case strings.EqualFold(e.Key, "Netname"):
			// handled at File level
		default:
			b.Other = append(b.Other, e)
		}
	}
	return b
}

// Render emits the file in canonical form.
func (f File) Render() string {
	var b strings.Builder
	writeBlock := func(blk Block, includeNetname bool) {
		fmt.Fprintf(&b, "Name = %s\n", blk.Name)
		if includeNetname && f.Netname != "" {
			fmt.Fprintf(&b, "Netname = %s\n", f.Netname)
		}
		for _, c := range blk.ConnectTo {
			fmt.Fprintf(&b, "ConnectTo = %s\n", c)
		}
		if blk.Address != "" {
			fmt.Fprintf(&b, "Address = %s\n", blk.Address)
		}
		for _, ic := range blk.Ifconfig {
			fmt.Fprintf(&b, "Ifconfig = %s\n", ic)
		}
		for _, rt := range blk.Route {
			fmt.Fprintf(&b, "Route = %s\n", rt)
		}
		for _, e := range blk.Other {
			fmt.Fprintf(&b, "%s = %s\n", e.Key, e.Value)
		}
	}
	writeBlock(f.Invitee, true)
	for _, h := range f.Hosts {
		b.WriteString("#---------------------------------------#\n")
		writeBlock(h, false)
	}
	return b.String()
}
