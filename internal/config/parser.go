// Package config parses tinc-compatible configuration files.
//
// File format (tinc.conf(5)):
//   - Lines of "Key = Value" or "Key Value" (the = is optional).
//   - Keys are case-insensitive (canonicalized to Title case in known list,
//     otherwise preserved).
//   - Lines beginning with # are comments.
//   - Multiple entries with the same key are allowed (e.g. ConnectTo).
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is a single key/value pair from a config file.
type Entry struct {
	Key   string
	Value string
}

// Entries is a list of entries with helpers.
type Entries []Entry

// Parse reads tinc-format configuration from r.
func Parse(r io.Reader) (Entries, error) {
	var out Entries
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := parseLine(line)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseLine(s string) (Entry, error) {
	var key, value string
	if i := strings.IndexByte(s, '='); i >= 0 {
		key = strings.TrimSpace(s[:i])
		value = strings.TrimSpace(s[i+1:])
	} else {
		fields := strings.Fields(s)
		if len(fields) < 2 {
			return Entry{}, fmt.Errorf("invalid line %q: missing value", s)
		}
		key = fields[0]
		value = strings.TrimSpace(s[len(fields[0]):])
	}
	if key == "" {
		return Entry{}, fmt.Errorf("invalid line %q: empty key", s)
	}
	if value == "" {
		return Entry{}, fmt.Errorf("invalid line %q: empty value", s)
	}
	return Entry{Key: canonicalKey(key), Value: value}, nil
}

// ParseFile parses a single config file.
func ParseFile(path string) (Entries, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// LoadDirectory loads a primary file and any *.conf files in conf.d/ next to it.
// Order: primary file first, then conf.d entries in lexical order.
func LoadDirectory(primaryPath string) (Entries, error) {
	entries, err := ParseFile(primaryPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	confd := filepath.Join(filepath.Dir(primaryPath), "conf.d")
	dirEntries, err := os.ReadDir(confd)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, err
	}
	var names []string
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".conf") {
			continue
		}
		names = append(names, de.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		es, err := ParseFile(filepath.Join(confd, n))
		if err != nil {
			return nil, err
		}
		entries = append(entries, es...)
	}
	return entries, nil
}

// GetFirst returns the first value matching key (case-insensitive).
func (es Entries) GetFirst(key string) (string, bool) {
	for _, e := range es {
		if strings.EqualFold(e.Key, key) {
			return e.Value, true
		}
	}
	return "", false
}

// GetAll returns all values matching key in order.
func (es Entries) GetAll(key string) []string {
	var out []string
	for _, e := range es {
		if strings.EqualFold(e.Key, key) {
			out = append(out, e.Value)
		}
	}
	return out
}

// Render formats entries back to tinc.conf format.
func (es Entries) Render() string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "%s = %s\n", e.Key, e.Value)
	}
	return b.String()
}

// canonicalKey returns the canonical capitalization for known keys; unknown
// keys are returned unchanged. This keeps parse output stable while not
// rejecting future or unknown variables.
func canonicalKey(k string) string {
	if c, ok := canonical[strings.ToLower(k)]; ok {
		return c
	}
	return k
}

var canonical = map[string]string{
	"address":           "Address",
	"addressfamily":     "AddressFamily",
	"autoconnect":       "AutoConnect",
	"bindtoaddress":     "BindToAddress",
	"bindtointerface":   "BindToInterface",
	"broadcast":         "Broadcast",
	"broadcastsubnet":   "BroadcastSubnet",
	"cipher":            "Cipher",
	"clampmss":          "ClampMSS",
	"compression":       "Compression",
	"connectto":         "ConnectTo",
	"decrementttl":      "DecrementTTL",
	"device":            "Device",
	"devicestandby":     "DeviceStandby",
	"devicetype":        "DeviceType",
	"digest":            "Digest",
	"directonly":        "DirectOnly",
	"ed25519publickey":  "Ed25519PublicKey",
	"ed25519privatekey": "Ed25519PrivateKey",
	"forwarding":        "Forwarding",
	"fwmark":            "FWMark",
	"hostnames":         "Hostnames",
	"ifconfig":          "Ifconfig",
	"iffonequeue":       "IffOneQueue",
	"indirectdata":      "IndirectData",
	"interface":         "Interface",
	"invitationexpire":  "InvitationExpire",
	"keyexpire":         "KeyExpire",
	"listenaddress":     "ListenAddress",
	"localdiscovery":    "LocalDiscovery",
	"loglevel":          "LogLevel",
	"maclength":         "MACLength",
	"macexpire":         "MACExpire",
	"maxconnectionburst": "MaxConnectionBurst",
	"maxtimeout":        "MaxTimeout",
	"mode":              "Mode",
	"mtuinfointerval":   "MTUInfoInterval",
	"name":              "Name",
	"netname":           "Netname",
	"pmtu":              "PMTU",
	"pmtudiscovery":     "PMTUDiscovery",
	"pinginterval":      "PingInterval",
	"pingtimeout":       "PingTimeout",
	"port":              "Port",
	"priorityinheritance": "PriorityInheritance",
	"processpriority":   "ProcessPriority",
	"proxy":             "Proxy",
	"replaywindow":      "ReplayWindow",
	"route":             "Route",
	"sandbox":           "Sandbox",
	"scriptsextension":  "ScriptsExtension",
	"scriptsinterpreter": "ScriptsInterpreter",
	"strictsubnets":     "StrictSubnets",
	"subnet":            "Subnet",
	"tcponly":           "TCPOnly",
	"tunnelserver":      "TunnelServer",
	"udpdiscovery":      "UDPDiscovery",
	"udpdiscoveryinterval": "UDPDiscoveryInterval",
	"udpdiscoverykeepaliveinterval": "UDPDiscoveryKeepaliveInterval",
	"udpdiscoverytimeout": "UDPDiscoveryTimeout",
	"udpinfointerval":   "UDPInfoInterval",
	"udprcvbuf":         "UDPRcvBuf",
	"udpsndbuf":         "UDPSndBuf",
	"upnp":              "UPnP",
	"upnpdiscoverwait":  "UPnPDiscoverWait",
	"upnprefreshperiod": "UPnPRefreshPeriod",
	"weight":            "Weight",
	"wgpublickey":       "WGPublicKey",
	"wgprivatekey":      "WGPrivateKey",
	"wgendpoint":        "WGEndpoint",
}
