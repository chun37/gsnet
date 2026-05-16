// Package gossip implements the gsnet control plane: a small message protocol
// distributed between nodes to share topology (edges, subnets) and peer
// metadata (WireGuard public keys, endpoints).
//
// Wire format: each message is a JSON-encoded envelope. We deliberately use a
// simple, self-describing format because the volume is low (configuration
// churn, not packet data) and ease of debugging matters.
//
// Loop suppression: every Add/Del message carries a unique ID derived from
// (origin, monotonic counter). A receiver records seen IDs and drops repeats.
package gossip

import (
	"encoding/json"
	"fmt"
	"time"
)

// Kind is the discriminator for envelope payloads.
type Kind string

const (
	KindHello     Kind = "hello"
	KindAddEdge   Kind = "add_edge"
	KindDelEdge   Kind = "del_edge"
	KindAddSubnet Kind = "add_subnet"
	KindDelSubnet Kind = "del_subnet"
	KindAddNode   Kind = "add_node"
	KindDelNode   Kind = "del_node"
	KindPing      Kind = "ping"
	KindPong      Kind = "pong"
)

// Envelope is the on-the-wire form of a gossip message.
type Envelope struct {
	ID        string          `json:"id"`     // unique per-origin sequence
	Origin    string          `json:"origin"` // node that minted the message
	Kind      Kind            `json:"kind"`
	TS        int64           `json:"ts"`            // unix nanos at origin
	Payload   json.RawMessage `json:"payload"`       // kind-specific body
	Signature []byte          `json:"sig,omitempty"` // Ed25519 of SigningBytes()
}

// SigningBytes returns the canonical bytes signed by the origin. The signature
// covers everything except the signature itself, in a stable encoding so that
// re-encoding by intermediaries does not invalidate the signature.
func (e Envelope) SigningBytes() []byte {
	var b []byte
	b = append(b, e.ID...)
	b = append(b, 0)
	b = append(b, e.Origin...)
	b = append(b, 0)
	b = append(b, string(e.Kind)...)
	b = append(b, 0)
	for i := 56; i >= 0; i -= 8 {
		b = append(b, byte(e.TS>>i))
	}
	b = append(b, 0)
	b = append(b, e.Payload...)
	return b
}

// Hello announces a node and its current WireGuard key + endpoint.
//
// Ed25519Public is the raw 32-byte public key (not PEM, not base64) so it
// can be used directly for envelope verification.
type Hello struct {
	Name          string `json:"name"`
	Ed25519Public []byte `json:"ed25519_pub"`
	WGPublic      string `json:"wg_pub"`
	Endpoint      string `json:"endpoint,omitempty"` // host:port if known
}

type AddEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Weight int    `json:"weight"`
}

type DelEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type AddSubnet struct {
	Owner  string `json:"owner"`
	Subnet string `json:"subnet"`
}

type DelSubnet struct {
	Owner  string `json:"owner"`
	Subnet string `json:"subnet"`
}

// Encode serializes the envelope as a single-line JSON document.
func (e Envelope) Encode() ([]byte, error) {
	return json.Marshal(e)
}

// Decode parses a JSON-encoded envelope.
func Decode(b []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return Envelope{}, err
	}
	if e.Kind == "" || e.Origin == "" {
		return Envelope{}, fmt.Errorf("gossip: envelope missing required fields")
	}
	return e, nil
}

// NewID mints a unique message ID from origin and seq.
func NewID(origin string, seq uint64) string {
	return fmt.Sprintf("%s/%d", origin, seq)
}

// TSNow returns the current time in unix nanos.
func TSNow() int64 { return time.Now().UnixNano() }
