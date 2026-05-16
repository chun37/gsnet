// Package invite handles tinc-compatible invitation URLs and files.
//
// URL format (tinc.texi "How invitations work"):
//
//	hostname:port/<keyhash><cookie>
//
// where the slash-suffix is the concatenation of:
//   - keyhash: server's Ed25519 public key fingerprint (43-char base64url SHA-256)
//   - cookie:  shared secret identifying this invitation
//
// Both halves are URL-safe base64 (no padding). For SHA-256 the keyhash is
// always 43 characters; whatever remains is the cookie.
package invite

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/chun/gsnet/internal/keys"
)

// cookieBytes is the size of the random cookie before base64 encoding.
// 24 bytes → 32 base64url characters (no padding), giving plenty of entropy.
const cookieBytes = 24

// NewCookie returns a fresh random invitation cookie.
func NewCookie() (string, error) {
	buf := make([]byte, cookieBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// BuildURL constructs an invitation URL for the given server endpoint and
// signing public key. The cookie should be the secret shared with the invitee.
func BuildURL(host string, port int, pub keys.Ed25519Public, cookie string) URL {
	return URL{
		Host:    host,
		Port:    port,
		KeyHash: pub.Hash(),
		Cookie:  cookie,
	}
}

// keyHashLen is the length of a URL-safe base64-encoded SHA-256 hash without padding.
const keyHashLen = 43

// URL is a parsed invitation URL.
type URL struct {
	Host    string
	Port    int
	KeyHash string
	Cookie  string
}

func ParseURL(s string) (URL, error) {
	slash := strings.IndexByte(s, '/')
	if slash < 0 {
		return URL{}, fmt.Errorf("invitation URL %q: missing '/'", s)
	}
	hostport, secret := s[:slash], s[slash+1:]

	colon := strings.LastIndexByte(hostport, ':')
	if colon < 0 {
		return URL{}, fmt.Errorf("invitation URL %q: missing port", s)
	}
	host := hostport[:colon]
	portStr := hostport[colon+1:]
	if host == "" {
		return URL{}, fmt.Errorf("invitation URL %q: empty host", s)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return URL{}, fmt.Errorf("invitation URL %q: invalid port %q", s, portStr)
	}

	if len(secret) <= keyHashLen {
		return URL{}, fmt.Errorf("invitation URL %q: secret too short", s)
	}
	keyHash := secret[:keyHashLen]
	cookie := secret[keyHashLen:]
	if cookie == "" {
		return URL{}, fmt.Errorf("invitation URL %q: empty cookie", s)
	}

	return URL{Host: host, Port: port, KeyHash: keyHash, Cookie: cookie}, nil
}

func (u URL) String() string {
	return fmt.Sprintf("%s:%d/%s%s", u.Host, u.Port, u.KeyHash, u.Cookie)
}
