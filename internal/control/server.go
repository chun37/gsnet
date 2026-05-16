package control

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

// Handler implements daemon-side handling of a control request.
type Handler interface {
	Handle(ctx context.Context, m Message, w io.Writer) error
}

// HandlerFunc adapter.
type HandlerFunc func(ctx context.Context, m Message, w io.Writer) error

func (f HandlerFunc) Handle(ctx context.Context, m Message, w io.Writer) error {
	return f(ctx, m, w)
}

// Server listens on a UNIX socket and dispatches control messages.
type Server struct {
	NodeName string
	Cookie   string
	Handler  Handler

	listener net.Listener
	wg       sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (s *Server) trackConn(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.conns[c] = struct{}{}
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

func (s *Server) closeAllConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}

// NewCookie returns a fresh random control-socket cookie.
func NewCookie() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Listen creates the UNIX socket at path with mode 0600. Any pre-existing
// socket at path is removed first.
func (s *Server) Listen(path string) error {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return err
	}
	s.listener = l
	return nil
}

// Serve accepts connections until ctx is canceled or the listener is closed.
func (s *Server) Serve(ctx context.Context) error {
	if s.listener == nil {
		return errors.New("control.Server: Listen not called")
	}
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
		s.closeAllConns()
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			return err
		}
		s.trackConn(conn)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrackConn(conn)
			defer conn.Close()
			if err := s.handle(ctx, conn); err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "control: %v\n", err)
			}
		}()
	}
}

// Close stops accepting and waits for in-flight handlers to finish.
func (s *Server) Close() error {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) handle(ctx context.Context, conn net.Conn) error {
	// Greet first.
	g := Greeting{Name: s.NodeName, Major: 1, Minor: 0}
	if _, err := io.WriteString(conn, g.Encode()); err != nil {
		return err
	}

	r := bufio.NewReader(conn)
	first, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if err := s.authenticate(strings.TrimSpace(first)); err != nil {
		return err
	}

	// Send authenticated ack: "4 0 <pid>". 4 = response class for the ack.
	fmt.Fprintf(conn, "4 0 %d\n", os.Getpid())

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		msg, err := DecodeMessage(line)
		if err != nil {
			fmt.Fprintf(conn, "%d -1 %s\n", ClassRequest, err.Error())
			continue
		}
		if msg.Class != ClassRequest {
			fmt.Fprintf(conn, "%d -1 bad class\n", ClassRequest)
			continue
		}
		if s.Handler == nil {
			fmt.Fprintf(conn, "%d %d 0\n", ClassRequest, msg.Type)
			continue
		}
		if err := s.Handler.Handle(ctx, msg, conn); err != nil {
			fmt.Fprintf(conn, "%d %d %s\n", ClassRequest, msg.Type, err.Error())
		}
	}
}

func (s *Server) authenticate(line string) error {
	// Client first line: "0 ^<cookie> 0"
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "0" {
		return fmt.Errorf("control: bad auth line %q", line)
	}
	cookie := fields[1]
	if !strings.HasPrefix(cookie, "^") {
		return fmt.Errorf("control: cookie missing '^' prefix")
	}
	if cookie[1:] != s.Cookie {
		return errors.New("control: cookie mismatch")
	}
	return nil
}

// Client is a minimal control-socket client used by the gsnet CLI.
type Client struct {
	conn net.Conn
	r    *bufio.Reader

	ServerName string
	ServerPID  int
}

// Dial connects to the daemon at socketPath and authenticates using cookie.
func Dial(socketPath, cookie string) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, r: bufio.NewReader(conn)}

	greet, err := c.r.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	g, err := ParseGreeting(strings.TrimSpace(greet))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.ServerName = g.Name

	if _, err := fmt.Fprintf(conn, "0 ^%s 0\n", cookie); err != nil {
		_ = conn.Close()
		return nil, err
	}
	ack, err := c.r.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	var class, code, pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(ack), "%d %d %d", &class, &code, &pid); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("control: bad ack %q: %w", ack, err)
	}
	if code != 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("control: auth rejected: %s", ack)
	}
	c.ServerPID = pid
	return c, nil
}

// Send writes a request and returns the first response line.
func (c *Client) Send(t RequestType, args ...string) (string, error) {
	if _, err := io.WriteString(c.conn, EncodeMessage(t, args...)); err != nil {
		return "", err
	}
	return c.r.ReadString('\n')
}

// ReadLine reads one additional line (used for multi-line dump responses).
func (c *Client) ReadLine() (string, error) { return c.r.ReadString('\n') }

func (c *Client) Close() error { return c.conn.Close() }
