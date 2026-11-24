package challenge

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Redis keeps challenges in a Redis server shared by every verifier instance. Issue is
// SET key NX PX ttl and Consume is DEL, which Redis runs atomically: of two instances racing on
// the same challenge, exactly one sees it deleted.
//
// It speaks the small part of RESP it needs, so the verifier keeps no dependencies outside the
// standard library (ADR 0006).
type Redis struct {
	addr     string
	useTLS   bool
	password string
	username string
	db       int
	prefix   string
	ttl      time.Duration
	timeout  time.Duration

	mu   sync.Mutex
	idle []*redisConn
}

// NewRedis parses redis://[user:password@]host:port[/db] or rediss:// (TLS).
func NewRedis(rawURL string, ttl time.Duration) (*Redis, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	if u.Scheme != "redis" && u.Scheme != "rediss" {
		return nil, fmt.Errorf("redis url: scheme must be redis or rediss, got %q", u.Scheme)
	}
	r := &Redis{addr: u.Host, useTLS: u.Scheme == "rediss", prefix: "iris:challenge:", ttl: ttl, timeout: 2 * time.Second}
	if u.Port() == "" {
		r.addr = net.JoinHostPort(u.Hostname(), "6379")
	}
	if u.User != nil {
		r.password, _ = u.User.Password()
		if r.password == "" {
			r.password = u.User.Username() // redis://:secret@ and redis://secret@ both seen in practice
		} else {
			r.username = u.User.Username()
		}
	}
	if db := strings.Trim(u.Path, "/"); db != "" {
		if r.db, err = strconv.Atoi(db); err != nil {
			return nil, fmt.Errorf("redis url: database %q is not a number", db)
		}
	}
	return r, nil
}

func (r *Redis) TTL() time.Duration { return r.ttl }

func (r *Redis) key(c []byte) string { return r.prefix + hex.EncodeToString(c) }

func (r *Redis) Issue(ctx context.Context) ([]byte, error) {
	c, err := newChallenge()
	if err != nil {
		return nil, err
	}
	reply, err := r.do(ctx, "SET", r.key(c), "1", "NX", "PX", strconv.FormatInt(r.ttl.Milliseconds(), 10))
	if err != nil {
		return nil, err
	}
	if reply != "OK" {
		// 256 random bits colliding with a live challenge would mean a broken RNG.
		return nil, errors.New("redis: challenge already exists")
	}
	return c, nil
}

func (r *Redis) Consume(ctx context.Context, c []byte) (bool, error) {
	if len(c) != Size {
		return false, nil
	}
	reply, err := r.do(ctx, "DEL", r.key(c))
	if err != nil {
		return false, err
	}
	return reply == "1", nil
}

// Ping checks that the server answers, for startup and readiness checks.
func (r *Redis) Ping(ctx context.Context) error {
	reply, err := r.do(ctx, "PING")
	if err == nil && reply != "PONG" {
		err = fmt.Errorf("redis: unexpected PING reply %q", reply)
	}
	return err
}

type redisConn struct {
	net.Conn
	rd *bufio.Reader
}

func (r *Redis) do(ctx context.Context, args ...string) (string, error) {
	c, err := r.get(ctx)
	if err != nil {
		return "", err
	}
	reply, err := c.command(ctx, r.timeout, args...)
	if err != nil {
		c.Close() // the stream may be out of sync; never reuse it
		return "", err
	}
	r.put(c)
	return reply, nil
}

func (r *Redis) get(ctx context.Context) (*redisConn, error) {
	r.mu.Lock()
	if n := len(r.idle); n > 0 {
		c := r.idle[n-1]
		r.idle = r.idle[:n-1]
		r.mu.Unlock()
		return c, nil
	}
	r.mu.Unlock()

	d := net.Dialer{Timeout: r.timeout}
	var conn net.Conn
	var err error
	if r.useTLS {
		host, _, _ := net.SplitHostPort(r.addr)
		td := tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
		conn, err = td.DialContext(ctx, "tcp", r.addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", r.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}
	c := &redisConn{Conn: conn, rd: bufio.NewReader(conn)}
	if r.password != "" {
		auth := []string{"AUTH", r.password}
		if r.username != "" {
			auth = []string{"AUTH", r.username, r.password}
		}
		if _, err := c.command(ctx, r.timeout, auth...); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if r.db != 0 {
		if _, err := c.command(ctx, r.timeout, "SELECT", strconv.Itoa(r.db)); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return c, nil
}

func (r *Redis) put(c *redisConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.idle) < 8 {
		r.idle = append(r.idle, c)
		return
	}
	c.Close()
}

// command writes one RESP array and reads one reply: simple string, error, or integer.
// Bulk replies are not needed by the commands above and are rejected.
func (c *redisConn) command(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.SetDeadline(deadline); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := c.Write([]byte(b.String())); err != nil {
		return "", fmt.Errorf("redis: %w", err)
	}
	line, err := c.rd.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("redis: %w", err)
	}
	line = strings.TrimSuffix(line, "\r\n")
	if line == "" {
		return "", errors.New("redis: empty reply")
	}
	switch line[0] {
	case '+', ':':
		return line[1:], nil
	case '-':
		return "", fmt.Errorf("redis: %s", line[1:])
	case '$':
		if line == "$-1" { // SET NX on an existing key
			return "", nil
		}
	}
	return "", fmt.Errorf("redis: unexpected reply %q", line)
}
