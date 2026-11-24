package challenge

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRedis implements SET NX PX, DEL, PING, AUTH and SELECT over RESP, enough to test the
// client without a server. CI also runs these tests against a real Redis (IRIS_TEST_REDIS_URL).
type fakeRedis struct {
	mu       sync.Mutex
	keys     map[string]time.Time
	password string
	ln       net.Listener
	commands []string
}

func startFake(t *testing.T, password string) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis{keys: map[string]time.Time{}, password: password, ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeRedis) serve(c net.Conn) {
	defer c.Close()
	rd := bufio.NewReader(c)
	authed := f.password == ""
	for {
		head, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		n, _ := strconv.Atoi(strings.TrimSpace(head[1:]))
		args := make([]string, n)
		for i := range args {
			rd.ReadString('\n') // $len
			v, _ := rd.ReadString('\n')
			args[i] = strings.TrimSuffix(v, "\r\n")
		}
		f.mu.Lock()
		f.commands = append(f.commands, args[0])
		reply := ""
		switch {
		case args[0] == "AUTH":
			if args[len(args)-1] == f.password {
				authed, reply = true, "+OK"
			} else {
				reply = "-WRONGPASS invalid password"
			}
		case !authed:
			reply = "-NOAUTH Authentication required."
		case args[0] == "PING":
			reply = "+PONG"
		case args[0] == "SELECT":
			reply = "+OK"
		case args[0] == "SET":
			ms, _ := strconv.Atoi(args[5])
			if exp, ok := f.keys[args[1]]; ok && time.Now().Before(exp) {
				reply = "$-1"
			} else {
				f.keys[args[1]] = time.Now().Add(time.Duration(ms) * time.Millisecond)
				reply = "+OK"
			}
		case args[0] == "DEL":
			exp, ok := f.keys[args[1]]
			delete(f.keys, args[1])
			if ok && time.Now().Before(exp) {
				reply = ":1"
			} else {
				reply = ":0"
			}
		default:
			reply = "-ERR unknown command"
		}
		f.mu.Unlock()
		fmt.Fprintf(c, "%s\r\n", reply)
	}
}

func redisURL(t *testing.T, f *fakeRedis, password string) string {
	if password != "" {
		return "redis://:" + password + "@" + f.ln.Addr().String() + "/2"
	}
	return "redis://" + f.ln.Addr().String()
}

func exerciseStore(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	c, err := s.Issue(ctx)
	if err != nil || len(c) != Size {
		t.Fatalf("issue: %v %d", err, len(c))
	}
	if ok, err := s.Consume(ctx, c); !ok || err != nil {
		t.Fatalf("fresh challenge rejected: %v %v", ok, err)
	}
	if ok, _ := s.Consume(ctx, c); ok {
		t.Fatal("challenge accepted twice")
	}
	if ok, _ := s.Consume(ctx, make([]byte, Size)); ok {
		t.Fatal("unknown challenge accepted")
	}
	if ok, _ := s.Consume(ctx, []byte("short")); ok {
		t.Fatal("malformed challenge accepted")
	}
}

func TestRedisAgainstFake(t *testing.T) {
	f := startFake(t, "")
	s, err := NewRedis(redisURL(t, f, ""), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	exerciseStore(t, s)
}

func TestRedisExpiry(t *testing.T) {
	f := startFake(t, "")
	s, _ := NewRedis(redisURL(t, f, ""), 50*time.Millisecond)
	c, err := s.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	if ok, _ := s.Consume(context.Background(), c); ok {
		t.Fatal("expired challenge accepted")
	}
}

func TestRedisAuthAndSelect(t *testing.T) {
	f := startFake(t, "s3cret")
	s, _ := NewRedis(redisURL(t, f, "s3cret"), time.Minute)
	exerciseStore(t, s)
	f.mu.Lock()
	got := strings.Join(f.commands[:2], ",")
	f.mu.Unlock()
	if got != "AUTH,SELECT" {
		t.Fatalf("connection setup sent %s", got)
	}

	bad, _ := NewRedis("redis://:wrong@"+f.ln.Addr().String(), time.Minute)
	if _, err := bad.Issue(context.Background()); err == nil || !strings.Contains(err.Error(), "WRONGPASS") {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestRedisUnreachableIsAnErrorNotAReject(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	s, _ := NewRedis("redis://"+addr, time.Minute)
	if _, err := s.Consume(context.Background(), make([]byte, Size)); err == nil {
		t.Fatal("expected an error from an unreachable server")
	}
}

func TestNewRedisURLs(t *testing.T) {
	for in, want := range map[string]string{
		"redis://h":         "h:6379",
		"rediss://h:6380/3": "h:6380",
		"redis://:p@h:1":    "h:1",
	} {
		r, err := NewRedis(in, time.Minute)
		if err != nil || r.addr != want {
			t.Errorf("%s: %v %+v", in, err, r)
		}
	}
	for _, bad := range []string{"http://h", "redis://h/x", "::"} {
		if _, err := NewRedis(bad, time.Minute); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// TestRedisReal runs the shared contract against a real server when one is configured.
func TestRedisReal(t *testing.T) {
	u := os.Getenv("IRIS_TEST_REDIS_URL")
	if u == "" {
		t.Skip("IRIS_TEST_REDIS_URL not set")
	}
	s, err := NewRedis(u, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	exerciseStore(t, s)
}
