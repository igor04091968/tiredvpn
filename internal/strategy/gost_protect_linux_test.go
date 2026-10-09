//go:build linux

package strategy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protect"
	"golang.org/x/sys/unix"
)

func TestGOSTSocketProtectionBeforeConnect(t *testing.T) {
	// The protector is process-global and has no reset API. Isolate it from
	// the other strategy tests, which run without an Android VPN service.
	if os.Getenv("TIREDVPN_GOST_PROTECT_TEST") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestGOSTSocketProtectionBeforeConnect$")
		cmd.Env = append(os.Environ(), "TIREDVPN_GOST_PROTECT_TEST=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated protector test: %v\n%s", err, out)
		}
		return
	}
	// Unix sockets have a short path limit; GOTMPDIR can be a long USB path.
	dir, err := os.MkdirTemp("/tmp", "tv-gost-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "protect.sock")
	app, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	seen := make(chan error, 1)
	go func() {
		for {
			c, err := app.Accept()
			if err != nil {
				return
			}
			var fd [4]byte
			_, err = io.ReadFull(c, fd[:])
			if err != nil {
				c.Close()
				continue
			} // initialization check
			_, err = unix.Getpeername(int(binary.LittleEndian.Uint32(fd[:])))
			seen <- err
			_, _ = c.Write([]byte{1}) // Android rejects protection
			c.Close()
			return
		}
	}()
	if err := protect.InitAndroidProtector(path); err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := gostProtectedDialer(time.Second).DialContext(ctx, "tcp4", tcp.Addr().String())
	if err == nil {
		c.Close()
		t.Fatal("unprotected connection was allowed")
	}
	select {
	case err := <-seen:
		if err != unix.ENOTCONN {
			t.Fatalf("socket already connected before protect: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Android protector was never called")
	}
	_ = tcp.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if c, err := tcp.Accept(); err == nil {
		c.Close()
		t.Fatal("TCP connection reached server after protect rejection")
	}
}
