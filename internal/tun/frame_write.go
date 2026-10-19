package tun

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// frameWriteConn keeps complete frames contiguous even when the underlying
// stream returns short writes or several producers write concurrently.
type frameWriteConn struct {
	net.Conn
	mu          sync.Mutex
	pmtuMu      sync.Mutex
	pmtuTokens  float64
	pmtuUpdated time.Time
}

func (c *frameWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for written < len(p) {
		n, err := c.Conn.Write(p[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func sendPacketTooBig(conn net.Conn, pkt []byte, mtu int) error {
	response := packetTooBigForPeer(pkt, mtu)
	if response == nil {
		return nil
	}
	// RFC 4443 error rate limit: independent per tunnel, burst 10, 10/s.
	if c, ok := conn.(*frameWriteConn); ok && !c.allowPMTU(time.Now()) {
		return nil
	}
	frame := make([]byte, 4+len(response))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(response)))
	copy(frame[4:], response)
	_, err := conn.Write(frame)
	return err
}

func (c *frameWriteConn) allowPMTU(now time.Time) bool {
	c.pmtuMu.Lock()
	defer c.pmtuMu.Unlock()
	if c.pmtuUpdated.IsZero() {
		c.pmtuTokens = 10
	} else {
		c.pmtuTokens += now.Sub(c.pmtuUpdated).Seconds() * 10
		if c.pmtuTokens > 10 {
			c.pmtuTokens = 10
		}
	}
	c.pmtuUpdated = now
	if c.pmtuTokens < 1 {
		return false
	}
	c.pmtuTokens--
	return true
}
