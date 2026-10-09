package gosthttp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/idna"
)

const (
	socks5Version              = 0x05
	socks5CommandConnect       = 0x01
	socks5AddressIPv4          = 0x01
	socks5AddressDomain        = 0x03
	socks5AddressIPv6          = 0x04
	socks5AuthNone             = 0x00
	socks5AuthUsernamePassword = 0x02
	socks5AuthUnavailable      = 0xff
	socks5UserPassVersion      = 0x01
	socks5MaxMessageSize       = 513
)

// SOCKS5ConnectError describes a failure reply to a SOCKS5 CONNECT request.
// Proxy never contains URL user information.
type SOCKS5ConnectError struct {
	Proxy  string
	Target string
	Reply  byte
}

func (e *SOCKS5ConnectError) Error() string {
	return fmt.Sprintf(
		"gosthttp: SOCKS5 CONNECT %s via %s failed: %s",
		e.Target,
		e.Proxy,
		socks5ReplyText(e.Reply),
	)
}

func socks5ReplyText(reply byte) string {
	switch reply {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown reply code 0x%02x", reply)
	}
}

func isSOCKS5Proxy(proxyURL *url.URL) bool {
	return proxyURL != nil && (proxyURL.Scheme == "socks5" || proxyURL.Scheme == "socks5h")
}

func sanitizedProxyString(proxyURL *url.URL) string {
	if proxyURL == nil {
		return ""
	}
	clone := cloneURL(proxyURL)
	clone.User = nil
	return clone.String()
}

func socks5Credentials(user *url.Userinfo) (username, password string, present bool, err error) {
	if user == nil {
		return "", "", false, nil
	}
	username = user.Username()
	password, _ = user.Password()
	if len(username) == 0 || len(username) > 255 || len(password) > 255 {
		return "", "", false, errors.New("gosthttp: invalid SOCKS5 username/password length")
	}
	return username, password, true, nil
}

func proxyOperationContext(parent context.Context, timeout time.Duration, conn net.Conn) (context.Context, func()) {
	operationCtx := parent
	cancel := func() {}
	if timeout > 0 {
		operationCtx, cancel = context.WithTimeout(parent, timeout)
	}
	if operationCtx.Done() == nil {
		return operationCtx, func() {
			_ = conn.SetDeadline(time.Time{})
			cancel()
		}
	}

	deadlineApplied := make(chan struct{})
	stop := context.AfterFunc(operationCtx, func() {
		_ = conn.SetDeadline(time.Now())
		close(deadlineApplied)
	})
	return operationCtx, func() {
		if !stop() {
			<-deadlineApplied
		}
		_ = conn.SetDeadline(time.Time{})
		cancel()
	}
}

func (t *Transport) connectSOCKS5(ctx context.Context, conn net.Conn, route dialRoute) error {
	operationCtx, cleanup := proxyOperationContext(ctx, t.ProxyConnectTimeout, conn)
	defer cleanup()
	err := socks5Connect(operationCtx, conn, route.proxyURL, route.targetAddr)
	if err == nil {
		return nil
	}
	if operationCtx.Err() != nil {
		return operationCtx.Err()
	}
	var connectError *SOCKS5ConnectError
	if errors.As(err, &connectError) {
		return err
	}
	return fmt.Errorf(
		"gosthttp: SOCKS5 CONNECT %s via %s: %w",
		route.targetAddr,
		sanitizedProxyString(route.proxyURL),
		err,
	)
}

func socks5Connect(ctx context.Context, conn net.Conn, proxyURL *url.URL, target string) error {
	username, password, hasCredentials, err := socks5Credentials(proxyURL.User)
	if err != nil {
		return err
	}

	var buffer [socks5MaxMessageSize]byte
	message := buffer[:0]
	if hasCredentials {
		message = append(message, socks5Version, 2, socks5AuthNone, socks5AuthUsernamePassword)
	} else {
		message = append(message, socks5Version, 1, socks5AuthNone)
	}
	if err := writeAll(conn, message); err != nil {
		return socks5IOError(ctx, "write authentication methods", err)
	}
	if _, err := io.ReadFull(conn, buffer[:2]); err != nil {
		return socks5IOError(ctx, "read authentication method", err)
	}
	if buffer[0] != socks5Version {
		return fmt.Errorf("unexpected protocol version 0x%02x", buffer[0])
	}
	switch buffer[1] {
	case socks5AuthNone:
	case socks5AuthUsernamePassword:
		if !hasCredentials {
			return errors.New("proxy selected username/password authentication that was not offered")
		}
		message = buffer[:0]
		message = append(message, socks5UserPassVersion, byte(len(username)))
		message = append(message, username...)
		message = append(message, byte(len(password)))
		message = append(message, password...)
		if err := writeAll(conn, message); err != nil {
			return socks5IOError(ctx, "write username/password authentication", err)
		}
		if _, err := io.ReadFull(conn, buffer[:2]); err != nil {
			return socks5IOError(ctx, "read username/password authentication", err)
		}
		if buffer[0] != socks5UserPassVersion {
			return fmt.Errorf("unexpected username/password version 0x%02x", buffer[0])
		}
		if buffer[1] != 0 {
			return errors.New("username/password authentication failed")
		}
	case socks5AuthUnavailable:
		return errors.New("no acceptable authentication methods")
	default:
		return fmt.Errorf("proxy selected unsupported authentication method 0x%02x", buffer[1])
	}

	message = buffer[:0]
	message = append(message, socks5Version, socks5CommandConnect, 0)
	message, err = appendSOCKS5Address(message, target)
	if err != nil {
		return err
	}
	if err := writeAll(conn, message); err != nil {
		return socks5IOError(ctx, "write CONNECT request", err)
	}
	if _, err := io.ReadFull(conn, buffer[:4]); err != nil {
		return socks5IOError(ctx, "read CONNECT reply", err)
	}
	if buffer[0] != socks5Version {
		return fmt.Errorf("unexpected CONNECT reply version 0x%02x", buffer[0])
	}
	if buffer[2] != 0 {
		return fmt.Errorf("non-zero CONNECT reserved field 0x%02x", buffer[2])
	}
	if buffer[1] != 0 {
		return &SOCKS5ConnectError{
			Proxy:  sanitizedProxyString(proxyURL),
			Target: target,
			Reply:  buffer[1],
		}
	}

	remaining := 0
	switch buffer[3] {
	case socks5AddressIPv4:
		remaining = net.IPv4len + 2
	case socks5AddressIPv6:
		remaining = net.IPv6len + 2
	case socks5AddressDomain:
		if _, err := io.ReadFull(conn, buffer[:1]); err != nil {
			return socks5IOError(ctx, "read CONNECT bound domain length", err)
		}
		if buffer[0] == 0 {
			return errors.New("zero-length CONNECT bound domain")
		}
		remaining = int(buffer[0]) + 2
	default:
		return fmt.Errorf("unknown CONNECT address type 0x%02x", buffer[3])
	}
	if _, err := io.ReadFull(conn, buffer[:remaining]); err != nil {
		return socks5IOError(ctx, "read CONNECT bound address", err)
	}
	return nil
}

func appendSOCKS5Address(buffer []byte, address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 target address %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("invalid SOCKS5 target port %q", portText)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			buffer = append(buffer, socks5AddressIPv4)
			buffer = append(buffer, ipv4...)
		} else {
			ipv6 := ip.To16()
			if ipv6 == nil {
				return nil, fmt.Errorf("invalid SOCKS5 target IP %q", host)
			}
			buffer = append(buffer, socks5AddressIPv6)
			buffer = append(buffer, ipv6...)
		}
	} else {
		asciiHost, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return nil, fmt.Errorf("invalid SOCKS5 target hostname %q: %w", host, err)
		}
		if len(asciiHost) == 0 || len(asciiHost) > 255 {
			return nil, errors.New("SOCKS5 target hostname must contain 1..255 bytes")
		}
		buffer = append(buffer, socks5AddressDomain, byte(len(asciiHost)))
		buffer = append(buffer, asciiHost...)
	}
	buffer = binary.BigEndian.AppendUint16(buffer, uint16(port))
	return buffer, nil
}

func writeAll(writer io.Writer, buffer []byte) error {
	for len(buffer) != 0 {
		written, err := writer.Write(buffer)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		buffer = buffer[written:]
	}
	return nil
}

func socks5IOError(ctx context.Context, operation string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%s: %w", operation, err)
}
