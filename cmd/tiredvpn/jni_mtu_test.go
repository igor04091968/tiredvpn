package main

import "testing"

func TestJNIValidatesMTU(t *testing.T) {
	for _, value := range []string{"1279", "9001", "0", "-1", "1400oops", "huge"} {
		if _, err := parseClientArgs([]string{"-server", "127.0.0.1:443", "-tun-mtu", value}); err == nil {
			t.Errorf("accepted MTU %q", value)
		}
	}
	for _, value := range []string{"1280", "1400", "9000"} {
		if _, err := parseClientArgs([]string{"-server", "127.0.0.1:443", "-tun-mtu", value}); err != nil {
			t.Errorf("rejected %s: %v", value, err)
		}
	}
	if _, err := parseClientArgs([]string{"-server", "127.0.0.1:443", "-tun-mtu"}); err == nil {
		t.Fatal("accepted missing MTU")
	}
}
