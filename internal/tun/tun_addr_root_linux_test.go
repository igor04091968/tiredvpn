//go:build linux

package tun

import (
	"errors"
	"net"
	"slices"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
)

// v4AddrsOn lists the IPv4 addresses on a link as "ip/len" strings.
func v4AddrsOn(t *testing.T, name string) []string {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName(%s): %v", name, err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("AddrList(%s): %v", name, err)
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IPNet.String())
	}
	return out
}

func rootTUN(t *testing.T, name string) *TUNDevice {
	t.Helper()
	dev, err := CreateTUN(name, 1280)
	if err != nil {
		t.Skipf("cannot create TUN %s: %v", name, err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	return dev
}

// TestRootConfigureSubnetAssignsTunIP checks what the kernel ends up with,
// not what subnetAddr returns: the server TUN must carry -tun-ip itself.
// Run as described above rootOnly (sudo unshare -n, TIREDVPN_NETNS_TESTS=1).
func TestRootConfigureSubnetAssignsTunIP(t *testing.T) {
	rootOnly(t)
	dev := rootTUN(t, "fxsrv0")
	_, pool, _ := net.ParseCIDR("10.99.0.0/24")
	if err := dev.ConfigureSubnet(net.ParseIP("10.99.0.1").To4(), pool, nil); err != nil {
		t.Fatalf("ConfigureSubnet: %v", err)
	}
	if got := v4AddrsOn(t, dev.Name()); !slices.Equal(got, []string{"10.99.0.1/24"}) {
		t.Fatalf("server TUN addresses = %v, want [10.99.0.1/24]", got)
	}
}

// TestRootConfigureFallbackAssignsLocalIP drives the client's fallback branch:
// the p2p address is already on the link, so the first AddrAdd fails with
// EEXIST and Configure falls back to the /24 form, which must be the client's
// own address rather than the network.
func TestRootConfigureFallbackAssignsLocalIP(t *testing.T) {
	rootOnly(t)
	dev := rootTUN(t, "fxcli0")
	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	local, remote := net.ParseIP("10.99.0.7").To4(), net.ParseIP("10.99.0.1").To4()
	p2p, peer, _ := p2pAddrPlan(local, remote)
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: p2p, Peer: peer}); err != nil {
		t.Fatalf("pre-adding p2p address: %v", err)
	}
	if err := dev.Configure(local, remote, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	got := v4AddrsOn(t, dev.Name())
	if !slices.Contains(got, "10.99.0.7/24") || slices.Contains(got, "10.99.0.0/24") {
		t.Fatalf("client TUN addresses = %v, want 10.99.0.7/24 from the fallback and no network address", got)
	}
}

// TestRootConfigureSubnetInstallsAndRemovesIPv6MSSClamp verifies the server
// dual-stack setup owns an ip6 clamp table and that Close removes it without
// relying on the client-only v6Enabled state.
func TestRootConfigureSubnetInstallsAndRemovesIPv6MSSClamp(t *testing.T) {
	rootOnly(t)
	dev := rootTUN(t, "fxsrv6mss0")
	_, pool4, _ := net.ParseCIDR("10.99.1.0/24")
	_, pool6, _ := net.ParseCIDR("fd99:1::/64")
	server6 := &net.IPNet{IP: net.ParseIP("fd99:1::1"), Mask: pool6.Mask}
	if err := dev.ConfigureSubnet(net.ParseIP("10.99.1.1").To4(), pool4, server6); err != nil {
		if errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("kernel/network namespace does not support IPv6 TUN addresses: %v", err)
		}
		t.Fatalf("ConfigureSubnet: %v", err)
	}

	tablePresent := func() bool {
		t.Helper()
		conn, err := nftables.New()
		if err != nil {
			t.Fatalf("nftables.New: %v", err)
		}
		tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv6)
		if err != nil {
			t.Fatalf("ListTablesOfFamily: %v", err)
		}
		for _, table := range tables {
			if table.Name == mssTableName(dev.Name()) {
				return true
			}
		}
		return false
	}
	if !tablePresent() {
		t.Fatal("server dual-stack TUN did not install its IPv6 MSS table")
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if tablePresent() {
		t.Fatal("IPv6 MSS table survived TUN Close")
	}
}
