//go:build linux

package tun

import (
	"os"
	"testing"

	"github.com/google/nftables"
)

// Opt-in kernel validation; refuse to run in the host network namespace.
func TestMTUNFTIsolatedNamespace(t *testing.T) {
	if os.Getenv("TIREDVPN_MTU_NFT_TEST") != "1" {
		t.Skip("requires isolated root netns")
	}
	current, e1 := os.Readlink("/proc/self/ns/net")
	host, e2 := os.Readlink("/proc/1/ns/net")
	if e1 != nil || e2 != nil || current == host || os.Geteuid() != 0 {
		t.Fatal("refusing host network namespace or non-root run")
	}
	const iface = "mtu-audit0"
	defer removeMSSClamping(iface)
	defer removeMSSClampingV6(iface)
	if err := addMSSClamping(iface, 1280); err != nil {
		t.Fatal(err)
	}
	if err := addMSSClampingV6(iface, 1280); err != nil {
		t.Fatal(err)
	}
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, table := range tables {
		if table.Name != nftablesTableName+"-"+iface {
			continue
		}
		rules, err := conn.GetRules(table, &nftables.Chain{Name: "mssclamping", Table: table})
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 2 {
			t.Fatalf("family %v has %d rules", table.Family, len(rules))
		}
		found++
	}
	if found != 2 {
		t.Fatalf("wanted IPv4 and IPv6 tables, got %d", found)
	}
}
