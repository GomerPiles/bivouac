//go:build integration && darwin

package vz

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/paths"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

// TestRealLinuxGuest needs an isolated BIVOUAC_HOME, BIVOUAC_EXE (signed host
// binary), BIVOUAC_LINUX_HELPER, and BIVOUAC_VZ_LINUX_BASELINE. It never opens
// GitHub sessions or uses the production home. Every disposable clone is
// recorded before creation, with cleanup checking both record and marker.
func TestRealLinuxGuest(t *testing.T) {
	baseline, exe, helper := os.Getenv("BIVOUAC_VZ_LINUX_BASELINE"), os.Getenv("BIVOUAC_EXE"), os.Getenv("BIVOUAC_LINUX_HELPER")
	if baseline == "" || exe == "" || helper == "" || os.Getenv("BIVOUAC_HOME") == "" {
		t.Skip("isolated Linux integration environment not configured")
	}
	if os.Getenv("BIVOUAC_VZ_CAPACITY_CONFIRMED") != "1" {
		t.Fatal("confirm isolated CPU/memory capacity before Linux validation")
	}
	layout, err := paths.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	lock, err := (control.Files{Dir: layout.State}).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	records, err := state.Open(layout.State, func() string { return "linux-integration" })
	if err != nil || len(records.List()) != 0 {
		t.Fatal("integration home must have no retained records", err)
	}
	cfg := config.VZ{GuestOS: "linux", Baseline: baseline, Helper: helper, CPU: 4, MemoryGB: 4}
	p, err := New("linux", cfg, GuestRuntime{OS: cfg.RunnerOS(), Helper: cfg.Helper}, records.ControllerID(), layout.VMs, &local{store: vm.Store(layout.VMs), exe: exe}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.SetRecords(records)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if err := p.CheckRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, baseline); !errors.Is(err, provider.ErrNotOwned) {
		t.Fatal("baseline deletion was not refused", err)
	}
	var previousMachineID string
	for round := 0; round < 2; round++ {
		func() {
			id := "it" + strconv.FormatInt(time.Now().UnixNano(), 36)
			name := "bivouac-linux-" + id
			if err := records.Put(&state.Instance{ID: id, Provider: "linux", Name: name, Phase: state.PhaseCreating, CreatedAt: time.Now(), CPU: 4, MemoryGB: 4}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
				defer cleanupCancel()
				found := false
				for _, i := range records.List() {
					found = found || i.ID == id && i.Name == name && i.Provider == p.name && records.ControllerID() == p.controllerID
				}
				if !found {
					return
				}
				st, err := p.Status(cleanupCtx, name)
				if err != nil || (st.Exists && (!st.Owned || st.Meta.InstanceID != id)) {
					t.Error("integration cleanup ownership could not be proven")
					return
				}
				if st.Exists {
					if err := p.Stop(cleanupCtx, name, 10*time.Second); err != nil {
						t.Error(err)
						return
					}
					if err := p.Delete(cleanupCtx, name); err != nil {
						t.Error(err)
						return
					}
				}
				if err := records.Remove(id); err != nil {
					t.Error(err)
				}
			})
			start := time.Now()
			spec := provider.Spec{Name: name, Baseline: baseline, CPU: 4, MemoryMB: 4096, Meta: provider.Metadata{ControllerID: records.ControllerID(), InstanceID: id}}
			if err := p.Create(ctx, spec); err != nil {
				t.Fatal(err)
			}
			if err := p.Start(ctx, name, io.Discard); err != nil {
				t.Fatal(err)
			}
			if err := p.WaitReady(ctx, name); err != nil {
				t.Fatal(err)
			}
			t.Logf("round %d: Linux ARM64 non-root agent ready in %s", round+1, time.Since(start).Round(time.Millisecond))
			for _, argv := range [][]string{
				{linuxguest.PreparedHelper, "version"},
				{"/opt/actions-runner/bin/Runner.Listener", "--version"},
				{"test", "!", "-e", "/tmp/bivouac-validation-sentinel"},
				{"touch", "/tmp/bivouac-validation-sentinel"},
				{"curl", "--fail", "--silent", "--show-error", "--output", "/dev/null", "https://github.com"},
				{"docker", "info", "--format", "{{.OSType}}"},
			} {
				if _, err := p.output(ctx, name, argv, nil); err != nil {
					t.Fatalf("guest check %s: %v", argv[0], err)
				}
			}
			identity, err := p.output(ctx, name, []string{"cat", "/etc/machine-id"}, nil)
			if err != nil || len(strings.TrimSpace(string(identity))) != 32 || string(identity) == previousMachineID {
				t.Fatal("clone machine identity is missing or reused", err)
			}
			previousMachineID = string(identity)
			provenance, err := p.guest(ctx, name, []string{"cat", "/etc/bivouac/prepared-image.json"}, nil, 4096)
			if err != nil {
				t.Fatal("prepared image provenance unavailable")
			}
			hash, err := linuxguest.HelperSHA256(helper)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := linuxguest.DecodePreparedImage(provenance, linuxguest.VZ, hash); err != nil {
				t.Fatal(err)
			}
			if err := p.runnerIsolation(name); err != nil {
				t.Fatal(err)
			}
			validateLinuxNetwork(t, ctx, p, name)
			containers, err := p.output(ctx, name, []string{"docker", "ps", "--all", "--quiet"}, nil)
			if err != nil || len(strings.TrimSpace(string(containers))) != 0 {
				t.Fatal("container state survived from another clone", err)
			}
			if _, err := p.output(ctx, name, []string{"docker", "create", "--name", "bivouac-validation-sentinel", "busybox:1.37.0", "true"}, nil); err != nil {
				t.Fatal("guest-local container creation failed", err)
			}
			args, err := p.LaunchArgs(name)
			if err != nil || strings.Contains(strings.Join(args, " "), "--input") || strings.Contains(strings.Join(args, " "), "--share") || !strings.Contains(strings.Join(args, " "), "--rootless-network") {
				t.Fatal("Linux helper received desktop or host-share options", err)
			}
			if err := p.Stop(ctx, name, 10*time.Second); err != nil {
				t.Fatal(err)
			}
			if err := p.Delete(ctx, name); err != nil {
				t.Fatal(err)
			}
			if st, err := p.Status(ctx, name); err != nil || st.Exists {
				t.Fatal("Linux clone deletion not confirmed", err)
			}
			if err := records.Remove(id); err != nil {
				t.Fatal(err)
			}
		}()
	}
}

// Credential-free probes target this host alone; no LAN inventory or scan is made.
func validateLinuxNetwork(t *testing.T, ctx context.Context, p *Provider, name string) {
	t.Helper()
	// #nosec G102 -- Explicit opt-in isolation test; the ephemeral listener sends no data and validates host NIC denial.
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	var hostAddresses []string
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				t.Fatal(err)
			}
			ip := prefix.Addr()
			if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				hostAddresses = append(hostAddresses, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
			}
		}
	}
	if len(hostAddresses) == 0 {
		t.Fatal("no host IPv4 address for isolation validation")
	}
	// Host-side positive controls: these listeners must actually be reachable.
	for _, address := range hostAddresses {
		conn, err := net.DialTimeout("tcp4", address, time.Second)
		if err != nil {
			t.Fatal("host listener positive control", err)
		}
		_ = conn.Close()
		accepted, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		_ = accepted.Close()
	}
	input, err := json.Marshal(hostAddresses)
	if err != nil {
		t.Fatal(err)
	}
	const probes = `import json,socket,struct,subprocess,sys
from pathlib import Path
routes=json.loads(subprocess.check_output(['ip','-j','route','show','default']))
gateway=routes[0]['gateway']
assert gateway=='192.0.2.1', 'unexpected virtual gateway'
servers=[line.split()[1] for line in Path('/etc/resolv.conf').read_text().splitlines() if line.startswith('nameserver ')]
if set(servers) <= {'127.0.0.53','127.0.0.54'} and servers:
 upstreams=subprocess.check_output(['resolvectl','dns',routes[0]['dev']],text=True).split(':',1)[1].split()
 assert upstreams and set(upstreams)=={gateway}, 'virtual DHCP DNS upstream differs'
else: assert servers and set(servers)=={gateway}, 'virtual DHCP resolver differs'
assert socket.getaddrinfo('example.com',443,socket.AF_INET), 'system resolver failed'
blocked=json.loads(sys.argv[1])+[gateway+':'+sys.argv[2]]
for address in blocked:
 host,port=address.rsplit(':',1)
 try: connection=socket.create_connection((host,int(port)),2)
 except OSError: continue
 connection.close(); raise AssertionError('host listener reachable')
query=struct.pack('!HHHHHH',0x1234,0x0100,1,0,0,0)+b'\x06github\x03com\x00'+struct.pack('!HH',1,1)
for host,allowed in [(gateway,True)]:
 udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.settimeout(2);udp.sendto(query,(host,53))
 try: data,_=udp.recvfrom(4096); answered=len(data)>12 and data[:2]==query[:2]
 except OSError: answered=False
 finally: udp.close()
 assert answered==allowed, 'virtual resolver DNS failed'
try: connection=socket.create_connection(('2606:4700:4700::1111',443),2)
except OSError: pass
else: connection.close();raise AssertionError('IPv6 uplink reachable')
`
	for _, argv := range [][]string{
		{"python3", "-c", probes, string(input), strconv.Itoa(port)},
		{"docker", "run", "--rm", "--privileged", "--network", "host", "--volume", "/:/guest", "busybox:1.37.0", "chroot", "/guest", "/usr/bin/python3", "-c", probes, string(input), strconv.Itoa(port)},
	} {
		if _, err := p.output(ctx, name, argv, nil); err != nil {
			t.Fatalf("isolated guest/container probe failed: %v", err)
		}
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("guest reached a blocked host listener")
	}
}
