package dnsproxy_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/dnsproxy"
	"github.com/GomerPiles/bivouac/internal/macnetwork"
	"github.com/GomerPiles/bivouac/internal/rootnet"
	"github.com/miekg/dns"
)

func TestSandboxedDNSCapability(t *testing.T) {
	if os.Getenv("BIVOUAC_DNS_CAPABILITY_FIXTURE") == "1" {
		f := os.NewFile(3, "dns-capability")
		defer func() { _ = f.Close() }()
		client, err := dnsproxy.NewClient(f, 32)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = client.Close() }()
		if rootnet.ApplySandbox() != nil {
			t.Fatal("sandbox unavailable")
		}
		q := new(dns.Msg)
		q.SetQuestion("fixture.invalid.", dns.TypeTXT)
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		raw, err = client.Resolve(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		m, err := dnsproxy.ValidateResponse(raw, q)
		if err != nil || len(m.Answer) != 1 {
			t.Fatal("sandboxed DNS FD I/O failed")
		}
		if _, err := os.ReadFile("/etc/hosts"); err == nil {
			t.Fatal("DNS capability broadened file rights")
		}
		if _, err := macnetwork.Policy(); err != nil {
			t.Fatal("route refresh unavailable")
		}
		return
	}
	b, fd, err := dnsproxy.NewBroker(func(_ context.Context, raw []byte) ([]byte, error) {
		var q dns.Msg
		if q.Unpack(raw) != nil {
			return nil, errors.New("invalid fixture query")
		}
		m := new(dns.Msg)
		m.SetReply(&q)
		m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"fixture"}}}
		return m.Pack()
	}, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	defer func() { _ = fd.Close() }()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestSandboxedDNSCapability$")
	cmd.ExtraFiles = []*os.File{fd}
	cmd.Env = []string{"HOME=/", "BIVOUAC_DNS_CAPABILITY_FIXTURE=1"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("DNS sandbox fixture: %v: %s", err, out)
	}
}
