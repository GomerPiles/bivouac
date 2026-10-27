//go:build integration && darwin

package vz

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/control"
	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/paths"
	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/rootnet"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

// TestRootlessGuestLab is an explicit lab, never part of ordinary CI. NAT is
// a separately selected trusted baseline measurement, never a managed fallback.
func TestRootlessGuestLab(t *testing.T) {
	if os.Getenv("BIVOUAC_ROOTLESS_LAB") != "1" {
		t.Skip("rootless lab not selected")
	}
	if os.Getenv("BIVOUAC_HOME") == "" || os.Getenv("BIVOUAC_VZ_CAPACITY_CONFIRMED") != "1" {
		t.Fatal("isolated home and capacity audit required")
	}
	exe, baseline, asset := os.Getenv("BIVOUAC_EXE"), os.Getenv("BIVOUAC_VZ_BASELINE"), os.Getenv("BIVOUAC_LAB_PUBLIC_ASSET")
	if asset != "" {
		u, err := url.Parse(asset)
		if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.Contains(u.Path, "/releases/download/") {
			t.Fatal("public asset must be a release URL without credentials")
		}
	} else {
		t.Log("public_downloads=skipped reason=asset_unset")
	}
	settings, err := rootlessLabSettings(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("network mtu=%d memory_mb=%d max_flows=%d tcp_idle_seconds=%.0f udp_idle_seconds=%.0f dns_overrides=%d dns_concurrency=%d tcp_buffer_bytes=%d cache_max_connections=%d cache_readers=%d", settings.network.MTU, settings.network.MemoryMB, settings.network.MaxFlows, settings.network.TCPIdleTimeout.Seconds(), settings.network.UDPIdleTimeout.Seconds(), len(settings.network.DNSServers), settings.network.DNSConcurrency(), settings.network.TCPBufferLimit(), settings.cacheMax, settings.readers)
	if exe == "" || baseline == "" {
		t.Fatal("explicit signed executable and isolated baseline required")
	}
	layout, err := paths.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.State, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := (control.Files{Dir: layout.State}).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	records, err := state.Open(layout.State, func() string { return "rootless-lab" })
	if err != nil {
		t.Fatal(err)
	}
	if len(records.List()) != 0 {
		t.Fatal("lab has retained records; recover before continuing")
	}
	rt := &local{store: vm.Store(layout.VMs), exe: exe}
	p, err := New("macos", config.VZ{Baseline: baseline, CPU: 2, MemoryGB: 4, HostVMLimit: 2, ForeignSlots: 1, Network: settings.network}, GuestRuntime{OS: "darwin"}, records.ControllerID(), layout.VMs, rt, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.SetRecords(records)
	modes := []bool{true}
	if os.Getenv("BIVOUAC_ROOTLESS_LAB_ROUNDS") == "2" {
		modes = []bool{true, true}
	}
	if os.Getenv("BIVOUAC_ROOTLESS_NAT_BENCHMARK") == "1" {
		modes = []bool{false, true}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	for index, isolated := range modes {
		if len(records.List()) != 0 {
			t.Fatal("prior lab guest retained ownership state; recover before another boot")
		}
		sampler := perf.NewSampler(layout.State)
		resources, err := sampler.Sample()
		if err != nil || resources.LogicalCPUs < 8 || resources.AvailableBytes < 10<<30 {
			t.Fatal("capacity unavailable: require test 2 CPU/4 GiB, Linux reservation 4 CPU/4 GiB, host 2 CPU and 2 GiB physical headroom")
		}
		name := "bivouac-macos-rootless-lab-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		if err := records.Put(&state.Instance{ID: name, Name: name, Provider: "macos", CPU: 2, MemoryGB: 4, Phase: state.PhaseCreating}); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				cleanup, done := context.WithTimeout(context.Background(), time.Minute)
				defer done()
				_ = p.Stop(cleanup, name, time.Second)
				if err := p.Delete(cleanup, name); err != nil {
					t.Error("lab guest deletion failed")
					return
				}
				if st, err := p.Status(cleanup, name); err != nil || st.Exists {
					t.Error("lab guest absence unproven")
					return
				}
				if err := records.Remove(name); err != nil {
					t.Error(err)
				}
			}()
			meta := provider.Metadata{ControllerID: records.ControllerID(), InstanceID: name}
			if isolated {
				meta.NetworkPolicy = rootnet.PolicyID
			}
			if err := p.createVM(ctx, provider.Spec{Name: name, Baseline: baseline, CPU: 2, MemoryMB: 4096, Meta: meta}, "darwin", vm.MachineOptions{}); err != nil {
				t.Fatal(err)
			}
			launchLog, err := os.OpenFile(filepath.Join(layout.State, "rootless-lab-helper.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = launchLog.Close() }()
			if err := p.startVM(ctx, name, Launch{RootlessNetwork: isolated, Input: true, Network: settings.network, CacheMaxConnections: settings.cacheMax}, launchLog); err != nil {
				t.Fatal(err)
			}
			guestCtx, stopGuest := context.WithCancel(ctx)
			defer stopGuest()
			monitorDone := make(chan struct{})
			defer func() { stopGuest(); <-monitorDone }()
			go func() {
				defer close(monitorDone)
				ticker := time.NewTicker(2 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-guestCtx.Done():
						return
					case <-ticker.C:
						sample, err := sampler.Sample()
						if err != nil || sample.AvailableBytes < 2<<30 {
							stopGuest()
							cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
							_ = p.Stop(cleanup, name, time.Second)
							done()
							return
						}
					}
				}
			}()
			start := time.Now()
			if err := p.waitVM(guestCtx, name); err != nil {
				t.Fatal("guest agent failed before lab readiness")
			}
			if err := p.installGuestScript(guestCtx, name); err != nil {
				t.Fatal(err)
			}
			if err := p.checkSession(guestCtx, name); err != nil {
				t.Fatal("Aqua readiness failed")
			}
			t.Logf("mode %d rootless=%t: ready_ms=%d", index, isolated, time.Since(start).Milliseconds())
			if os.Getenv("BIVOUAC_LAB_LOCAL_STREAM") == "1" {
				measureLocalAgentStream(t, guestCtx, p, name)
			}
			if isolated {
				ip, ipErr := p.guest(guestCtx, name, []string{"/usr/sbin/ipconfig", "getifaddr", "en0"}, nil, 64)
				if ipErr != nil || strings.TrimSpace(string(ip)) != rootnet.Guest {
					t.Fatal("rootless DHCP address incorrect")
				}
				checkLabMTU(t, guestCtx, p, name, settings.network.MTU)
				if err := p.runnerIsolation(name); err != nil {
					t.Fatal(err)
				}
				if os.Getenv("BIVOUAC_LAB_DNS_PROBES") == "1" {
					probeLabDNS(t, guestCtx, p, name)
				}
				if os.Getenv("BIVOUAC_LAB_LOCAL_TCP") == "1" || os.Getenv("BIVOUAC_LAB_LIMIT_PROBES") == "1" {
					stageLabFixture(t, guestCtx, p, name)
				}
				if os.Getenv("BIVOUAC_LAB_LOCAL_TCP") == "1" {
					measureLabTCP(t, guestCtx, p, name, launchLog.Name())
				}
				if os.Getenv("BIVOUAC_LAB_LIMIT_PROBES") == "1" {
					probeLabLimits(t, guestCtx, p, name, launchLog.Name())
				}
			}
			download := func(label, proxy string) int64 {
				maxTime := "90"
				if label == "during-full-cache-admission-direct" {
					maxTime = "5"
				}
				argv := []string{"/usr/bin/curl", "--fail", "--silent", "--show-error", "--location", "--connect-timeout", "10", "--max-time", maxTime, "--output", "/dev/null", "--write-out", "%{size_download} %{time_total}"}
				if proxy == "" {
					argv = append(argv, "--noproxy", "*")
				} else {
					argv = append(argv, "--proxy", proxy, "--noproxy", "", "--cacert", "/tmp/bivouac-cache-roots.pem")
				}
				if asset == "" {
					return 0
				}
				argv = append(argv, asset)
				result, err := p.guest(guestCtx, name, argv, nil, 128)
				if err != nil {
					var exit *guestagent.ExitError
					if errors.As(err, &exit) {
						t.Logf("mode %d %s curl exit category=%d", index, label, exit.Code)
					}
					t.Fatalf("mode %d %s public transfer failed", index, label)
				}
				fields := strings.Fields(string(result))
				if len(fields) != 2 {
					t.Fatal("invalid bounded transfer metrics")
				}
				size, e1 := strconv.ParseInt(fields[0], 10, 64)
				seconds, e2 := strconv.ParseFloat(fields[1], 64)
				if e1 != nil || e2 != nil || size < 1 || seconds <= 0 {
					t.Fatal("invalid numeric transfer metrics")
				}
				t.Logf("mode %d %s: bytes=%d seconds=%.3f mb_per_second=%.2f", index, label, size, seconds, float64(size)/seconds/1e6)
				return size
			}
			if _, err := p.output(guestCtx, name, []string{"test", "!", "-e", "/tmp/bivouac-lab-sentinel"}, nil); err != nil {
				t.Fatal("fresh clone retained prior lab state")
			}
			if _, err := p.output(guestCtx, name, []string{"/usr/bin/touch", "/tmp/bivouac-lab-sentinel"}, nil); err != nil {
				t.Fatal("clone-local reset sentinel unavailable")
			}
			directSize := download("direct", "")
			if isolated && os.Getenv("BIVOUAC_LAB_PUBLIC_PROBES") == "1" {
				validateGuestIsolation(t, guestCtx, p, name)
			}
			if !isolated {
				return
			}
			if err := p.installGuestHelper(guestCtx, name); err != nil {
				t.Fatal(err)
			}
			if probe := os.Getenv("BIVOUAC_LAB_PACKET_PROBE"); probe != "" {
				f, err := os.Open(probe)
				if err != nil {
					t.Fatal("open guest packet probe")
				}
				if err := labExec(t, guestCtx, p, name, "packet_stage", []string{"/usr/bin/install", "-m", "0700", "/dev/null", "/tmp/bivouac-network-probe"}, nil, io.Discard); err != nil {
					_ = f.Close()
					t.Fatal(err)
				}
				err = labExec(t, guestCtx, p, name, "packet_upload", []string{"dd", "of=/tmp/bivouac-network-probe", "status=none"}, f, io.Discard)
				_ = f.Close()
				if err != nil {
					t.Fatal("deliver guest packet probe")
				}
				if err := labExec(t, guestCtx, p, name, "metal_probe", []string{"/tmp/bivouac-network-probe", "--metal"}, nil, io.Discard); err != nil {
					t.Fatal("guest Metal GPU copy failed")
				}
				if err := labExec(t, guestCtx, p, name, "packet_probe", []string{"sudo", "-n", "/tmp/bivouac-network-probe"}, nil, io.Discard); err != nil {
					t.Fatal("privileged guest packet injection failed")
				}
				waitLabCounters(t, guestCtx, launchLog.Name(), func(r labCounterReport) bool {
					c := r.Counters
					return c.MACDenied > 0 && c.SourceDenied > 0 && c.ProtocolDenied > 0 && c.IPv6 > 0 && c.DNSInvalid > 0
				}, nil)
				t.Log("guest Metal buffer copy and privileged MAC/IP/ICMP/IPv6 denial counters verified")
			}
			if source := os.Getenv("BIVOUAC_LAB_DESKTOP_PROBE"); source != "" {
				f, err := os.Open(source)
				if err != nil {
					t.Fatal("desktop probe source unavailable")
				}
				err = labExec(t, guestCtx, p, name, "desktop_stage", []string{"/usr/bin/install", "-m", "0600", "/dev/null", "/tmp/bivouac-desktop-probe.swift"}, nil, io.Discard)
				if err == nil {
					err = labExec(t, guestCtx, p, name, "desktop_upload", []string{"/bin/dd", "of=/tmp/bivouac-desktop-probe.swift", "status=none"}, f, io.Discard)
				}
				_ = f.Close()
				if err != nil {
					t.Fatal("desktop probe staging failed")
				}
				if err := labExec(t, guestCtx, p, name, "desktop_compile", []string{"/usr/bin/xcrun", "swiftc", "-parse-as-library", "/tmp/bivouac-desktop-probe.swift", "-o", "/tmp/bivouac-desktop-probe"}, nil, io.Discard); err != nil {
					t.Fatal("desktop probe compilation failed")
				}
				desktopOutput := &boundedBuffer{limit: 1024}
				desktopCtx, cancelDesktop := context.WithTimeout(guestCtx, 20*time.Second)
				err = labExec(t, desktopCtx, p, name, "desktop_run", []string{"/tmp/bivouac-desktop-probe"}, nil, desktopOutput)
				cancelDesktop()
				result := desktopOutput.data
				var proof struct {
					FailedStage           int  `json:"failed_stage"`
					Window                bool `json:"window_visible"`
					Metal                 bool `json:"metal_readback"`
					Focus                 bool `json:"focus_verified"`
					Keyboard              int  `json:"typed_characters"`
					Pointer               int  `json:"button_actions"`
					PresentationTimestamp bool `json:"presentation_timestamp_available"`
				}
				parseErr := json.Unmarshal(result, &proof)
				if err != nil || parseErr != nil || !proof.Window || !proof.Metal || !proof.Focus || proof.Keyboard != 7 || proof.Pointer != 1 {
					t.Errorf("desktop window/focus/application-input verification failed: stage=%d", proof.FailedStage)
				}
				if err == nil && proof.Window && proof.Metal && proof.Focus && proof.Keyboard == 7 && proof.Pointer == 1 {
					t.Logf("visible window, Metal pixel readback, focus and application-routed keyboard/pointer events verified; presentation_timestamp_available=%t", proof.PresentationTimestamp)
				}
			}
			if fixture := os.Getenv("BIVOUAC_LAB_CACHE_FIXTURE"); fixture != "" {
				command := exec.CommandContext(guestCtx, fixture, "-test.run=^TestNativeCacheLocalTransport$", "-test.v", "-test.timeout=5m") //nolint:gosec // Explicit operator-selected lab executable, invoked without a shell.
				command.Env = append(os.Environ(), "BIVOUAC_NATIVE_CACHE_GUEST="+name)
				metrics := &boundedBuffer{limit: 64 << 10}
				command.Stdout = metrics
				fixtureStderr := guestagent.NewDiagnosticStderr()
				defer func() { _ = fixtureStderr.Close() }()
				command.Stderr = fixtureStderr
				probePublic := func(label string) {
					if asset == "" {
						return
					}
					dns, err := p.output(guestCtx, name, []string{"/usr/bin/dig", "@192.0.2.1", "github.com", "A", "+time=5", "+tries=1", "+short"}, nil)
					if err != nil || strings.TrimSpace(string(dns)) == "" {
						t.Fatal("public DNS failed during native load validation")
					}
					download(label, "")
				}
				var err error
				if os.Getenv("BIVOUAC_LAB_BURST_PROBES") == "1" {
					if _, err := p.output(guestCtx, name, []string{"/bin/rm", "-f", "/tmp/bivouac-cache-native-stage", "/tmp/bivouac-cache-native-probe-done"}, nil); err != nil {
						t.Fatal("native checkpoint reset failed")
					}
					err = command.Start()
					if err != nil {
						labFixtureFailure(t, "native_start", err, fixtureStderr)
						t.Fatal("native fixture start failed")
					}
					done := make(chan error, 1)
					go func() { done <- command.Wait() }()
					ticker := time.NewTicker(time.Second)
					defer ticker.Stop()
					probed := false
				waiting:
					for {
						select {
						case err = <-done:
							break waiting
						case <-ticker.C:
							if !probed {
								stage, stageErr := p.output(guestCtx, name, []string{"/bin/cat", "/tmp/bivouac-cache-native-stage"}, nil)
								if stageErr == nil && strings.TrimSpace(string(stage)) == "32-held" {
									probePublic("during-full-cache-admission-direct")
									if _, err := p.output(guestCtx, name, []string{"/usr/bin/touch", "/tmp/bivouac-cache-native-probe-done"}, nil); err != nil {
										t.Fatal("native full-admission release failed")
									}
									probed = true
								}
							}
						}
					}
					if !probed {
						t.Error("native burst ended without public-connection probes")
					}
				} else {
					err = command.Run()
				}
				result := metrics.data
				if metrics.exceeded {
					labFixtureFailure(t, "native_output", ErrOutputLimit, fixtureStderr)
					t.Fatal("native cache fixture output exceeded its bound")
				}
				if err != nil {
					labFixtureFailure(t, "native_run", err, fixtureStderr)
					t.Log(string(result))
					t.Fatal("native local cache fixture failed")
				}
				t.Log(string(result))
				probePublic("after-cache-burst-direct")
				if os.Getenv("BIVOUAC_LAB_POST_FIXTURE_HOLD") == "1" {
					t.Log("owned disposable guest diagnostic window ready")
					select {
					case <-guestCtx.Done():
					case <-time.After(3 * time.Minute):
					}
				}
				if os.Getenv("BIVOUAC_LAB_FIXTURE_ONLY") == "1" {
					return
				}
			}
			if asset != "" {
				service, err := cache.Start(layout.Cache, "127.0.0.1:0", "127.0.0.1", 1<<30, 256<<20, time.Hour, slog.New(slog.DiscardHandler))
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				service.SetEndpointLimit(settings.cacheMax)
				service.EnableReleaseProxy()
				service.EnableUploadStore()
				p.SetCache(service)
				if err := p.installCache(guestCtx, name); err != nil {
					t.Fatal("virtual endpoint cache setup failed")
				}
				env, err := p.guest(guestCtx, name, []string{"/usr/bin/head", "-n", "1", "/tmp/bivouac-cache-env"}, nil, 128)
				if err != nil {
					t.Fatal("guest proxy endpoint unavailable")
				}
				proxy := strings.TrimSpace(string(env))
				pu, err := url.Parse(proxy)
				if err != nil || pu.Scheme != "http" || pu.Hostname() != "127.0.0.1" {
					t.Fatal("guest proxy endpoint was not loopback")
				}
				download("cache-cold", proxy)
				download("cache-warm", proxy)
				summary, err := p.output(guestCtx, name, []string{guestHelper, "guest", "macos", "hook-completed", "/tmp"}, nil)
				if err != nil || !strings.Contains(string(summary), "[bivouac cache]") || strings.Contains(string(summary), "summary unavailable") {
					t.Fatal("virtual endpoint authenticated metrics unavailable")
				}
				snap := service.Snapshot()
				if snap.Releases.Hits < 1 || snap.Releases.Failures != 0 {
					t.Fatal("warm release cache did not serve a verified hit")
				}
				t.Logf("verified release cache hits=%d misses=%d failures=%d", snap.Releases.Hits, snap.Releases.Misses, snap.Releases.Failures)
				if settings.readers != 0 {
					readers := settings.readers
					argv := []string{"/usr/bin/curl", "--http1.1", "--parallel", "--parallel-immediate", "--parallel-max", strconv.Itoa(readers), "--silent", "--fail", "--location", "--connect-timeout", "10", "--max-time", "90", "--proxy", proxy, "--noproxy", "", "--cacert", "/tmp/bivouac-cache-roots.pem", "--write-out", "%{size_download} %{http_code} %{exitcode}\n"}
					for range readers {
						argv = append(argv, "--output", "/dev/null", asset)
					}
					before := service.Snapshot().Releases.Hits
					started := time.Now()
					metrics := &boundedBuffer{limit: readers * 128}
					err := labExec(t, guestCtx, p, name, "cache_parallel", argv, nil, metrics)
					result := metrics.data
					var exit *guestagent.ExitError
					if errors.As(err, &exit) {
						t.Logf("native parallel curl exit category=%d", exit.Code)
					}
					if err != nil {
						t.Logf("native parallel output_limit=%t rows=%d", metrics.exceeded, len(strings.Split(strings.TrimSpace(string(result)), "\n")))
					}
					var complete, failed int
					for _, line := range strings.Split(strings.TrimSpace(string(result)), "\n") {
						fields := strings.Fields(line)
						if len(fields) != 3 {
							continue
						}
						code, e := strconv.Atoi(fields[2])
						if e != nil {
							continue
						}
						if code == 0 {
							complete++
						} else {
							failed++
							size, _ := strconv.ParseInt(fields[0], 10, 64)
							status, _ := strconv.Atoi(fields[1])
							t.Logf("native parallel transfer failure category=%d bytes=%d http_status=%d", code, size, status)
						}
					}
					t.Logf("native parallel completed=%d failed=%d", complete, failed)
					if err != nil {
						t.Fatal("native concurrent cache/download fallback failed")
					}

					lines := strings.Split(strings.TrimSpace(string(result)), "\n")
					if len(lines) != readers {
						t.Fatal("native concurrent download count differs")
					}
					for _, line := range lines {
						fields := strings.Fields(line)
						if len(fields) != 3 {
							t.Fatal("native parallel metrics invalid")
						}
						size, err := strconv.ParseInt(fields[0], 10, 64)
						if err != nil || size != directSize || fields[1] != "200" {
							t.Fatal("native parallel download incomplete")
						}
					}
					seconds := time.Since(started).Seconds()
					t.Logf("native cache concurrency: readers=%d bytes=%d seconds=%.3f aggregate_mb_per_second=%.2f cache_hits=%d", readers, int64(readers)*directSize, seconds, float64(int64(readers)*directSize)/seconds/1e6, service.Snapshot().Releases.Hits-before)
				}
				service.Close()
				download("cache-outage", proxy)
			}
			restarted, err := New(p.name, p.cfg, p.runner, p.controllerID, string(p.store), rt, nil)
			if err != nil {
				t.Fatal(err)
			}
			restarted.SetRecords(records)
			if err := restarted.runnerIsolation(name); err != nil {
				t.Fatal("live rootless adoption proof failed")
			}
			// Sentinel is clone-local; the next ordinary integration round checks reset.
			if _, err := p.output(guestCtx, name, []string{"/usr/bin/touch", "/tmp/bivouac-lab-sentinel"}, nil); err != nil {
				t.Fatal(err)
			}
			if err := p.runnerIsolation(name); err != nil {
				t.Fatal("owned rootless child proof failed")
			}
			pid, err := vm.NetworkChildPID(p.vmDir(name))
			if err != nil {
				t.Fatal(err)
			}
			process, err := os.FindProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			if err := process.Kill(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				st, err := p.Status(ctx, name)
				if err == nil && !st.Running {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("guest survived its network/VM owner process loss")
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Log("sandboxed network child loss retired the disposable VM")
		}()
	}
}

// measureLocalAgentStream excludes disks, the cache handler, public freshness
// checks and the Ethernet stack. Only this disposable guest's agent is used.
func measureLocalAgentStream(t *testing.T, parent context.Context, p *Provider, name string) {
	t.Helper()
	const size = 256 << 20
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	start := time.Now()
	if err := labExec(t, ctx, p, name, "agent_stream", []string{"/bin/dd", "if=/dev/zero", "bs=1048576", "count=256"}, nil, io.Discard); err != nil {
		t.Fatal("local agent download failed")
	}
	t.Logf("local agent download bytes=%d seconds=%.3f mb_per_second=%.2f", size, time.Since(start).Seconds(), float64(size)/time.Since(start).Seconds()/1e6)
	start = time.Now()
	if err := labExec(t, ctx, p, name, "agent_stream", []string{"/bin/dd", "of=/dev/null", "bs=1048576"}, io.LimitReader(labZeroReader{}, size), io.Discard); err != nil {
		t.Fatal("local agent upload failed")
	}
	t.Logf("local agent upload bytes=%d seconds=%.3f mb_per_second=%.2f", size, time.Since(start).Seconds(), float64(size)/time.Since(start).Seconds()/1e6)
	stream, stderr, err := labDuplex(t, ctx, p, name, "agent_duplex_start", []string{"/bin/cat"})
	if err != nil {
		t.Fatal("local agent duplex unavailable")
	}
	defer func() { _ = stream.Close(); _ = stderr.Close() }()
	stopStream := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stopStream()
	start = time.Now()
	sent := make(chan error, 1)
	go func() {
		_, err := io.CopyN(stream, labZeroReader{}, size)
		if err == nil {
			if half, ok := stream.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			} else {
				err = io.ErrClosedPipe
			}
		}
		sent <- err
	}()
	n, err := io.Copy(io.Discard, stream)
	if err != nil || n != size {
		labFixtureFailure(t, "agent_duplex_read", err, stderr)
		_ = stream.Close()
		if sendErr := <-sent; sendErr != nil {
			labFixtureFailure(t, "agent_duplex_write", sendErr, stderr)
		}
		t.Fatal("local agent duplex download incomplete")
	}
	if err := <-sent; err != nil {
		labFixtureFailure(t, "agent_duplex_write", err, stderr)
		t.Fatal("local agent duplex upload incomplete")
	}
	t.Logf("local agent duplex bytes_per_direction=%d seconds=%.3f mb_per_second=%.2f", size, time.Since(start).Seconds(), float64(size)/time.Since(start).Seconds()/1e6)
}

type labZeroReader struct{}

func (labZeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
