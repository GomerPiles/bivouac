//go:build windows

package vmhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/sandboxdiscovery"
	"golang.org/x/sys/windows"
)

// requestTimeout bounds one request, including a create's own cleanup.
const requestTimeout = 4 * time.Minute

// Server answers the pipe protocol for one Host. It authorizes every request
// by the caller's Windows account, and each guest by the account that created
// it: one account can neither see nor stop another's guests.
type Server struct {
	host            *Host
	cfg             Config
	identify        func(net.Conn) (string, error)
	discoverSandbox func(context.Context) ([]sandboxdiscovery.Candidate, error)
	// guardTimeout bounds the guard's work on one guest, including its
	// quarantine.
	guardTimeout time.Duration

	mu      sync.Mutex
	closing bool
	// admission is set while a guard pass fails or a guest is quarantined.
	admission error
	guests    map[string]*owned
}

// owned is a guest or a reservation for one being created.
type owned struct {
	owner    string
	guest    *Guest
	cpu      uint32
	memoryMB uint64
	labels   map[string]string
	busy     bool // a request or the guard is operating on it
	// quarantined guests failed a network guard pass: their port is blocked
	// (or they were destroyed) and they report stopped until destroyed.
	quarantined bool
	// guardChecking permits status to read the recorded state during a check.
	guardChecking bool
	// guardDestroyed records confirmed cleanup; the owner still sees stopped
	// until it acknowledges destruction and releases the reservation.
	guardDestroyed bool
}

func NewServer(host *Host, cfg Config) *Server {
	return &Server{host: host, cfg: cfg, identify: pipeCaller, discoverSandbox: sandboxdiscovery.Discover, guardTimeout: 30 * time.Second, guests: map[string]*owned{}}
}

// Serve handles connections until ctx ends, then waits for requests in flight.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, func() {
		s.mu.Lock()
		s.closing = true
		s.mu.Unlock()
		_ = l.Close()
	})
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(conn)
		}()
	}
}

// DestroyAll ends every guest. The VM host calls it before exiting; its guests
// would otherwise end with its handles and be settled by the next Recover.
func (s *Server) DestroyAll(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	var guests []*Guest
	for name, o := range s.guests {
		if o.guest != nil && !o.busy {
			if !o.guardDestroyed {
				guests = append(guests, o.guest)
			}
			delete(s.guests, name)
		}
	}
	s.mu.Unlock()
	var errs []error
	for _, g := range guests {
		errs = append(errs, s.host.Destroy(ctx, g))
	}
	return errors.Join(errs...)
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var req Request
	d := json.NewDecoder(io.LimitReader(conn, maxRequest))
	d.DisallowUnknownFields()
	resp := Response{Code: CodeRefused, Error: "invalid request"}
	if d.Decode(&req) == nil {
		// A pipe client can only be impersonated after its data was read.
		if sid, err := s.identify(conn); err != nil || !slices.Contains(s.cfg.PipeAccounts(), sid) {
			resp = Response{Code: CodeRefused, Error: "caller is not an authorized account"}
		} else {
			_ = conn.SetDeadline(time.Now().Add(requestTimeout + 30*time.Second))
			ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
			resp = s.dispatch(ctx, sid, req)
			cancel()
		}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func refused(text string) Response { return Response{Code: CodeRefused, Error: text} }

func failure(err error) Response {
	switch {
	case errors.Is(err, ErrForeign):
		return Response{Code: CodeForeign, Error: err.Error()}
	case hcs.OutcomeUnknown(err):
		return Response{Code: CodeUnknown, Error: err.Error()}
	default:
		return Response{Code: CodeFailed, Error: err.Error()}
	}
}

func (s *Server) dispatch(ctx context.Context, sid string, req Request) Response {
	if req.Op == "sandbox-candidates" {
		if !slices.Contains(s.cfg.SandboxAccounts, sid) || req.Name != "" || req.Create != nil {
			return refused("Sandbox discovery capability required")
		}
		step, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		items, err := s.discoverSandbox(step)
		if err != nil {
			return Response{Code: CodeFailed, Error: "Sandbox native discovery unavailable"}
		}
		if len(items) > 16 {
			return refused("Sandbox discovery response exceeds bound")
		}
		for _, item := range items {
			if !item.Valid() {
				return refused("Sandbox discovery identity invalid")
			}
		}
		return Response{SandboxCandidates: items}
	}
	if !s.cfg.HCSEnabled() || !slices.Contains(s.cfg.Accounts, sid) {
		return refused("HCS lifecycle capability required")
	}
	switch req.Op {
	case "info":
		return Response{Info: s.info()}
	case "list":
		return s.list(sid)
	case "create":
		if req.Create == nil {
			return refused("create needs a guest")
		}
		return s.create(ctx, sid, *req.Create)
	case "status":
		return s.status(ctx, sid, req.Name)
	case "destroy":
		return s.destroy(ctx, sid, req.Name)
	}
	return refused("unknown operation")
}

func (s *Server) info() *Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := &Info{Controller: s.cfg.Controller, MaxInstances: s.cfg.MaxInstances, MaxCPU: s.cfg.MaxCPU, MaxMemoryMB: s.cfg.MaxMemoryMB, ImageContracts: map[string]int{}}
	for name, path := range s.cfg.Images {
		i.Images = append(i.Images, name)
		i.ImageContracts[name] = imageContract(path, s.host.native.CheckImage)
	}
	sort.Strings(i.Images)
	for _, o := range s.guests {
		i.Running++
		i.RunningCPU += o.cpu
		i.RunningMB += o.memoryMB
	}
	return i
}

func (s *Server) list(sid string) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	guests := []GuestInfo{}
	for name, o := range s.guests {
		if o.owner == sid && o.guest != nil {
			guests = append(guests, GuestInfo{Name: name, RuntimeID: o.guest.RuntimeID, State: o.state(), Labels: o.labels, Network: lease(o.guest)})
		}
	}
	sort.Slice(guests, func(i, j int) bool { return guests[i].Name < guests[j].Name })
	return Response{Guests: guests}
}

func (s *Server) create(ctx context.Context, sid string, c CreateRequest) Response {
	image, ok := s.cfg.Images[c.Image]
	if !ok {
		return refused("unknown image")
	}
	spec := Spec{Name: c.Name, Image: image, CPU: c.CPU, MemoryMB: c.MemoryMB, LazyMemory: c.LazyMemory, GPU: c.GPU, Network: c.Network, Labels: c.Labels}
	for _, id := range c.Services {
		spec.Services = append(spec.Services, Service{ID: id, Connect: []string{sid}})
	}
	if err := spec.Validate(); err != nil {
		return refused(err.Error())
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return refused("VM host is stopping")
	}
	if s.admission != nil {
		s.mu.Unlock()
		return refused("network guard closed admission: " + s.admission.Error())
	}
	if _, exists := s.guests[c.Name]; exists {
		s.mu.Unlock()
		return refused("guest name already in use")
	}
	var cpu uint32
	var memoryMB uint64
	for _, o := range s.guests {
		cpu += o.cpu
		memoryMB += o.memoryMB
	}
	if len(s.guests) >= s.cfg.MaxInstances || cpu+c.CPU > s.cfg.MaxCPU || memoryMB+c.MemoryMB > s.cfg.MaxMemoryMB {
		s.mu.Unlock()
		return refused("VM host limits reached")
	}
	reservation := &owned{owner: sid, cpu: c.CPU, memoryMB: c.MemoryMB, labels: c.Labels, busy: true}
	s.guests[c.Name] = reservation
	s.mu.Unlock()

	g, err := s.host.Create(ctx, spec)
	s.mu.Lock()
	defer s.mu.Unlock()
	reservation.busy = false
	if err != nil {
		// An unknown outcome or a failed cleanup keeps its reservation: the
		// journal still holds the guest until a later VM host's Recover
		// settles it.
		if !hcs.OutcomeUnknown(err) && !errors.Is(err, errRetained) {
			delete(s.guests, c.Name)
		}
		return failure(err)
	}
	reservation.guest = g
	return Response{Guest: &GuestInfo{Name: g.Name, RuntimeID: g.RuntimeID, State: StateRunning, TimingsMS: durations(g.Timings), Labels: c.Labels, Network: lease(g), ProtectedBeforeStart: g.Timings.ProtectedBeforeStart}}
}

// claim marks the caller's guest busy for one operation.
func (s *Server) claim(sid, name string) (*owned, Response, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.guests[name]
	if !ok || o.owner != sid || o.guest == nil {
		return nil, Response{Code: CodeNotFound, Error: "no such guest for this account"}, false
	}
	if o.busy {
		return nil, refused("guest is busy"), false
	}
	o.busy = true
	return o, Response{}, true
}

func (s *Server) release(o *owned) {
	s.mu.Lock()
	o.busy = false
	s.mu.Unlock()
}

func (s *Server) status(ctx context.Context, sid, name string) Response {
	s.mu.Lock()
	o, ok := s.guests[name]
	if !ok || o.owner != sid || o.guest == nil {
		s.mu.Unlock()
		return Response{Code: CodeNotFound, Error: "no such guest for this account"}
	}
	if o.guardChecking {
		resp := Response{Guest: &GuestInfo{Name: name, RuntimeID: o.guest.RuntimeID, State: o.state(), Labels: o.labels, Network: lease(o.guest)}}
		s.mu.Unlock()
		return resp
	}
	if o.busy {
		s.mu.Unlock()
		return refused("guest is busy")
	}
	o.busy = true
	s.mu.Unlock()
	defer s.release(o)
	state := o.state()
	if err := s.host.Running(ctx, o.guest); errors.Is(err, ErrForeign) {
		return failure(err)
	} else if err != nil {
		state = StateStopped
	}
	return Response{Guest: &GuestInfo{Name: name, RuntimeID: o.guest.RuntimeID, State: state, Labels: o.labels, Network: lease(o.guest)}}
}

func (s *Server) destroy(ctx context.Context, sid, name string) Response {
	o, resp, ok := s.claim(sid, name)
	if !ok {
		return resp
	}
	var err error
	if !o.guardDestroyed {
		err = s.host.Destroy(ctx, o.guest)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o.busy = false
	if err != nil {
		// The handle is released either way; the journal retains the guest.
		o.guest = nil
		return failure(err)
	}
	delete(s.guests, name)
	return Response{Guest: &GuestInfo{Name: name, State: StateAbsent}}
}

// pipeCaller identifies the client of an accepted pipe connection by
// impersonating it at identification level. Impersonation runs on its own
// locked thread; if reverting fails, that thread exits with its goroutine
// instead of running other work as the client.
func pipeCaller(conn net.Conn) (string, error) {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return "", errors.New("caller identity requires a named pipe")
	}
	type result struct {
		sid string
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		sid, reverted, err := impersonatedUser(f.Fd())
		if reverted {
			runtime.UnlockOSThread()
		}
		done <- result{sid, err}
	}()
	r := <-done
	return r.sid, r.err
}

func impersonatedUser(pipe uintptr) (sid string, reverted bool, err error) {
	impersonate := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
	if r, _, callErr := impersonate.Call(pipe); r == 0 {
		return "", true, callErr
	}
	var token windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if windows.RevertToSelf() != nil {
		if err == nil {
			_ = token.Close()
		}
		return "", false, errors.New("cannot revert pipe client impersonation")
	}
	if err != nil {
		return "", true, err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", true, err
	}
	return user.User.Sid.String(), true, nil
}

// clientAccess is all a pipe client needs. It excludes FILE_APPEND_DATA,
// which on a pipe means FILE_CREATE_PIPE_INSTANCE: accounts may connect but
// never serve the VM host's name.
const clientAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE

func pipeDescriptor(accounts []string) string {
	var b strings.Builder
	b.WriteString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	for _, sid := range accounts {
		fmt.Fprintf(&b, "(A;;0x%x;;;%s)", clientAccess|windows.READ_CONTROL, sid)
	}
	return b.String()
}

func (o *owned) state() string {
	if o.quarantined {
		return StateStopped
	}
	return StateRunning
}

func lease(g *Guest) *NetworkLease {
	if g == nil || g.Network == nil {
		return nil
	}
	return &NetworkLease{Address: g.Network.Address, Gateway: g.Network.Gateway, Prefix: 28, MAC: g.Network.MAC}
}

// GuardInterval is how often Guard reproves every networked guest.
const GuardInterval = 10 * time.Second

// Guard reproves each networked guest's endpoint, port policy and the host's
// effective denial every interval until ctx ends. A guest that fails is
// quarantined: its port is blocked, or the guest is destroyed if blocking
// fails, and it reports stopped until its owner destroys it. Admission stays
// closed while any guest is quarantined or a pass is incomplete. This polls;
// it is not an atomic reaction to a host interface change.
func (s *Server) Guard(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.guardPass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) guardPass(ctx context.Context) {
	s.mu.Lock()
	var claimed []*owned
	incomplete := false
	for _, o := range s.guests {
		switch {
		case o.guest == nil || o.guest.Network == nil || o.quarantined:
		case o.busy:
			incomplete = true // creating or destroying; checked next pass
		default:
			o.busy = true
			o.guardChecking = true
			claimed = append(claimed, o)
		}
	}
	s.mu.Unlock()
	var failures []error
	for _, o := range claimed {
		passCtx, cancel := context.WithTimeout(ctx, s.guardTimeout)
		err := s.host.VerifyNetwork(passCtx, o.guest)
		destroyed := false
		if err != nil && ctx.Err() == nil {
			failures = append(failures, err)
			if blockErr := s.host.BlockNetwork(passCtx, o.guest); blockErr != nil {
				// A port that cannot be blocked ends its guest.
				destroyed = s.host.Destroy(passCtx, o.guest) == nil
			}
		}
		cancel()
		s.mu.Lock()
		o.busy = false
		o.guardChecking = false
		o.guardDestroyed = destroyed
		if err != nil && ctx.Err() == nil {
			o.quarantined = true
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	quarantined := 0
	for _, o := range s.guests {
		if o.quarantined {
			quarantined++
		}
	}
	switch {
	case ctx.Err() != nil:
		// A canceled pass proves nothing; admission keeps its last state.
	case len(failures) != 0:
		s.admission = errors.Join(failures...)
	case quarantined != 0:
		s.admission = errors.New("quarantined guests await destruction")
	case incomplete:
		// Leave admission unchanged until every guest has been checked.
	default:
		s.admission = nil
	}
}
