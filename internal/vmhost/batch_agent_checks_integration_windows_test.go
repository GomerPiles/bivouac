//go:build windows && integration

package vmhost

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

func labReadFrame(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > 65536 {
		return 0, nil, errors.New("fixture bound")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return h[0], b, err
}
func labWriteFrame(w io.Writer, kind byte, p []byte) error {
	h := binary.BigEndian.AppendUint32([]byte{kind}, uint32(len(p))) // #nosec G115 -- bounded fixture.
	if _, err := w.Write(h); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func TestAgentLiveChecksUseOnlyFixedAgentCommands(t *testing.T) {
	var calls []string
	good := guestagent.InstallationFacts{TaskUser: true, TaskHighest: true, TaskInteractive: true, TaskAction: true, TaskPriority: 4, OwnerTrusted: true, ACLProtected: true, ACLExpected: true}
	dial := func(context.Context) (net.Conn, error) {
		host, guest := net.Pipe()
		go func() {
			defer func() { _ = guest.Close() }()
			kind, p, err := labReadFrame(guest)
			if err != nil || kind != 'R' {
				return
			}
			var req struct {
				Argv  []string
				Stdin bool
				V     int
			}
			if json.Unmarshal(p, &req) != nil || req.Stdin || req.V != guestagent.Version || len(req.Argv) < 4 || req.Argv[0] != guestagent.WindowsPath {
				return
			}
			mode := req.Argv[len(req.Argv)-1]
			calls = append(calls, mode)
			var result any = map[string]bool{}
			switch mode {
			case "loopback":
				result = map[string]bool{"loopback_refused": true}
			case "inspect":
				result = good
			case "lab-start":
				result = map[string]bool{"started": true}
			case "lab-status":
				result = map[string]bool{"alive": true, "outside_job": true}
			case "lab-task-cycle", "lab-agent-cycle":
				result = map[string]bool{"scheduled": true}
			case "lab-task-result", "lab-agent-result":
				result = map[string]bool{"complete": true, "restarted": true}
			}
			b, _ := json.Marshal(result)
			if labWriteFrame(guest, 'O', b) != nil {
				return
			}
			_ = labWriteFrame(guest, 'X', []byte{0, 0, 0, 0})
		}()
		return host, nil
	}
	facts, err := agentLiveChecks(t.Context(), dial)
	want := []string{"loopback", "inspect", "lab-start", "lab-status", "lab-task-cycle", "lab-task-result", "lab-status", "lab-agent-cycle", "lab-agent-result", "lab-status", "lab-stop"}
	if err != nil || !facts.valid() || !slices.Equal(calls, want) {
		t.Fatal("incorrect live-gate command sequence", err, calls)
	}
	for _, field := range []string{"loopback_refused", "probe_outside_job", "task_restart_survived", "agent_kill_survived"} {
		b, _ := json.Marshal(facts)
		var value map[string]any
		_ = json.Unmarshal(b, &value)
		value[field] = false
		b, _ = json.Marshal(value)
		var bad agentLiveFacts
		if json.Unmarshal(b, &bad) != nil || bad.valid() {
			t.Fatal("missing live gate accepted", field)
		}
	}
	b, _ := json.Marshal(facts)
	for _, text := range []string{"SID", "C:\\", "imageuser"} {
		if strings.Contains(string(b), text) {
			t.Fatal("non-fixed live facts")
		}
	}
}
