package appsandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/GomerPiles/bivouac/internal/provider"
)

// CommandRunner accepts argument arrays, never a shell command. Outputs are
// bounded and not included in errors: native diagnostics contain host metadata.
type CommandRunner interface {
	Output(context.Context, string, []string) ([]byte, error)
}
type NativeCommands struct{}

func (NativeCommands) Output(ctx context.Context, binary string, args []string) ([]byte, error) {
	return (NativeCommands{}).OutputLimit(ctx, binary, args, maxResponseBytes)
}
func (NativeCommands) OutputLimit(ctx context.Context, binary string, args []string, limit int) ([]byte, error) {
	return nativeCommand(ctx, binary, args, nil, limit)
}

// Input sends opaque JIT bytes to authenticated SSH stdin, never argv or logs.
func (NativeCommands) Input(ctx context.Context, binary string, args []string, data []byte) ([]byte, error) {
	return nativeCommand(ctx, binary, args, bytes.NewReader(data), maxResponseBytes)
}
func nativeCommand(ctx context.Context, binary string, args []string, input io.Reader, limit int) ([]byte, error) {
	if limit < 1 || limit > 45<<20 {
		return nil, errors.New("invalid native output bound")
	}
	// #nosec G702 -- System vfpctrl/OpenSSH use fixed argument arrays; no shell or credential argument is used.
	cmd := exec.CommandContext(ctx, binary, args...)
	hideCommandWindow(cmd)
	cmd.Stdin = input
	output := boundedOutput{limit: limit}
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	ssh := strings.EqualFold(filepath.Base(binary), "ssh.exe") || filepath.Base(binary) == "ssh"
	stderr := boundedOutput{limit: 8 << 10}
	if ssh {
		cmd.Stderr = &stderr
	}
	defer func() { clear(stderr.data) }()
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			if ssh && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				if kind := classifySSH(stderr); !kind.Retryable() {
					return nil, kind
				}
				return nil, provider.SSHTimeout
			}
			return nil, ctx.Err()
		}
		var status *exec.ExitError
		if errors.As(err, &status) {
			if ssh && status.ExitCode() == 255 {
				return nil, fmt.Errorf("SSH failed (exit 255): %w", classifySSH(stderr))
			}
			return nil, fmt.Errorf("native command %s failed (exit %d)", filepath.Base(binary), status.ExitCode())
		}
		return nil, errors.New("native command failed")
	}
	if output.overflow {
		return nil, errors.New("native filtering response exceeds bound")
	}
	return output.data, nil
}

// Do not retain arbitrary stderr, even after redaction. Truncation cannot prove
// the absence of a terminal authentication/key error, so it fails immediately.
func classifySSH(stderr boundedOutput) provider.TransportFailure {
	if stderr.overflow {
		return provider.SSHDiagnosticLimit
	}
	data := bytes.ToLower(stderr.data)
	defer clear(data)
	for _, pattern := range []string{"host key verification failed", "remote host identification has changed", "offending", "no matching host key", "revoked host key", "host key is revoked"} {
		if bytes.Contains(data, []byte(pattern)) {
			return provider.SSHHostKey
		}
	}
	for _, pattern := range []string{"no matching key exchange", "no matching cipher", "no matching mac", "bad configuration", "bad permissions", "load key", "identity file", "unknown option", "unknown configuration", "invalid format"} {
		if bytes.Contains(data, []byte(pattern)) {
			return provider.SSHConfiguration
		}
	}
	for _, pattern := range []string{"permission denied", "authentication failed", "authentication failures", "signing failed"} {
		if bytes.Contains(data, []byte(pattern)) {
			return provider.SSHAuthentication
		}
	}
	for _, entry := range []struct {
		pattern string
		kind    provider.TransportFailure
	}{
		{"timed out", provider.SSHTimeout},
		{"connection refused", provider.SSHRefused},
		{"connection reset", provider.SSHReset},
		{"connection closed", provider.SSHClosed},
		{"broken pipe", provider.SSHClosed},
	} {
		if bytes.Contains(data, []byte(entry.pattern)) {
			return entry.kind
		}
	}
	// OpenSSH uses 255 for transport failure (and can pass through a remote
	// 255). The fixed status command gets bounded grace for this ambiguity;
	// other exit codes and invalid responses remain terminal.
	return provider.SSHUnavailable
}

type boundedOutput struct {
	data     []byte
	overflow bool
	limit    int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	limit := b.limit
	if limit == 0 {
		limit = maxResponseBytes
	}
	remaining := limit - len(b.data)
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil
}

type VFP struct {
	Binary   string
	Commands CommandRunner
}
type vfpItem struct {
	ID                  string `json:"Id"`
	Name                string
	Type                int
	SubType             int
	Flags               int
	Priority            int
	GroupMatchType      int
	Conditions          []json.RawMessage
	MatchConditionTypes []json.RawMessage
	TimeToLive          int
	RuleFlags           int
}
type vfpReply struct {
	Layers           []vfpItem
	Groups           []vfpItem
	Rules            []vfpItem
	InformationArray []struct {
		Enabled        bool
		Blocked        bool
		BlockOnRestore bool
	}
	VfpCtrlTrailer     *struct{ NumErrors int }
	VfpCtrlErrorRecord struct {
		ErrorCode int
		Function  string
	}
}

func (v VFP) run(ctx context.Context, args []string, query bool) (vfpReply, error) {
	var result vfpReply
	data, err := v.Commands.Output(ctx, v.Binary, append(args, "/format", "1"))
	if err != nil {
		operation := "operation"
		for _, arg := range args {
			if strings.HasPrefix(arg, "/") {
				operation = arg
			}
		}
		return result, fmt.Errorf("VFP %s: %w", operation, err)
	}
	if !query {
		return result, nil
	}
	if len(data) > maxResponseBytes || json.Unmarshal(data, &result) != nil {
		return result, errors.New("invalid bounded native filter response")
	}
	if result.VfpCtrlTrailer == nil {
		return result, errors.New("native filter query omitted its result trailer")
	}
	if result.VfpCtrlTrailer.NumErrors != 0 {
		if result.VfpCtrlTrailer.NumErrors == 1 && result.VfpCtrlErrorRecord.ErrorCode == 259 && result.VfpCtrlErrorRecord.Function == "JsonWriteItemListStart" {
			return result, nil
		}
		return result, errors.New("native filter query failed")
	}
	return result, nil
}
func filterArgs(n NetworkPlan, rest ...string) []string {
	return append([]string{"/port", n.EndpointID, "/layer", n.Layer}, rest...)
}
func filterGroupArgs(n NetworkPlan, direction string, rest ...string) []string {
	return append(filterArgs(n, "/group", direction), rest...)
}
func filterDirections() [4]string { return [4]string{"in", "out", "inv6", "outv6"} }

func (v VFP) Add(ctx context.Context, n NetworkPlan) error {
	layers, err := v.run(ctx, []string{"/port", n.EndpointID, "/list-layer"}, true)
	if err != nil {
		return err
	}
	for _, layer := range layers.Layers {
		if layer.ID == n.Layer {
			return errors.New("owned filter layer exists; reconcile instead of recreating")
		}
	}
	// A new layer cannot be selected with /layer until /add-layer creates it.
	if _, err = v.run(ctx, []string{"/port", n.EndpointID, "/add-layer", strings.Join([]string{n.Layer, "BivouacIsolation", "stateless", "10", "1"}, " ")}, false); err != nil {
		return err
	}
	for _, direction := range filterDirections() {
		if _, err = v.run(ctx, filterArgs(n, "/add-group", strings.Join([]string{direction, "BivouacIsolation", direction, "100"}, " ")), false); err != nil {
			return err
		}
		if direction == "inv6" || direction == "outv6" {
			if _, err = v.run(ctx, filterGroupArgs(n, direction, "/add-rule-ex", "block6 BivouacBlock * * * * * 1 0 100 block"), false); err != nil {
				return err
			}
			continue
		}
		for index, prefix := range n.Blocked {
			source, destination := "*", "*"
			if direction == "out" {
				destination = prefix
			} else {
				source = prefix
			}
			description := strings.Join([]string{"block" + strconv.Itoa(index), "BivouacBlock", "*", source, "*", destination, "*", "1", "0", "100", "block"}, " ")
			if _, err = v.run(ctx, filterGroupArgs(n, direction, "/add-rule-ex", description), false); err != nil {
				return err
			}
		}
	}
	return v.Verify(ctx, n)
}
func (v VFP) Verify(ctx context.Context, n NetworkPlan) error {
	layers, err := v.run(ctx, []string{"/port", n.EndpointID, "/list-layer"}, true)
	if err != nil {
		return err
	}
	count := 0
	for _, layer := range layers.Layers {
		if layer.ID == n.Layer {
			count++
			if layer.Name != "BivouacIsolation" || layer.Type != 3 || layer.SubType != 1 || layer.Priority != 10 || layer.Flags != 1 {
				return errors.New("native owned filter layer differs")
			}
		}
	}
	if count != 1 {
		return errors.New("native owned filter layer missing")
	}
	groups, err := v.run(ctx, filterArgs(n, "/list-group"), true)
	if err != nil {
		return err
	}
	if len(groups.Groups) != 4 {
		return errors.New("native filter group count differs")
	}
	for index, direction := range filterDirections() {
		found := 0
		for _, group := range groups.Groups {
			if group.ID == direction {
				found++
				if group.Type != 4 || group.SubType != index+1 || group.Name != "BivouacIsolation" || group.Flags != 0 || group.Priority != 100 || group.GroupMatchType != 0 || len(group.Conditions) != 0 || len(group.MatchConditionTypes) != 0 {
					return errors.New("native filter group differs")
				}
			}
		}
		if found != 1 {
			return errors.New("native filter direction missing")
		}
		rules, err := v.run(ctx, filterGroupArgs(n, direction, "/list-rule"), true)
		if err != nil {
			return err
		}
		if err = verifyFilterRules(direction, n.Blocked, rules.Rules); err != nil {
			return err
		}
	}
	return nil
}
func verifyFilterRules(direction string, prefixes []string, rules []vfpItem) error {
	ipv6 := direction == "inv6" || direction == "outv6"
	expected := len(prefixes)
	if ipv6 {
		expected = 1
	}
	if len(rules) != expected {
		return errors.New("native block rule count differs")
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.Type != 5 || rule.SubType != 2 || rule.Name != "BivouacBlock" || rule.Flags != 1 || rule.Priority != 100 || rule.TimeToLive != 0 || rule.RuleFlags != 0 || seen[rule.ID] {
			return errors.New("native block rule differs")
		}
		seen[rule.ID] = true
		if ipv6 {
			if rule.ID != "block6" || len(rule.Conditions) != 0 {
				return errors.New("native IPv6 blanket denial differs")
			}
			continue
		}
		index, err := strconv.Atoi(strings.TrimPrefix(rule.ID, "block"))
		if err != nil || rule.ID != "block"+strconv.Itoa(index) || index < 0 || index >= len(prefixes) || len(rule.Conditions) != 1 {
			return errors.New("native IPv4 block identity differs")
		}
		var condition struct {
			ConditionType int
			SourceIPList  []struct {
				A string
				C int
			}
			DestinationIPList []struct {
				A string
				C int
			}
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(rule.Conditions[0], &fields) != nil {
			return errors.New("invalid native IP condition fields")
		}
		for key := range fields {
			switch key {
			case "$type", "ConditionType", "SourceIPList", "DestinationIPList":
			default:
				return errors.New("unexpected native IP condition field")
			}
		}
		if json.Unmarshal(rule.Conditions[0], &condition) != nil {
			return errors.New("invalid native IP condition")
		}
		list := condition.SourceIPList
		kind := 2
		if direction == "out" {
			list = condition.DestinationIPList
			kind = 3
		}
		prefix, err := netip.ParsePrefix(prefixes[index])
		if err != nil {
			return err
		}
		if condition.ConditionType != kind || len(list) != 1 || list[0].A != prefix.Masked().Addr().String() || list[0].C != prefix.Bits() {
			return errors.New("native IP denial prefix differs")
		}
		if direction == "out" && len(condition.SourceIPList) != 0 || direction == "in" && len(condition.DestinationIPList) != 0 {
			return errors.New("unexpected native IP condition")
		}
	}
	return nil
}
func (v VFP) Block(ctx context.Context, n NetworkPlan) error {
	blocked, err := v.blocked(ctx, n)
	if err != nil || blocked {
		return err
	}
	if _, err = v.run(ctx, []string{"/port", n.EndpointID, "/block-port"}, false); err != nil {
		return err
	}
	blocked, err = v.blocked(ctx, n)
	if err != nil {
		return err
	}
	if !blocked {
		return errors.New("native filter port did not become blocked")
	}
	return nil
}

func (v VFP) blocked(ctx context.Context, n NetworkPlan) (bool, error) {
	state, err := v.run(ctx, []string{"/port", n.EndpointID, "/get-port-state"}, true)
	if err != nil {
		return false, err
	}
	if len(state.InformationArray) != 1 || !state.InformationArray[0].Enabled {
		return false, errors.New("native filtering unavailable for port blocking")
	}
	return state.InformationArray[0].Blocked, nil
}
func (v VFP) Unblock(ctx context.Context, n NetworkPlan) error {
	state, err := v.run(ctx, []string{"/port", n.EndpointID, "/get-port-state"}, true)
	if err != nil {
		return err
	}
	if len(state.InformationArray) != 1 || !state.InformationArray[0].Enabled {
		return errors.New("native filter disabled before unblocking")
	}
	if !state.InformationArray[0].BlockOnRestore {
		if _, err := v.run(ctx, []string{"/port", n.EndpointID, "/block-port-on-restore"}, false); err != nil {
			return err
		}
		state, err = v.run(ctx, []string{"/port", n.EndpointID, "/get-port-state"}, true)
		if err != nil {
			return err
		}
		if len(state.InformationArray) != 1 || !state.InformationArray[0].Enabled || !state.InformationArray[0].BlockOnRestore {
			return errors.New("native restore blocking unconfirmed")
		}
	}
	if err := v.Verify(ctx, n); err != nil {
		return err
	}
	if state.InformationArray[0].Blocked {
		if _, err := v.run(ctx, []string{"/port", n.EndpointID, "/unblock-port"}, false); err != nil {
			return err
		}
	}
	return v.Ready(ctx, n)
}
func (v VFP) Ready(ctx context.Context, n NetworkPlan) error {
	state, err := v.run(ctx, []string{"/port", n.EndpointID, "/get-port-state"}, true)
	if err != nil {
		return err
	}
	if len(state.InformationArray) != 1 || !state.InformationArray[0].Enabled || state.InformationArray[0].Blocked || !state.InformationArray[0].BlockOnRestore {
		return errors.New("native filter port readiness differs")
	}
	return nil
}
