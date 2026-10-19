package appsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
)

type filterFixture struct {
	weaken         string
	calls          [][]string
	blocked        bool
	restoreMissing bool
}

type capturedFilterFixture struct {
	Layer  vfpItem
	Groups []vfpItem
	Rules  map[string][]vfpItem
}

func (f capturedFilterFixture) Output(_ context.Context, _ string, args []string) ([]byte, error) {
	result := map[string]any{"VfpCtrlTrailer": map[string]int{"NumErrors": 0}}
	switch {
	case slices.Contains(args, "/list-layer"):
		result["Layers"] = []vfpItem{f.Layer}
	case slices.Contains(args, "/list-group"):
		result["Groups"] = f.Groups
	case slices.Contains(args, "/list-rule"):
		result["Rules"] = f.Rules[args[slices.Index(args, "/group")+1]]
	default:
		return nil, errors.New("unexpected capture query")
	}
	return json.Marshal(result)
}

func TestVFPNativeCaptureMatchesCustomGroupPolicy(t *testing.T) {
	// Native VFP readback, with headers removed and IDs normalized. Keep the
	// observed custom-group fields rather than borrowing firewall-group values.
	data, err := os.ReadFile("testdata/vfp-native-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture capturedFilterFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	n := NetworkPlan{EndpointID: "endpoint", Layer: "owned", Blocked: []string{"240.0.0.0/4"}}
	if err := (VFP{Commands: fixture}).Verify(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	fixture.Groups[0].GroupMatchType = 4
	if err := (VFP{Commands: fixture}).Verify(context.Background(), n); err == nil {
		t.Fatal("accepted changed group matching semantics")
	}
}

func (f *filterFixture) Output(_ context.Context, _ string, args []string) ([]byte, error) {
	f.calls = append(f.calls, slices.Clone(args))
	trailer := map[string]any{"NumErrors": 0}
	result := map[string]any{"VfpCtrlTrailer": trailer}
	switch {
	case slices.Contains(args, "/list-layer"):
		layer := map[string]any{"Id": "owned", "Name": "BivouacIsolation", "Type": 3, "SubType": 1, "Flags": 1, "Priority": 10}
		if f.weaken == "priority" {
			layer["Priority"] = 1000
		}
		result["Layers"] = []any{layer}
	case slices.Contains(args, "/list-group"):
		var groups []any
		for i, direction := range filterDirections() {
			groups = append(groups, map[string]any{"Id": direction, "Name": "BivouacIsolation", "Type": 4, "SubType": i + 1, "Flags": 0, "Priority": 100, "GroupMatchType": 0, "Conditions": []any{}, "MatchConditionTypes": []any{}})
		}
		if f.weaken == "group" {
			groups = groups[:3]
		}
		result["Groups"] = groups
	case slices.Contains(args, "/list-rule"):
		direction := args[slices.Index(args, "/group")+1]
		rule := map[string]any{"Id": "block0", "Name": "BivouacBlock", "Type": 5, "SubType": 2, "Flags": 1, "Priority": 100, "TimeToLive": 0, "RuleFlags": 0}
		if direction == "in" || direction == "out" {
			kind, key := 2, "SourceIPList"
			if direction == "out" {
				kind, key = 3, "DestinationIPList"
			}
			condition := map[string]any{"ConditionType": kind, key: []any{map[string]any{"A": "10.0.0.0", "C": 8}}}
			if f.weaken == "prefix" {
				condition[key] = []any{map[string]any{"A": "10.0.0.0", "C": 24}}
			}
			if f.weaken == "protocol" {
				condition["Protocol"] = 6
			}
			rule["Conditions"] = []any{condition}
		} else {
			rule["Id"] = "block6"
			rule["Conditions"] = []any{}
		}
		if f.weaken == "ttl" {
			rule["TimeToLive"] = 1
		}
		result["Rules"] = []any{rule}
		if f.weaken == "missing-rule" {
			result["Rules"] = []any{}
		}
	case slices.Contains(args, "/get-port-state"):
		result["InformationArray"] = []any{map[string]any{"Enabled": f.weaken != "disabled", "Blocked": f.blocked, "BlockOnRestore": !f.restoreMissing && f.weaken != "restore"}}
	case slices.Contains(args, "/block-port-on-restore"):
		f.restoreMissing = false
		return []byte("Native command completed."), nil
	case slices.Contains(args, "/block-port"):
		f.blocked = f.weaken != "block-noop"
		return []byte("Native command completed."), nil
	case slices.Contains(args, "/unblock-port"):
		f.blocked = false
		return []byte("Native command completed."), nil
	default:
		return []byte("Native command completed."), nil
	}
	if f.weaken == "trailer" {
		delete(result, "VfpCtrlTrailer")
	}
	if f.weaken == "native-error" {
		trailer["NumErrors"] = 1
	}
	return json.Marshal(result)
}

func TestVFPUnblockDoesNotRepeatEnabledOrRestoreFlags(t *testing.T) {
	n := NetworkPlan{EndpointID: "endpoint", Layer: "owned", Blocked: []string{"10.0.0.0/8"}}
	for _, missing := range []bool{false, true} {
		f := &filterFixture{blocked: true, restoreMissing: missing}
		v := VFP{Commands: f}
		for range 2 {
			if err := v.Unblock(context.Background(), n); err != nil {
				t.Fatal(err)
			}
		}
		restores, unblocks := 0, 0
		for _, args := range f.calls {
			if slices.Contains(args, "/enable-port") {
				t.Fatal("repeated enable of a native-enabled port")
			}
			if slices.Contains(args, "/block-port-on-restore") {
				restores++
			}
			if slices.Contains(args, "/unblock-port") {
				unblocks++
			}
		}
		wantRestores := 0
		if missing {
			wantRestores = 1
		}
		if restores != wantRestores || unblocks != 1 {
			t.Fatal("repeated native port-state mutation")
		}
	}
	for _, weaken := range []string{"restore", "disabled"} {
		f := &filterFixture{blocked: true, weaken: weaken}
		if err := (VFP{Commands: f}).Unblock(context.Background(), n); err == nil {
			t.Fatal("unconfirmed port state accepted")
		}
		for _, args := range f.calls {
			if slices.Contains(args, "/unblock-port") {
				t.Fatal("unblocked before confirming port flags")
			}
		}
	}
}

type filterCreationFixture struct {
	filterFixture
	created bool
}

func (f *filterCreationFixture) Output(ctx context.Context, binary string, args []string) ([]byte, error) {
	if slices.Contains(args, "/add-layer") {
		if slices.Contains(args, "/layer") || f.created {
			return nil, errors.New("selecting a nonexistent layer or duplicate creation")
		}
		f.created = true
		return []byte("Native command completed."), nil
	}
	if slices.Contains(args, "/list-layer") && !f.created {
		return []byte(`{"Layers":[],"VfpCtrlTrailer":{"NumErrors":0}}`), nil
	}
	return f.filterFixture.Output(ctx, binary, args)
}

func TestVFPCreatesLayerWithoutSelectingItFirst(t *testing.T) {
	f := &filterCreationFixture{}
	n := NetworkPlan{EndpointID: "endpoint", Layer: "owned", Blocked: []string{"10.0.0.0/8"}}
	if err := (VFP{Binary: "system-tool", Commands: f}).Add(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if !f.created {
		t.Fatal("layer was not created")
	}
}

func TestVFPBlockIsIdempotentAndRequiresNativeReadback(t *testing.T) {
	n := NetworkPlan{EndpointID: "endpoint"}
	f := &filterFixture{}
	v := VFP{Commands: f}
	for range 2 {
		if err := v.Block(context.Background(), n); err != nil {
			t.Fatal(err)
		}
	}
	mutations := 0
	for _, args := range f.calls {
		if slices.Contains(args, "/block-port") {
			mutations++
		}
	}
	if mutations != 1 {
		t.Fatal("repeated block mutated an already blocked port")
	}
	for _, weaken := range []string{"block-noop", "disabled", "trailer", "native-error"} {
		if err := (VFP{Commands: &filterFixture{weaken: weaken}}).Block(context.Background(), n); err == nil {
			t.Fatalf("accepted unconfirmed block: %s", weaken)
		}
	}
}

func TestVFPRejectsWeakenedPolicyBeforeUnblocking(t *testing.T) {
	n := NetworkPlan{EndpointID: "endpoint", Layer: "owned", Blocked: []string{"10.0.0.0/8"}}
	for _, changed := range []string{"priority", "group", "prefix", "protocol", "ttl", "missing-rule", "trailer", "native-error"} {
		t.Run(changed, func(t *testing.T) {
			f := &filterFixture{weaken: changed}
			if err := (VFP{Binary: "system-tool", Commands: f}).Unblock(context.Background(), n); err == nil {
				t.Fatal("weakened policy accepted")
			}
			for _, args := range f.calls {
				if slices.Contains(args, "/unblock-port") {
					t.Fatal("port unblocked before proof")
				}
			}
		})
	}
}

func TestVFPAllowsTextMutationResponsesButRequiresReadback(t *testing.T) {
	f := &filterFixture{}
	n := NetworkPlan{EndpointID: "endpoint", Layer: "owned", Blocked: []string{"10.0.0.0/8"}}
	if err := (VFP{Binary: "system-tool", Commands: f}).Unblock(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	f.weaken = "restore"
	if err := (VFP{Binary: "system-tool", Commands: f}).Ready(context.Background(), n); err == nil {
		t.Fatal("restore without blocking accepted")
	}
}

type fixedFilterResponse string

func (f fixedFilterResponse) Output(context.Context, string, []string) ([]byte, error) {
	return []byte(f), nil
}
func TestVFPEmptyEnumerationIsNarrowlyRecognized(t *testing.T) {
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"VfpCtrlTrailer":{"NumErrors":1},"VfpCtrlErrorRecord":{"ErrorCode":259,"Function":"JsonWriteItemListStart"}}`, true},
		{`{"VfpCtrlTrailer":{"NumErrors":1},"VfpCtrlErrorRecord":{"ErrorCode":259,"Function":"Other"}}`, false},
		{`{"VfpCtrlTrailer":{"NumErrors":2},"VfpCtrlErrorRecord":{"ErrorCode":259,"Function":"JsonWriteItemListStart"}}`, false},
		{`{}`, false},
	} {
		_, err := (VFP{Commands: fixedFilterResponse(tc.body)}).run(context.Background(), []string{"/list-layer"}, true)
		if (err == nil) != tc.valid {
			t.Errorf("unexpected query result: %v", err)
		}
	}
}
