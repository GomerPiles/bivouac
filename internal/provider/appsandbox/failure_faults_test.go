package appsandbox

import (
	"context"
	"errors"
)

// Faults apply to both fake-backed restart tests and opt-in native tests.
// After-operation failures model a response lost after the mutation committed.
type nativeAPIFault struct {
	NativeAPI
	createAfter, deleteAfter bool
}

func (f *nativeAPIFault) CreateClone(ctx context.Context, r CloneRecord, user, password string) error {
	if err := f.NativeAPI.CreateClone(ctx, r, user, password); err != nil {
		return err
	}
	if f.createAfter {
		f.createAfter = false
		return ErrOutcomeUnknown
	}
	return nil
}
func (f *nativeAPIFault) VMCommand(ctx context.Context, name, action string) error {
	if err := f.NativeAPI.VMCommand(ctx, name, action); err != nil {
		return err
	}
	if action == "delete" && f.deleteAfter {
		f.deleteAfter = false
		return ErrOutcomeUnknown
	}
	return nil
}

type nativeNetworkFault struct {
	NativeNetwork
	attachAfter, deleteBefore, verifyBefore, blockBefore bool
}

func (f *nativeNetworkFault) Attach(ctx context.Context, r EngineRecord) error {
	if err := f.NativeNetwork.Attach(ctx, r); err != nil {
		return err
	}
	if f.attachAfter {
		f.attachAfter = false
		return errors.New("injected loss after native network attachment")
	}
	return nil
}
func (f *nativeNetworkFault) Delete(ctx context.Context, r EngineRecord) error {
	if f.deleteBefore {
		f.deleteBefore = false
		return errors.New("injected network cleanup failure")
	}
	return f.NativeNetwork.Delete(ctx, r)
}
func (f *nativeNetworkFault) Verify(ctx context.Context, r EngineRecord) error {
	if f.verifyBefore {
		return errors.New("injected policy verification failure")
	}
	return f.NativeNetwork.Verify(ctx, r)
}
func (f *nativeNetworkFault) Block(ctx context.Context, r EngineRecord) error {
	if f.blockBefore {
		return errors.New("injected port-block failure")
	}
	return f.NativeNetwork.Block(ctx, r)
}
