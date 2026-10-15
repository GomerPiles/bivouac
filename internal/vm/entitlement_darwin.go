package vm

import (
	"context"
	"errors"
	"os/exec"
)

// CheckEntitlement reports whether exe is signed with Entitlement. Without
// it the framework refuses every VM configuration.
func CheckEntitlement(ctx context.Context, exe string) error {
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", exe).Output()
	if err != nil {
		return errors.New("read code signature: " + err.Error())
	}
	if !entitled(out, Entitlement) {
		return errors.New("executable lacks the " + Entitlement + " entitlement; sign it with tools/macos/bivouac.entitlements")
	}
	return nil
}
