//go:build windows

package imagefactory

import (
	"context"
	"encoding/json"
	"errors"
)

func inspectOwned(ctx context.Context, c Config, r *record, setup bool, run func(context.Context, string, any, bool) ([]byte, error)) (*Inspection, error) {
	data := r.scriptData()
	data["guest_user"] = c.GuestUser
	if setup {
		data["mode"] = "setup"
	}
	b, runErr := run(ctx, runnerCheck+"\n"+(videoFacts+offlineFiles)+"\n"+inspectDisk, data, true)
	var facts Inspection
	if len(b) == 0 || json.Unmarshal(b, &facts) != nil {
		return nil, errors.Join(runErr, errors.New("invalid bounded inspection result"))
	}
	return &facts, runErr
}
