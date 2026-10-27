package sandboxdiscovery

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/GomerPiles/bivouac/internal/hcs"
)

// Candidate is public routing metadata, never ownership authority. Consumers
// must authenticate the agent and corroborate their recorded CLI/boot identity.
type Candidate struct {
	ID        string `json:"id"`
	RuntimeID string `json:"runtime_id"`
}

func validID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(id, "-", "")
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 16 && strings.Trim(raw, "0") != ""
}

func (c Candidate) Valid() bool { return validID(c.ID) && validID(c.RuntimeID) }

func candidates(properties []hcs.Properties) ([]Candidate, error) {
	if len(properties) > 64 {
		return nil, errors.New("sandbox inventory bound exceeded")
	}
	result := []Candidate{}
	ids, runtimes := map[string]bool{}, map[string]bool{}
	for _, p := range properties {
		if p.Owner != "WindowsSandbox" || p.SystemType != hcs.SystemTypeVM || p.State != hcs.StateRunning {
			continue
		}
		candidate := Candidate{ID: strings.ToLower(p.ID), RuntimeID: strings.ToLower(p.RuntimeID)}
		if !candidate.Valid() || ids[candidate.ID] || runtimes[candidate.RuntimeID] || len(result) >= 16 {
			return nil, errors.New("sandbox native identity refused")
		}
		ids[candidate.ID], runtimes[candidate.RuntimeID] = true, true
		result = append(result, candidate)
	}
	return result, nil
}
