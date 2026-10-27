package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// A receipt and a fresh guest proof are both required. Inventory alone never
// adopts a Sandbox. These are lab proofs, not native HCS ownership metadata.
type labRecord struct {
	Name  string `json:"name"`
	ID    string `json:"sandbox_id"`
	Phase string `json:"phase"`
	Boot  string `json:"boot"`
}

type ownershipProof struct {
	Name    string `json:"name"`
	ID      string `json:"sandbox_id"`
	Boot    string `json:"boot"`
	Request string `json:"request"`
}

func validGUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	value = strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && strings.Trim(value, "0") != ""
}

func (r labRecord) valid() bool {
	return validGUID(r.ID) && r.Name == "bivouac-sandbox-"+r.ID && (r.Phase == "planned" || r.Phase == "started" || r.Phase == "stopped") && (r.Boot == "" || validGUID(r.Boot))
}

func (r labRecord) accepts(p ownershipProof, request string) bool {
	return r.valid() && r.Phase == "started" && validGUID(request) && p.Request == request &&
		p.Name == r.Name && p.ID == r.ID && validGUID(p.Boot) && (r.Boot == "" || r.Boot == p.Boot)
}

func decodeBounded(reader io.Reader, value any) error {
	data, err := io.ReadAll(io.LimitReader(reader, 65537))
	if err != nil || len(data) > 65536 {
		return errors.New("bounded lab response unavailable")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid lab response")
	}
	return nil
}

func listed(data []byte) ([]string, error) {
	var reply struct {
		Items []struct {
			ID string `json:"Id"`
		} `json:"WindowsSandboxEnvironments"`
	}
	if err := decodeBounded(strings.NewReader(string(data)), &reply); err != nil || reply.Items == nil || len(reply.Items) > 64 {
		return nil, errors.New("invalid Sandbox inventory")
	}
	ids := make([]string, 0, len(reply.Items))
	seen := map[string]bool{}
	for _, item := range reply.Items {
		if !validGUID(item.ID) || seen[item.ID] {
			return nil, errors.New("ambiguous Sandbox inventory")
		}
		seen[item.ID] = true
		ids = append(ids, item.ID)
	}
	return ids, nil
}
