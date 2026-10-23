package imagefactory

import (
	"encoding/json"
	"errors"
)

type GuestSecurity struct {
	SecureBoot bool `json:"secure_boot"`
	TPMPresent bool `json:"tpm_present"`
	TPMReady   bool `json:"tpm_ready"`
}

func parseGuestSecurity(b []byte) (GuestSecurity, error) {
	var fields struct {
		SecureBoot *bool `json:"secure_boot"`
		TPMPresent *bool `json:"tpm_present"`
		TPMReady   *bool `json:"tpm_ready"`
	}
	if json.Unmarshal(b, &fields) != nil || fields.SecureBoot == nil || fields.TPMPresent == nil || fields.TPMReady == nil || !*fields.SecureBoot || !*fields.TPMPresent {
		return GuestSecurity{}, errors.New("guest requires effective Secure Boot and a present TPM with readiness reported")
	}
	return GuestSecurity{*fields.SecureBoot, *fields.TPMPresent, *fields.TPMReady}, nil
}
