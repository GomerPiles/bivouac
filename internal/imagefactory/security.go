package imagefactory

import (
	"encoding/json"
	"errors"
)

type GuestSecurity struct {
	SecureBoot                bool   `json:"secure_boot"`
	TPMPresent                bool   `json:"tpm_present"`
	TPMReady                  bool   `json:"tpm_ready"`
	BitLockerConversionStatus uint32 `json:"bitlocker_conversion_status"`
	BitLockerProtectionStatus uint32 `json:"bitlocker_protection_status"`
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
	result := GuestSecurity{SecureBoot: *fields.SecureBoot, TPMPresent: *fields.TPMPresent, TPMReady: *fields.TPMReady, BitLockerConversionStatus: ^uint32(0), BitLockerProtectionStatus: ^uint32(0)}
	// A reported status must prove fully decrypted/protection off. Missing or
	// unreadable fields stay diagnostic, independently of the other field.
	var diagnostic map[string]json.RawMessage
	if json.Unmarshal(b, &diagnostic) != nil {
		return GuestSecurity{}, errors.New("invalid guest security diagnostic report")
	}
	for field, target := range map[string]*uint32{
		"bitlocker_conversion_status": &result.BitLockerConversionStatus,
		"bitlocker_protection_status": &result.BitLockerProtectionStatus,
	} {
		var value *uint32
		if json.Unmarshal(diagnostic[field], &value) != nil || value == nil {
			continue
		}
		*target = *value
		if *value != 0 && *value != ^uint32(0) {
			return GuestSecurity{}, errors.New("guest BitLocker status requires fully decrypted storage and protection off")
		}
	}
	return result, nil
}
