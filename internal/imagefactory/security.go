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
	// Diagnostics never decide publication, including missing/unreadable values.
	var diagnostic struct {
		Conversion *uint32 `json:"bitlocker_conversion_status"`
		Protection *uint32 `json:"bitlocker_protection_status"`
	}
	if json.Unmarshal(b, &diagnostic) == nil {
		if diagnostic.Conversion != nil && *diagnostic.Conversion <= 5 {
			result.BitLockerConversionStatus = *diagnostic.Conversion
		}
		if diagnostic.Protection != nil && *diagnostic.Protection <= 2 {
			result.BitLockerProtectionStatus = *diagnostic.Protection
		}
	}
	return result, nil
}
