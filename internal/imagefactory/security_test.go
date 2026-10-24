package imagefactory

import "testing"

func TestGuestSecurityFacts(t *testing.T) {
	for _, b := range []string{`{}`, `{"secure_boot":false,"tpm_present":true}`, `{"secure_boot":true,"tpm_present":false}`, `{"secure_boot":1,"tpm_present":true}`, `{"secure_boot":true,"tpm_present":true,"tpm_ready":"yes"}`} {
		if _, e := parseGuestSecurity([]byte(b)); e == nil {
			t.Fatal("invalid security report accepted")
		}
	}
	for _, b := range []string{`{"secure_boot":true,"tpm_present":true,"tpm_ready":true}`, `{"secure_boot":true,"tpm_present":true,"tpm_ready":false}`} {
		s, e := parseGuestSecurity([]byte(b))
		if e != nil || !s.SecureBoot || !s.TPMPresent {
			t.Fatal("valid security facts refused")
		}
	}
}

func TestBootGenerationFields(t *testing.T) {
	for _, generation := range []string{"uefi_ca_2023", "pca_2011"} {
		code := uint32(1)
		if generation == "uefi_ca_2023" {
			code = 2
		}
		issuers := BootIssuers{Fallback: code, Microsoft: code, Source: code, SignatureCounts: BootSignatureCounts{Fallback: 1, Microsoft: 1, Source: 1}}
		if !validBootGeneration(generation, issuers) {
			t.Fatal("valid generation refused")
		}
		issuers.Source = 4
		if validBootGeneration(generation, issuers) {
			t.Fatal("mixed source accepted")
		}
		issuers.Source = code
		issuers.SignatureCounts.Source = 0
		if validBootGeneration(generation, issuers) {
			t.Fatal("unsigned source accepted")
		}
		issuers.SignatureCounts.Source = 17
		if validBootGeneration(generation, issuers) {
			t.Fatal("signature bound")
		}
	}
	if validBootGeneration("unknown", BootIssuers{}) {
		t.Fatal("unknown generation")
	}
}

func TestBitLockerDiagnosticDoesNotGate(t *testing.T) {
	for _, b := range []string{`{"secure_boot":true,"tpm_present":true,"tpm_ready":true,"bitlocker_conversion_status":1,"bitlocker_protection_status":1}`, `{"secure_boot":true,"tpm_present":true,"tpm_ready":true,"bitlocker_conversion_status":4294967295,"bitlocker_protection_status":4294967295}`, `{"secure_boot":true,"tpm_present":true,"tpm_ready":true,"bitlocker_conversion_status":"unknown"}`} {
		if _, err := parseGuestSecurity([]byte(b)); err != nil {
			t.Fatal("diagnostic became publication gate")
		}
	}
	s, err := parseGuestSecurity([]byte(`{"secure_boot":true,"tpm_present":true,"tpm_ready":true,"bitlocker_conversion_status":4,"bitlocker_protection_status":2}`))
	if err != nil || s.BitLockerConversionStatus != 4 || s.BitLockerProtectionStatus != 2 {
		t.Fatal("numeric diagnostics not recorded")
	}
}
