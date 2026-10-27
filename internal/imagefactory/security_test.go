package imagefactory

import (
	"fmt"
	"testing"
)

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

func TestBitLockerPublicationGate(t *testing.T) {
	const prefix = `{"secure_boot":true,"tpm_present":true,"tpm_ready":true`
	for _, field := range []string{"bitlocker_conversion_status", "bitlocker_protection_status"} {
		for _, value := range []string{"0", "1", "2", "3", "4", "5", "6", "4294967294", "4294967295", `"unknown"`, "null", "-1", "4294967296"} {
			b := []byte(fmt.Sprintf(`%s,%q:%s}`, prefix, field, value))
			_, err := parseGuestSecurity(b)
			bad := value == "1" || value == "2" || value == "3" || value == "4" || value == "5" || value == "6" || value == "4294967294"
			if (err != nil) != bad {
				t.Fatalf("BitLocker gate field=%s fixture=%s", field, value)
			}
		}
	}
	for _, fields := range []string{
		`,"bitlocker_conversion_status":"unknown","bitlocker_protection_status":1`,
		`,"bitlocker_conversion_status":1,"bitlocker_protection_status":"unknown"`,
	} {
		if _, err := parseGuestSecurity([]byte(prefix + fields + "}")); err == nil {
			t.Fatal("unreadable diagnostic hid unsafe status")
		}
	}
	for _, fields := range []string{"", `,"bitlocker_conversion_status":null,"bitlocker_protection_status":"unknown"`, `,"bitlocker_conversion_status":4294967295,"bitlocker_protection_status":4294967295`} {
		s, err := parseGuestSecurity([]byte(prefix + fields + "}"))
		if err != nil || s.BitLockerConversionStatus != ^uint32(0) || s.BitLockerProtectionStatus != ^uint32(0) {
			t.Fatal("unavailable diagnostic changed")
		}
	}
	s, err := parseGuestSecurity([]byte(prefix + `,"bitlocker_conversion_status":0,"bitlocker_protection_status":0}`))
	if err != nil || s.BitLockerConversionStatus != 0 || s.BitLockerProtectionStatus != 0 {
		t.Fatal("fully decrypted report refused")
	}
}
