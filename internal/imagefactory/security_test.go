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
