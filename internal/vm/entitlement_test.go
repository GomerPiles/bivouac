package vm

import "testing"

func TestEntitledReadsTheTopLevelDict(t *testing.T) {
	const head = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`
	cases := map[string]bool{
		head + `<plist version="1.0"><dict><key>com.apple.security.virtualization</key><true/></dict></plist>`:                                                                            true,
		head + "<plist version=\"1.0\">\n<dict>\n\t<key>other</key>\n\t<array><string>x</string></array>\n\t<key>com.apple.security.virtualization</key>\n\t<true/>\n</dict>\n</plist>\n": true,
		head + `<plist version="1.0"><dict><key>com.apple.security.virtualization</key><false/></dict></plist>`:                                                                           false,
		head + `<plist version="1.0"><dict><key>other</key><array><string>com.apple.security.virtualization</string></array></dict></plist>`:                                              false,
		head + `<plist version="1.0"><dict><key>other</key><dict><key>com.apple.security.virtualization</key><true/></dict></dict></plist>`:                                               false,
		``: false,
		`<plist version="1.0"><dict><key>com.apple.security.virtualization</key>`: false,
	}
	for plist, want := range cases {
		if got := entitled([]byte(plist), Entitlement); got != want {
			t.Errorf("%q: got %v", plist, got)
		}
	}
}
