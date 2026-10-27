package imagefactory

import "testing"

func TestDriverRuntimeLogsAreNotCopied(t *testing.T) {
	for path, skip := range map[string]bool{
		"atikmdag_dce_14.log":     true,
		"sub/Trace.LOG":           true,
		"u0203303.inf":            false,
		"atikmdag.sys":            false,
		"HDCPSrmData.txt":         false,
		"logs/driver.log.bak":     false,
		"vulkaninfo64.exe":        false,
		"amdlog.dll":              false,
		"atikmdag_dce_14.log.sys": false,
	} {
		if driverRuntimeLog(path) != skip {
			t.Fatalf("%s: got %v", path, !skip)
		}
	}
}
