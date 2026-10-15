//go:build windows

package install

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestTaskOwnershipRejectsChangedExecution(t *testing.T) {
	r := taskRecord{Name: "Bivouac-test", SID: "S-1-5-21-123", Home: `C:\isolated home\`}
	definition, err := taskXML(r, `C:\tools & tests\bivouac.exe`)
	if err != nil {
		t.Fatal(err)
	}
	var d taskDefinition
	if err = xml.Unmarshal([]byte(definition), &d); err != nil {
		t.Fatal(err)
	}
	if d.Actions[0].Command != `C:\tools & tests\bivouac.exe` || d.Actions[0].Arguments != `login-run "C:\isolated home\\"` {
		t.Fatalf("arguments or XML escaping lost: %+v", d.Actions)
	}
	if !sameTask(definition, definition) {
		t.Fatal("own task rejected")
	}
	for _, change := range [][2]string{
		{"LeastPrivilege", "HighestAvailable"},
		{"InteractiveToken", "Password"},
		{"S-1-5-21-123", "S-1-5-18"},
		{"login-run", "run"},
		{"PT0S", "PT72H"},
		{"IgnoreNew", "StopExisting"},
		{`Context="manager"`, `Context="other"`},
		{"<Enabled>true</Enabled>", "<Enabled>false</Enabled>"},
		{"</Actions>", "<ComHandler><ClassId>foreign</ClassId></ComHandler></Actions>"},
		{"</Triggers>", "<BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>"},
		{"</Principals>", "<Principal><UserId>S-1-5-18</UserId></Principal></Principals>"},
	} {
		if sameTask(definition, strings.Replace(definition, change[0], change[1], 1)) {
			t.Errorf("accepted changed definition: %v", change)
		}
	}
}

func TestPendingTaskUpdateRetainsBothDefinitions(t *testing.T) {
	r := taskRecord{Name: "Bivouac-test", SID: "S-1-5-21-123"}
	var err error
	r.XML, err = taskXML(r, `C:\old\bivouac.exe`)
	if err != nil {
		t.Fatal(err)
	}
	r.PendingXML, err = taskXML(r, `C:\new\bivouac.exe`)
	if err != nil {
		t.Fatal(err)
	}
	if !recordMatches(r, r.XML) || !recordMatches(r, r.PendingXML) {
		t.Fatal("interrupted update cannot be recovered")
	}
	if recordMatches(r, strings.Replace(r.PendingXML, "LeastPrivilege", "HighestAvailable", 1)) {
		t.Fatal("accepted foreign elevated task")
	}
}

func TestTaskSchedulerNormalization(t *testing.T) {
	r := taskRecord{Name: "Bivouac-test", SID: "S-1-5-21-123"}
	definition, err := taskXML(r, `C:\portable\bivouac.exe`)
	if err != nil {
		t.Fatal(err)
	}
	native := `<?xml version="1.0" encoding="UTF-16"?>` + definition
	for _, field := range []string{"<RunLevel>LeastPrivilege</RunLevel>", "<Enabled>true</Enabled>", "<AllowStartOnDemand>true</AllowStartOnDemand>"} {
		native = strings.ReplaceAll(native, field, "")
	}
	if !sameTask(definition, native) {
		t.Fatal("native defaults or already-decoded COM XML rejected")
	}
}
