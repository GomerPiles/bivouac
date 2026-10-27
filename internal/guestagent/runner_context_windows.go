//go:build windows

package guestagent

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// RunnerContext holds transient native context, never logged or persisted.
type RunnerContext struct {
	UserSID, ExpectedSID           string
	ProcessSession, ConsoleSession uint32
	Elevated                       bool
	Elevation                      uint32
}

func (f RunnerContext) Valid() bool {
	return sessionAllowed(sessionFacts{process: f.ProcessSession, console: f.ConsoleSession, elevation: f.Elevation, elevated: f.Elevated, user: f.UserSID}, f.ExpectedSID)
}

// The published image pins its autologon account. Reading only these public
// machine configuration values avoids any task-definition or descriptor query
// in the trampoline; no delivered configuration or environment identity is used.
func ReadRunnerContext() (RunnerContext, error) {
	f, err := currentSession()
	if err != nil {
		return RunnerContext{}, errors.New("runner context unavailable")
	}
	result := RunnerContext{UserSID: f.user, ProcessSession: f.process, ConsoleSession: f.console, Elevated: f.elevated, Elevation: f.elevation}
	result.ExpectedSID, err = readAutologonSID()
	return result, err
}

func readAutologonSID() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.QUERY_VALUE)
	if err != nil {
		return "", errors.New("runner account unavailable")
	}
	defer func() { _ = key.Close() }()
	user, _, err := key.GetStringValue("DefaultUserName")
	if err != nil || user == "" || len(user) > 256 {
		return "", errors.New("runner account unavailable")
	}
	// Windows setup's own autologon may record no domain; sanitation writes the
	// computer name. Either way the image's account is a local account.
	domain, _, err := key.GetStringValue("DefaultDomainName")
	if errors.Is(err, registry.ErrNotExist) || (err == nil && domain == "") {
		domain, err = windows.ComputerName()
	}
	if err != nil || domain == "" || len(domain) > 256 {
		return "", errors.New("runner account unavailable")
	}
	sid, _, kind, err := windows.LookupSID("", domain+`\`+user)
	if err != nil || kind != windows.SidTypeUser {
		return "", errors.New("runner account unavailable")
	}
	return sid.String(), nil
}
