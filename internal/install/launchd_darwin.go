// Package install registers bivouac with the host's service manager so the
// daemon starts at login and the durable mode decides what it does.
package install

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"unicode/utf8"
)

// Label is the LaunchAgent identifier.
const Label = "com.gomerpiles.bivouac"

// plistTemplate escapes every value as XML character data.
var plistTemplate = template.Must(template.New("plist").Funcs(template.FuncMap{"xml": xmlText}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{xml .Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{xml .Binary}}</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>AbandonProcessGroup</key>
	<true/>
	<key>StandardOutPath</key>
	<string>{{xml .Log}}</string>
	<key>StandardErrorPath</key>
	<string>{{xml .Log}}</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
</dict>
</plist>
`))

func xmlText(s string) (string, error) {
	// XML 1.0 cannot represent most control characters, and EscapeText would
	// silently replace them, naming a different path.
	if !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", fmt.Errorf("plist value %q contains characters launchd cannot represent", s)
	}
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return "", err
	}
	return b.String(), nil
}

func renderPlist(binary, logDir string) ([]byte, error) {
	var buf bytes.Buffer
	if err := plistTemplate.Execute(&buf, map[string]string{"Label": Label, "Binary": binary, "Log": filepath.Join(logDir, "launchd.log")}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Paths are the files install touches.
type Paths struct {
	Binary string // absolute path to bivouac
	LogDir string
}

func plistPath() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "Library", "LaunchAgents", Label+".plist"), nil
}

func domain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

// errOtherHome refuses login item changes from a BIVOUAC_HOME layout: the one
// LaunchAgent label always runs the default layout, so acting on it from a
// validation home would start, replace, or remove the default daemon.
var errOtherHome = errors.New("the login item runs the default home only; with BIVOUAC_HOME set, use `bivouac run` in the foreground")

func otherHome() bool { return os.Getenv("BIVOUAC_HOME") != "" }

// Install writes the LaunchAgent and bootstraps it. The daemon reads the
// durable mode and exits at once when it is off, so installing never starts
// accepting jobs by itself.
func Install(ctx context.Context, p Paths) (string, error) {
	if otherHome() {
		return "", errOtherHome
	}
	path, err := plistPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	plist, err := renderPlist(p.Binary, p.LogDir)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, plist, 0o644); err != nil { //nolint:gosec // launchd needs world-readable plists
		return "", err
	}
	_ = launchctl(ctx, "bootout", domain()+"/"+Label)
	if err := launchctl(ctx, "bootstrap", domain(), path); err != nil {
		return path, err
	}
	return path, nil
}

// Uninstall boots the agent out and removes the plist.
func Uninstall(ctx context.Context) error {
	if otherHome() {
		return errOtherHome
	}
	path, err := plistPath()
	if err != nil {
		return err
	}
	_ = launchctl(ctx, "bootout", domain()+"/"+Label)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Kickstart starts the daemon now if it is loaded but not running.
func Kickstart(ctx context.Context) error {
	if otherHome() {
		return errOtherHome
	}
	return launchctl(ctx, "kickstart", domain()+"/"+Label)
}

// Installed reports whether the plist exists and launchd knows the label.
// A BIVOUAC_HOME layout never has a login item.
func Installed(ctx context.Context) (plist string, loaded bool, err error) {
	if otherHome() {
		return "", false, nil
	}
	path, err := plistPath()
	if err != nil {
		return "", false, err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return path, false, nil
		}
		return path, false, err
	}
	return path, launchctl(ctx, "print", domain()+"/"+Label) == nil, nil
}

func launchctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "/bin/launchctl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("launchctl %v: %w: %s", args, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return nil
}
