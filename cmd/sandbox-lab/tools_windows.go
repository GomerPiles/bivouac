//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/wintools"
)

const guestToolsDirectory = `C:\Program Files\Bivouac\Tools`

type toolFact struct {
	Variant   string `json:"variant,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	InstallMS int64  `json:"install_ms"`
	Verified  bool   `json:"verified"`
	CacheHit  bool   `json:"cache_hit"`
}

type toolFacts struct {
	Identity labRecord  `json:"identity"`
	Tools    []toolFact `json:"tools"`
	Build    bool       `json:"build"`
}

func (f toolFacts) valid(record labRecord, recipes []wintools.Recipe) bool {
	_, _, build := toolBuildRecipes(recipes)
	if !sameGuest(f.Identity, record) || len(f.Tools) != len(recipes) || f.Build != build {
		return false
	}
	for i, recipe := range recipes {
		fact := f.Tools[i]
		if fact.Name != recipe.Name || fact.Version != recipe.Version || fact.SHA256 != recipe.SHA256 || fact.Variant != recipe.Variant || !fact.Verified || fact.InstallMS < 0 || fact.InstallMS > 120000 {
			return false
		}
	}
	return true
}

func toolBuildRecipes(recipes []wintools.Recipe) (cmake, ninja wintools.Recipe, ok bool) {
	for _, recipe := range recipes {
		switch recipe.Name {
		case "cmake":
			cmake = recipe
		case "ninja":
			ninja = recipe
		}
	}
	return cmake, ninja, cmake.Name != "" && ninja.Name != ""
}

func guestToolPlan() ([]wintools.Recipe, error) {
	var names []string
	if readJSON(filepath.Join(bootstrapDirectory, "tools.json"), &names) != nil || names == nil {
		return nil, errors.New("guest tool selection unavailable")
	}
	return wintools.Resolve(names)
}

func toolExecutable(recipe wintools.Recipe) string {
	return filepath.Join(guestToolsDirectory, recipe.Name, filepath.FromSlash(recipe.Executable))
}

func toolCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	step, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(step, binary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.WaitDelay = 2 * time.Second
	var output boundedBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if cmd.Run() != nil {
		return nil, errors.New("guest tool command failed")
	}
	return output.data, nil
}

func prepareGuestTools(ctx context.Context) error {
	if !session().valid() {
		return errors.New("guest tool context refused")
	}
	var record labRecord
	if readJSON(filepath.Join(guestLabDirectory, "identity.json"), &record) != nil || !record.valid() || !validGUID(record.Boot) {
		return errors.New("guest tool identity unavailable")
	}
	recipes, err := guestToolPlan()
	if err != nil {
		return err
	}
	facts := toolFacts{Identity: record, Tools: []toolFact{}}
	if len(recipes) > 0 {
		if os.Mkdir(guestToolsDirectory, 0o700) != nil {
			return errors.New("fresh guest tool root required")
		}
	}
	for _, recipe := range recipes {
		started := time.Now()
		root := filepath.Join(guestToolsDirectory, recipe.Name)
		if os.Mkdir(root, 0o700) != nil {
			return errors.New("fresh guest tool directory required")
		}
		if err := wintools.Extract(filepath.Join(bootstrapDirectory, recipe.Name+".zip"), root, recipe); err != nil {
			return err
		}
		output, err := toolCommand(ctx, toolExecutable(recipe), "--version")
		if err != nil || strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0]) != recipe.VersionOutput {
			return errors.New("guest tool version unproven")
		}
		if recipe.Name == "pwsh" {
			output, err := toolCommand(ctx, toolExecutable(recipe), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "[Console]::Out.Write('bivouac-tool-probe')")
			if err != nil || string(output) != "bivouac-tool-probe" {
				return errors.New("guest PowerShell execution unproven")
			}
		}
		if recipe.Name == "git" {
			repository := filepath.Join(guestLabDirectory, "tool-git")
			if _, err := toolCommand(ctx, toolExecutable(recipe), "init", "--bare", "--initial-branch=main", repository); err != nil {
				return errors.New("guest Git initialization unproven")
			}
			output, err := toolCommand(ctx, toolExecutable(recipe), "--git-dir", repository, "rev-parse", "--is-bare-repository")
			if err != nil || strings.TrimSpace(string(output)) != "true" {
				return errors.New("guest Git repository unproven")
			}
		}
		facts.Tools = append(facts.Tools, toolFact{Name: recipe.Name, Version: recipe.Version, SHA256: recipe.SHA256, Variant: recipe.Variant, InstallMS: time.Since(started).Milliseconds(), Verified: true})
	}
	if cmake, ninja, ok := toolBuildRecipes(recipes); ok {
		// A real offline configure/build verifies that both executables work
		// together. This project intentionally requires no compiler or SDK.
		project := filepath.Join(guestLabDirectory, "tool-project")
		if os.Mkdir(project, 0o700) != nil {
			return errors.New("fresh tool build directory required")
		}
		const source = "cmake_minimum_required(VERSION 3.20)\nproject(SandboxTools NONE)\nadd_custom_target(proof ALL COMMAND \"${CMAKE_COMMAND}\" -E touch \"${CMAKE_BINARY_DIR}/tool-proof\" VERBATIM)\n"
		if os.WriteFile(filepath.Join(project, "CMakeLists.txt"), []byte(source), 0o600) != nil {
			return errors.New("tool project unavailable")
		}
		build := filepath.Join(project, "build")
		if _, err := toolCommand(ctx, toolExecutable(cmake), "-S", project, "-B", build, "-G", "Ninja", "-DCMAKE_MAKE_PROGRAM="+toolExecutable(ninja)); err != nil {
			return err
		}
		if _, err := toolCommand(ctx, toolExecutable(cmake), "--build", build, "--parallel", "1"); err != nil {
			return err
		}
		info, err := os.Stat(filepath.Join(build, "tool-proof"))
		if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
			return errors.New("tool build result unproven")
		}
		facts.Build = true
	}
	if err := writeJSON(filepath.Join(guestLabDirectory, "tools.json"), facts); err != nil {
		return err
	}
	return writeReport("tools.json", facts)
}

// Each fresh agent process (including a restart) inherits the same reviewed
// tool paths. This never writes host or guest machine/user PATH settings.
func guestToolEnvironment() error {
	recipes, err := guestToolPlan()
	if err != nil || len(recipes) == 0 {
		return err
	}
	if !session().valid() {
		return errors.New("guest tool environment context refused")
	}
	var record labRecord
	var facts toolFacts
	if readJSON(filepath.Join(guestLabDirectory, "identity.json"), &record) != nil || readJSON(filepath.Join(guestLabDirectory, "tools.json"), &facts) != nil || !facts.valid(record, recipes) {
		return errors.New("prepared guest tools unproven")
	}
	paths := []string{}
	for _, recipe := range recipes {
		paths = append(paths, filepath.Dir(toolExecutable(recipe)))
	}
	paths = append(paths, os.Getenv("PATH"))
	if os.Setenv("PATH", strings.Join(paths, string(os.PathListSeparator))) != nil {
		return errors.New("guest tool environment unavailable")
	}
	for _, recipe := range recipes {
		located, err := exec.LookPath(recipe.Name + ".exe")
		if err != nil || !strings.EqualFold(located, toolExecutable(recipe)) {
			return errors.New("guest tool PATH differs")
		}
	}
	return writeReport("tool-environment.json", facts)
}

// toolCheck does not alter PATH: this child must inherit it from the agent.
func toolCheck(ctx context.Context, out io.Writer) error {
	if !session().valid() {
		return errors.New("guest tool check context refused")
	}
	recipes, err := guestToolPlan()
	if err != nil {
		return err
	}
	var record labRecord
	var facts toolFacts
	if readJSON(filepath.Join(guestLabDirectory, "identity.json"), &record) != nil || readJSON(filepath.Join(guestLabDirectory, "tools.json"), &facts) != nil || !facts.valid(record, recipes) {
		return errors.New("guest tool check preparation refused")
	}
	for _, recipe := range recipes {
		located, err := exec.LookPath(recipe.Name + ".exe")
		if err != nil || !strings.EqualFold(located, toolExecutable(recipe)) {
			return errors.New("runner child did not inherit tool PATH")
		}
		output, err := toolCommand(ctx, recipe.Name+".exe", "--version")
		if err != nil || strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0]) != recipe.VersionOutput {
			return errors.New("runner child tool execution unproven")
		}
	}
	return json.NewEncoder(out).Encode(facts)
}

func (h *labHost) nativeToolCheck(ctx context.Context) error {
	data, err := h.nativeRun(ctx, "tool-check", nil)
	if err != nil {
		return errors.New("native tool check failed")
	}
	var facts toolFacts
	var names []string
	if readJSON(filepath.Join(h.input, "tools.json"), &names) != nil {
		return errors.New("recorded tool plan unavailable")
	}
	recipes, err := wintools.Resolve(names)
	if err != nil || decodeBounded(strings.NewReader(string(data)), &facts) != nil || !facts.valid(h.record, recipes) {
		return errors.New("native runner-child tool environment unproven")
	}
	return nil
}
