package linuxguest

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strconv"
	"strings"
)

// ProvisionRequest is the guest-root image recipe contract. A future host
// builder can send this same request to the static helper in its build guest.
// It supplies no commands, units, user names, destinations or privilege policy.
type ProvisionRequest struct {
	Recipe        string `json:"recipe"`
	RunnerArchive string `json:"runner_archive"`
	RunnerSHA256  string `json:"runner_sha256"`
}

type provisionRecipe struct {
	name, distro, version, arch string
	profile                     ExecutionProfile
	packages                    []string
}

// Return a fresh registry, not mutable process-wide recipe state. Exactly one
// supported layout today; another image type/distro adds an explicit recipe.
func provisionRecipes() []provisionRecipe {
	return []provisionRecipe{{
		name: "ubuntu-24.04-arm64-vz-runner", distro: "ubuntu", version: "24.04", arch: "arm64", profile: VZ,
		packages: []string{"ca-certificates", "curl", "git", "sudo", "python3", "build-essential", "docker.io", "netplan.io", "systemd-resolved"},
	}}
}

func decodeProvisionRequest(input io.Reader) (ProvisionRequest, error) {
	var request ProvisionRequest
	data, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(data) > 4096 {
		return request, errors.New("provision request exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF ||
		!digest(request.RunnerSHA256) || request.RunnerSHA256 != strings.ToLower(request.RunnerSHA256) ||
		len(request.RunnerArchive) > 1024 || request.RunnerArchive == "/" || !path.IsAbs(request.RunnerArchive) || path.Clean(request.RunnerArchive) != request.RunnerArchive || strings.ContainsAny(request.RunnerArchive, "\x00\r\n\\") {
		return request, errors.New("invalid bounded provision request")
	}
	if _, err := selectProvisionRecipe(request.Recipe, "linux", "arm64", 0, "ubuntu", "24.04"); err != nil {
		return request, err
	}
	return request, nil
}

func selectProvisionRecipe(name, osName, arch string, uid int, distro, version string) (provisionRecipe, error) {
	for _, r := range provisionRecipes() {
		if r.name == name && osName == "linux" && arch == r.arch && uid == 0 && distro == r.distro && version == r.version {
			return r, nil
		}
	}
	return provisionRecipe{}, errors.New("provisioning requires the selected Ubuntu ARM64 layout and guest root")
}

// os-release is data, never sourced by a shell. Only the two recipe selectors
// are consumed, with duplicates and unknown quoting refused.
func provisionDistro(data []byte) (string, string, error) {
	if len(data) > 16384 {
		return "", "", errors.New("OS release exceeds bound")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || key != "ID" && key != "VERSION_ID" {
			continue
		}
		if _, exists := values[key]; exists {
			return "", "", errors.New("ambiguous OS release")
		}
		if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) && len(value) >= 2 {
			value = value[1 : len(value)-1]
		}
		if strings.ContainsAny(value, "\"'\\ \t\r\x00") {
			return "", "", errors.New("unknown OS release layout")
		}
		for _, c := range value {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789._-", c) {
				return "", "", errors.New("unknown OS release selector")
			}
		}
		values[key] = value
	}
	return values["ID"], values["VERSION_ID"], nil
}

func validateProvisionHelper(data []byte) error {
	if len(data) > 128<<20 {
		return errors.New("provision helper exceeds bound")
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("provision helper is not ELF")
	}
	defer func() { _ = f.Close() }()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_AARCH64 || f.Type != elf.ET_EXEC {
		return errors.New("provision helper must be static Linux ARM64")
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
			return errors.New("provision helper requires a dynamic loader")
		}
	}
	return nil
}

const provisionNetwork = `network:
  version: 2
  renderer: networkd
  ethernets:
    bivouac-uplink:
      match:
        driver: virtio_net
      dhcp4: true
      dhcp4-overrides:
        use-dns: true
        use-mtu: true
      dhcp6: false
      accept-ra: false
      link-local: []
      optional: true
`
const provisionAgentDropin = `[Unit]
After=docker.service
Wants=docker.service

[Service]
User=bivouac
Group=bivouac
Environment=HOME=/home/bivouac
`

type provisionAccount struct {
	uid, gid int
	home     string
}

func provisionAccounts(data []byte) (map[string]provisionAccount, error) {
	result := map[string]provisionAccount{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return nil, errors.New("unknown account layout")
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid < 0 {
			return nil, errors.New("invalid account UID")
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil || gid < 0 {
			return nil, errors.New("invalid account GID")
		}
		name := fields[0]
		expectedHome := "/home/" + name
		if name == "root" {
			expectedHome = "/root"
		}
		known := name == "root" || name == "admin" || name == "ubuntu" || name == "bivouac"
		if !known {
			if uid == 0 || uid >= 1000 && uid != 65534 {
				return nil, errors.New("unknown preparation account")
			}
			continue
		}
		if fields[5] != expectedHome || name == "root" && uid != 0 || name != "root" && uid == 0 {
			return nil, errors.New("preparation account differs")
		}
		if _, duplicate := result[name]; duplicate {
			return nil, errors.New("duplicate preparation account")
		}
		result[name] = provisionAccount{uid: uid, gid: gid, home: fields[5]}
	}
	if _, exists := result["root"]; !exists {
		return nil, errors.New("root account missing")
	}
	return result, nil
}
