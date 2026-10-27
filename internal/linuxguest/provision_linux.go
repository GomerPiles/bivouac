//go:build linux

package linuxguest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/command"
	linuxassets "github.com/GomerPiles/bivouac/tools/linux"
)

const provisionStage = "/usr/local/libexec/bivouac-provision/bivouac-guest"

type provisionCommands interface {
	Input(context.Context, string, []string, []byte) ([]byte, error)
}

type provisioner struct {
	root     *os.Root
	commands provisionCommands
	ownerUID uint32
}

func provisionLinux(ctx context.Context, input io.Reader, out io.Writer) (result error) {
	// Never include paths, input, subprocess output or environment in errors.
	defer func() {
		if result != nil {
			result = errors.New("linux guest provisioning refused; inspect or replace the disposable preparation image")
		}
	}()
	request, err := decodeProvisionRequest(input)
	if err != nil {
		return err
	}
	var host syscall.Utsname
	if err := syscall.Uname(&host); err != nil {
		return err
	}
	var machine strings.Builder
	for _, c := range host.Machine {
		if c == 0 {
			break
		}
		machine.WriteRune(rune(c))
	}
	if runtime.GOARCH != "arm64" || machine.String() != "aarch64" || os.Geteuid() != 0 {
		return errors.New("provisioning requires ARM64 guest root")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	p := provisioner{root: root, commands: command.Native{}, ownerUID: 0}
	// /proc/self/exe pins the executing inode, independent of the staged filename.
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer func() { _ = self.Close() }()
	info, err := self.Stat()
	if err != nil || !p.protected(info) {
		return errors.New("unprotected provisioning executable")
	}
	helper, err := io.ReadAll(io.LimitReader(self, 128<<20+1))
	if err != nil || validateProvisionHelper(helper) != nil {
		return errors.New("invalid static helper")
	}
	report, err := p.provision(ctx, request, helper)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}

func (p provisioner) run(ctx context.Context, binary string, args []string, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	output, err := p.commands.Input(ctx, binary, args, input)
	if err != nil || len(output) > 1<<20 {
		return nil, errors.New("fixed provisioning command failed")
	}
	return output, nil
}
func (p provisioner) protected(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == p.ownerUID && info.Mode()&0022 == 0 && info.Mode()&os.ModeSymlink == 0
}

// All install parents are ordinary protected directories. os.Root also confines
// operations to the selected filesystem in tests and to the guest in production.
func (p provisioner) directory(name string) error {
	for _, prefix := range provisionParents(name) {
		info, err := p.root.Lstat(prefix)
		if errors.Is(err, fs.ErrNotExist) {
			if err := p.root.Mkdir(prefix, 0755); err != nil {
				return err
			}
			if err := p.root.Chmod(prefix, 0755); err != nil {
				return err
			}
			info, err = p.root.Lstat(prefix)
		}
		if err != nil || !info.IsDir() || !p.protected(info) {
			return errors.New("unprotected recipe directory")
		}
	}
	return nil
}
func provisionParents(name string) []string {
	result := []string{"."}
	if name == "." {
		return result
	}
	prefix := ""
	for _, component := range strings.Split(name, "/") {
		prefix = path.Join(prefix, component)
		result = append(result, prefix)
	}
	return result
}
func (p provisioner) install(name string, data []byte, mode fs.FileMode) error {
	if err := p.directory(path.Dir(name)); err != nil {
		return err
	}
	f, err := p.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
func (p provisioner) read(name string, bound int64) ([]byte, error) {
	f, err := p.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, bound+1))
	if err != nil || int64(len(data)) > bound {
		return nil, errors.New("recipe file exceeds bound")
	}
	return data, nil
}

func (p provisioner) provision(ctx context.Context, request ProvisionRequest, helper []byte) (PreparedLinuxImage, error) {
	var empty PreparedLinuxImage
	release, err := p.read("etc/os-release", 16384)
	if err != nil {
		return empty, err
	}
	distro, version, err := provisionDistro(release)
	if err != nil {
		return empty, err
	}
	recipe, err := selectProvisionRecipe(request.Recipe, "linux", "arm64", 0, distro, version)
	if err != nil {
		return empty, err
	}
	if err := p.preflight(); err != nil {
		return empty, err
	}
	// Hold the archive open from pinning through extraction. Only protected
	// ordinary operator-staged files are accepted, never a symlink or device.
	archiveName := strings.TrimPrefix(request.RunnerArchive, "/")
	info, err := p.root.Lstat(archiveName)
	if err != nil || !info.Mode().IsRegular() || !p.protected(info) {
		return empty, errors.New("unprotected runner archive")
	}
	archive, err := p.root.OpenFile(archiveName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	defer func() { _ = archive.Close() }()
	opened, err := archive.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || !p.protected(opened) {
		return empty, errors.New("runner archive identity changed")
	}
	entries, err := planProvisionArchive(archive, request.RunnerSHA256)
	if err != nil {
		return empty, err
	}
	// Validate known network/account layouts before package or image mutations.
	if err := p.networkDevice(); err != nil {
		return empty, err
	}
	_, err = p.networkFiles()
	if err != nil {
		return empty, err
	}
	if _, err := p.accounts(); err != nil {
		return empty, err
	}
	for _, args := range [][]string{{"DEBIAN_FRONTEND=noninteractive", "/usr/bin/apt-get", "update"}, append([]string{"DEBIAN_FRONTEND=noninteractive", "/usr/bin/apt-get", "install", "-y"}, recipe.packages...)} {
		if _, err := p.run(ctx, "/usr/bin/env", args, nil); err != nil {
			return empty, err
		}
	}
	accounts, err := p.accounts()
	if err != nil {
		return empty, err
	}
	if _, exists := accounts["bivouac"]; !exists {
		if _, err := p.run(ctx, "/usr/sbin/useradd", []string{"--create-home", "--user-group", "--shell", "/bin/bash", "bivouac"}, nil); err != nil {
			return empty, err
		}
	}
	accounts, err = p.accounts()
	if err != nil {
		return empty, err
	}
	user, exists := accounts["bivouac"]
	if !exists {
		return empty, errors.New("runner user was not created")
	}
	group, err := p.run(ctx, "/usr/bin/id", []string{"--group", "--name", "bivouac"}, nil)
	if err != nil || strings.TrimSpace(string(group)) != "bivouac" {
		return empty, errors.New("runner primary group differs")
	}
	if _, err := p.run(ctx, "/usr/sbin/usermod", []string{"--append", "--groups", "docker", "bivouac"}, nil); err != nil {
		return empty, err
	}
	if _, err := p.run(ctx, "/usr/bin/systemctl", []string{"enable", "--now", "docker.service"}, nil); err != nil {
		return empty, err
	}
	for _, query := range [][]string{{"ps", "--all", "--quiet"}, {"image", "ls", "--quiet"}, {"volume", "ls", "--quiet"}} {
		output, err := p.run(ctx, "/usr/bin/docker", query, nil)
		if err != nil || len(bytes.TrimSpace(output)) != 0 {
			return empty, errors.New("baseline contains Docker job state")
		}
	}
	if err := p.extract(archive, entries); err != nil {
		return empty, err
	}
	if _, err := p.run(ctx, "/usr/bin/env", []string{"DEBIAN_FRONTEND=noninteractive", "/opt/actions-runner/bin/installdependencies.sh"}, nil); err != nil {
		return empty, err
	}
	if err := p.chownRunner(user.uid, user.gid); err != nil {
		return empty, err
	}
	for _, file := range []struct {
		name string
		data []byte
		mode fs.FileMode
	}{
		{"usr/local/bin/bivouac", helper, 0755},
		{"etc/systemd/system/bivouac-guest-agent.service", linuxassets.GuestAgentUnit(), 0644},
		{"etc/systemd/system/bivouac-guest-agent.service.d/runner.conf", []byte(provisionAgentDropin), 0644},
		{strings.TrimPrefix(provisionStage, "/"), helper, 0755},
	} {
		if err := p.install(file.name, file.data, file.mode); err != nil {
			return empty, err
		}
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "bivouac-guest-agent.service"}} {
		if _, err := p.run(ctx, "/usr/bin/systemctl", args, nil); err != nil {
			return empty, err
		}
	}
	if err := p.sanitize(ctx, accounts); err != nil {
		return empty, err
	}
	if err := p.configureNetwork(ctx); err != nil {
		return empty, err
	}
	report, err := p.imageFactory(ctx, recipe.profile, helper)
	if err != nil {
		return empty, err
	}
	if err := p.root.Remove(strings.TrimPrefix(provisionStage, "/")); err != nil {
		return empty, err
	}
	if err := p.root.Remove(path.Dir(strings.TrimPrefix(provisionStage, "/"))); err != nil {
		return empty, err
	}
	return report, nil
}

func (p provisioner) preflight() error {
	for _, name := range []string{"opt/actions-runner", "tmp/bivouac-runner", "usr/local/bin/bivouac", "usr/local/libexec/bivouac-guest", "usr/local/libexec/bivouac-provision", "etc/bivouac/prepared-image.json", "etc/systemd/system/bivouac-guest-agent.service", "etc/systemd/system/bivouac-guest-agent.service.d"} {
		if _, err := p.root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return errors.New("recipe requires a fresh unprepared image")
		}
	}
	return nil
}

func (p provisioner) imageFactory(ctx context.Context, profile ExecutionProfile, helper []byte) (PreparedLinuxImage, error) {
	want := GuestConfig{Profile: profile, Name: "bivouac-image-build", ControllerID: "image-factory", RunnerDir: "/opt/actions-runner"}
	request, _ := json.Marshal(want)
	output, err := p.run(ctx, "/usr/sbin/runuser", []string{"-u", "bivouac", "--", provisionStage, "guest", "linux", "prepare"}, request)
	if err != nil {
		return PreparedLinuxImage{}, err
	}
	prepared, err := DecodeGuestPreparation(output, want, false)
	if err != nil {
		return PreparedLinuxImage{}, err
	}
	hash := sha256.Sum256(helper)
	digest := hex.EncodeToString(hash[:])
	request, _ = json.Marshal(ImagePreparationRequest{Profile: profile, Name: want.Name, ControllerID: want.ControllerID, BootID: prepared.Config.BootID, HelperSHA256: digest})
	// Root executes only the protected staged helper, never the runner-owned copy.
	output, err = p.run(ctx, provisionStage, []string{"guest", "linux", "prepare-image"}, request)
	if err != nil {
		return PreparedLinuxImage{}, err
	}
	return DecodePreparedImage(output, profile, digest)
}

func (p provisioner) extract(source io.ReadSeeker, entries []provisionEntry) error {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	compressed, err := gzip.NewReader(source)
	if err != nil {
		return err
	}
	defer func() { _ = compressed.Close() }()
	if err := p.directory("opt"); err != nil {
		return err
	}
	if err := p.root.Mkdir("opt/actions-runner", 0755); err != nil {
		return err
	}
	runner, err := p.root.OpenRoot("opt/actions-runner")
	if err != nil {
		return err
	}
	defer func() { _ = runner.Close() }()
	reader := tar.NewReader(compressed)
	for _, expected := range entries {
		header, err := reader.Next()
		if err != nil {
			return err
		}
		entry, err := provisionArchiveEntry(header)
		if err != nil || entry != expected {
			return errors.New("runner archive changed during preparation")
		}
		directory := path.Dir(entry.name)
		if entry.kind == tar.TypeDir {
			directory = entry.name
		}
		for _, prefix := range provisionParents(directory) {
			info, err := runner.Lstat(prefix)
			if errors.Is(err, fs.ErrNotExist) {
				if err = runner.Mkdir(prefix, 0755); err != nil {
					return err
				}
				info, err = runner.Lstat(prefix)
			}
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("runner archive linked parent")
			}
		}
		if entry.kind != tar.TypeReg {
			continue
		} // All links are installed last.
		file, err := runner.OpenFile(entry.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, entry.mode)
		if err != nil {
			return err
		}
		_, err = io.CopyN(file, reader, entry.size)
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		return errors.New("runner archive gained entries")
	}
	for _, entry := range entries {
		switch entry.kind {
		case tar.TypeLink:
			err = runner.Link(entry.link, entry.name)
		case tar.TypeSymlink:
			// The validated normalized target is relative to the archive root. Convert
			// it back to a relative link from this entry's parent without guessing.
			err = runner.Symlink(relativeProvisionLink(entry.name, entry.link), entry.name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func relativeProvisionLink(name, target string) string {
	parents := strings.Split(path.Dir(name), "/")
	if path.Dir(name) == "." {
		return target
	}
	return strings.Repeat("../", len(parents)) + target
}
func (p provisioner) chownRunner(uid, gid int) error {
	return fs.WalkDir(p.root.FS(), "opt/actions-runner", func(name string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return p.root.Lchown(name, uid, gid)
	})
}

func (p provisioner) accounts() (map[string]provisionAccount, error) {
	data, err := p.read("etc/passwd", 1<<20)
	if err != nil {
		return nil, err
	}
	return provisionAccounts(data)
}

// Match the recipe's one virtio NIC before generating a wildcard netplan rule.
func (p provisioner) networkDevice() error {
	directory, err := p.root.Open("sys/class/net")
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	entries, err := directory.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) != 2 {
		return errors.New("recipe requires loopback and one virtio NIC")
	}
	found := false
	for _, entry := range entries {
		if entry.Name() == "lo" {
			continue
		}
		driver, err := p.root.Readlink("sys/class/net/" + entry.Name() + "/device/driver")
		if err != nil || path.Base(driver) != "virtio_net" || found {
			return errors.New("unknown recipe network device")
		}
		found = true
	}
	if !found {
		return errors.New("virtio NIC missing")
	}
	return nil
}
func (p provisioner) networkFiles() ([]string, error) {
	for _, prefix := range provisionParents("etc/netplan") {
		info, err := p.root.Lstat(prefix)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil || !info.IsDir() || !p.protected(info) {
			return nil, errors.New("unprotected netplan directory")
		}
	}
	dir, err := p.root.Open("etc/netplan")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(33)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 32 {
		return nil, errors.New("unknown netplan layout")
	}
	files := []string{}
	for _, entry := range entries {
		if entry.Name() != "50-cloud-init.yaml" && entry.Name() != "00-installer-config.yaml" {
			return nil, errors.New("unknown netplan layout")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || !p.protected(info) {
			return nil, errors.New("unprotected netplan layout")
		}
		files = append(files, "etc/netplan/"+entry.Name())
	}
	sort.Strings(files)
	return files, nil
}
func (p provisioner) configureNetwork(ctx context.Context) error {
	// Recheck after apt/cloud-init cleanup; only recognized installer files may
	// remain. An unknown or substituted file must never be erased.
	files, err := p.networkFiles()
	if err != nil {
		return err
	}
	for _, name := range files {
		if err := p.root.Remove(name); err != nil {
			return err
		}
	}
	if err := p.install("etc/netplan/99-bivouac.yaml", []byte(provisionNetwork), 0600); err != nil {
		return err
	}
	for _, cmd := range []struct {
		binary string
		args   []string
	}{
		{"/usr/sbin/netplan", []string{"generate"}},
		{"/usr/bin/systemctl", []string{"enable", "systemd-networkd.service", "systemd-resolved.service"}},
	} {
		if _, err := p.run(ctx, cmd.binary, cmd.args, nil); err != nil {
			return err
		}
	}
	info, err := p.root.Lstat("etc/resolv.conf")
	if err == nil {
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return errors.New("unknown resolver layout")
		}
		if err := p.root.Remove("etc/resolv.conf"); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return p.root.Symlink("/run/systemd/resolve/stub-resolv.conf", "etc/resolv.conf")
}
func (p provisioner) sanitize(ctx context.Context, accounts map[string]provisionAccount) error {
	// Do not stop the preparation session; disable its transport for cold clones.
	for _, unit := range []string{"ssh.service", "ssh.socket"} {
		output, err := p.run(ctx, "/usr/bin/systemctl", []string{"show", "--property=LoadState", "--value", unit}, nil)
		if err != nil {
			return err
		}
		switch strings.TrimSpace(string(output)) {
		case "loaded":
			if _, err := p.run(ctx, "/usr/bin/systemctl", []string{"disable", unit}, nil); err != nil {
				return err
			}
		case "not-found", "masked":
		default:
			return errors.New("unknown SSH unit layout")
		}
	}
	for _, name := range []string{"root", "admin", "ubuntu", "bivouac"} {
		account, exists := accounts[name]
		if !exists {
			continue
		}
		if _, err := p.run(ctx, "/usr/bin/passwd", []string{"--lock", name}, nil); err != nil {
			return err
		}
		home := strings.TrimPrefix(account.home, "/")
		for _, suffix := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2", ".bash_history", ".python_history", ".zsh_history"} {
			if err := p.removePreparationFile(home + "/" + suffix); err != nil {
				return err
			}
		}
	}
	for _, algorithm := range []string{"rsa", "ecdsa", "ed25519"} {
		for _, suffix := range []string{"", ".pub"} {
			if err := p.removePreparationFile("etc/ssh/ssh_host_" + algorithm + "_key" + suffix); err != nil {
				return err
			}
		}
	}
	if _, err := p.root.Lstat("usr/bin/cloud-init"); err == nil {
		for _, args := range [][]string{{"status", "--wait"}, {"clean", "--logs", "--seed"}} {
			if _, err := p.run(ctx, "/usr/bin/cloud-init", args, nil); err != nil {
				return err
			}
		}
		if err := p.install("etc/cloud/cloud-init.disabled", nil, 0600); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_, err := p.run(ctx, "/usr/bin/apt-get", []string{"clean"}, nil)
	return err
}
func (p provisioner) removePreparationFile(name string) error {
	// Parent links could redirect a cleanup into another part of the image.
	for _, prefix := range provisionParents(path.Dir(name)) {
		info, err := p.root.Lstat(prefix)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("linked preparation home")
		}
	}
	info, err := p.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return errors.New("unknown preparation artifact")
	}
	return p.root.Remove(name)
}
