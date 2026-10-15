package appsandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ErrOutcomeUnknown forbids a blind retry after a native mutation loses its
// response. Durable intent must be reconciled against native inventory first.
var ErrOutcomeUnknown = errors.New("appsandbox mutation outcome unknown; reconcile recorded intent before retry")

// CreateClone sends one request with networking disabled. The privileged
// backend must first persist intent, verify absence, and protect the parent.
// The password exists only in this request and the daemon's guest setup.
func (c *Client) CreateClone(ctx context.Context, r CloneRecord, user, password string) error {
	if !strings.HasPrefix(r.NativeName, "bivouac-") || !identifier(r.NativeName, 15) || !identifier(user, 32) || len(password) < 24 || len(password) > 256 {
		return errors.New("invalid App Sandbox clone request")
	}
	if r.StorageParent == "" || !identifier(r.Template, 15) || r.CPU < 1 || r.MemoryMB < 512 || r.DiskGB < 16 || (r.GPUMode != 0 && r.GPUMode != 1) {
		return errors.New("invalid App Sandbox clone resources")
	}
	// #nosec G117 -- The native create API requires a random one-use guest password in the authenticated request body, never a log or record.
	body, err := json.Marshal(struct {
		Name       string `json:"name"`
		OS         string `json:"osType"`
		Template   string `json:"templateName"`
		Parent     string `json:"diskDirectory"`
		CPU        int    `json:"cpuCores"`
		Memory     int    `json:"ramMb"`
		Disk       int    `json:"hddGb"`
		GPU        int    `json:"gpuMode"`
		Network    int    `json:"networkMode"`
		User       string `json:"adminUser"`
		Password   string `json:"adminPass"`
		Test       bool   `json:"testMode"`
		SSH        bool   `json:"sshEnabled"`
		Key        bool   `json:"sshDeployKey"`
		IsTemplate bool   `json:"isTemplate"`
	}{r.NativeName, "Windows", r.Template, r.StorageParent, r.CPU, r.MemoryMB, r.DiskGB, r.GPUMode, 0, user, password, true, true, true, false})
	if err != nil {
		return errors.New("encode App Sandbox clone request")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.request(ctx, http.MethodPost, "/vms", bytes.NewReader(body), nil)
}

// VMCommand exposes only the native instance lifecycle operations, not global
// daemon shutdown, template mutation, disks, display, or arbitrary routes.
func (c *Client) VMCommand(ctx context.Context, name, action string) error {
	if !strings.HasPrefix(name, "bivouac-") || !identifier(name, 15) {
		return errors.New("invalid managed App Sandbox VM name")
	}
	switch action {
	case "start", "shutdown", "stop", "delete":
	default:
		return errors.New("unsupported App Sandbox VM operation")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.request(ctx, http.MethodPost, "/vms/"+name+"/"+action, strings.NewReader("{}"), nil)
}
