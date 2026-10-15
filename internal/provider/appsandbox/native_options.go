package appsandbox

// BrokerOptions is administrator-selected configuration, independent of the
// normal manager config. It contains no GitHub or SSH credential. The template
// file/name/hash binding is pinned before the broker admits requests.
type BrokerOptions struct {
	Root           string `json:"root"`
	ControllerID   string `json:"controller_id"`
	Baseline       string `json:"baseline"`
	BaselineDisk   string `json:"baseline_disk"`
	BaselineSHA256 string `json:"baseline_sha256"`
	Discovery      string `json:"discovery"`
	GuestUser      string `json:"guest_user"`
	MaxCPU         int    `json:"max_cpu"`
	MaxMemoryMB    int    `json:"max_memory_mb"`
	MaxDiskGB      int    `json:"max_disk_gb"`
	MaxInstances   int    `json:"max_instances"`
}
