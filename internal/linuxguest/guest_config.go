package linuxguest

type GuestConfig struct {
	Profile      ExecutionProfile `json:"profile"`
	Name         string           `json:"name"`
	ControllerID string           `json:"controller_id"`
	BootID       string           `json:"boot_id"`
	RunnerDir    string           `json:"runner_dir"`
	GPU          bool             `json:"gpu"`
}
