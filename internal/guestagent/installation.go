package guestagent

const WindowsTaskName = "bivouac-guest-agent"
const WindowsRunnerTaskName = "bivouac-guest-runner"

// TaskFacts contains only public predicates, never account identifiers or XML.
type TaskFacts struct {
	TaskUser        bool   `json:"task_user"`
	TaskHighest     bool   `json:"task_highest"`
	TaskInteractive bool   `json:"task_interactive"`
	TaskAction      bool   `json:"task_action"`
	TaskPriority    uint32 `json:"task_priority"`
	TaskPolicy      bool   `json:"task_policy"`
	TaskSecurity    bool   `json:"task_security"`
	// SecurityShape explains a refused descriptor without account identifiers:
	// "query" when it could not be read, else the owner kind and each entry's
	// kind (SY, BA, principal P, other X), access mask and flags.
	SecurityShape string `json:"security_shape,omitempty"`
}

func (f TaskFacts) Valid() bool {
	return f.ValidDefinition() && f.TaskSecurity
}

func (f TaskFacts) ValidDefinition() bool { return f.ValidAgent() && f.TaskPolicy }

// ValidAgent checks the existing agent-task contract. Policy and Security are
// additional runner-task predicates; they make no claim about the agent DACL.
func (f TaskFacts) ValidAgent() bool {
	return f.TaskUser && f.TaskHighest && f.TaskInteractive && f.TaskAction && f.TaskPriority == 4
}

type InstallationFacts struct {
	TaskUser                bool      `json:"task_user"`
	TaskHighest             bool      `json:"task_highest"`
	TaskInteractive         bool      `json:"task_interactive"`
	TaskAction              bool      `json:"task_action"`
	TaskPriority            uint32    `json:"task_priority"`
	OwnerTrusted            bool      `json:"owner_trusted"`
	ACLProtected            bool      `json:"acl_protected"`
	ACLExpected             bool      `json:"acl_expected"`
	RunnerTask              TaskFacts `json:"runner_task"`
	AutologonAccountMatches bool      `json:"autologon_account_matches"`
}

func (f InstallationFacts) Valid() bool {
	return f.TaskUser && f.TaskHighest && f.TaskInteractive && f.TaskAction && f.TaskPriority == 4 && f.OwnerTrusted && f.ACLProtected && f.ACLExpected && f.RunnerTask.Valid() && f.AutologonAccountMatches
}
