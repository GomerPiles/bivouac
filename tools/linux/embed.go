// Package linux embeds the Linux guest agent unit from its operator-facing source.
package linux

import _ "embed"

//go:embed bivouac-guest-agent.service
var guestAgentUnit string

// GuestAgentUnit returns a private copy; recipes cannot mutate the embedded unit.
func GuestAgentUnit() []byte { return []byte(guestAgentUnit) }
