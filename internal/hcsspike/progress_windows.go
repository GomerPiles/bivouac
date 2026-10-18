//go:build windows

package hcsspike

import (
	"bytes"
	"strconv"
	"time"
)

// Only fixed phase numbers cross the stderr sink. Arbitrary guest stderr is
// drained, never returned or logged; an overlong line is discarded in full.
// Session.Run joins its copy goroutines before the owner reads step.
type validationProgress struct {
	// Only the SSH stderr copy goroutine writes these. Session.Run joins it
	// before the caller reads timing spans. Clock injection keeps tests synthetic.
	now      func() time.Time
	received [28]time.Time
	line     [48]byte
	length   int
	overflow bool
	step     uint32
}

func (p *validationProgress) Write(data []byte) (int, error) {
	for _, b := range data {
		switch {
		case b == '\n':
			if !p.overflow {
				line := bytes.TrimSuffix(p.line[:p.length], []byte{'\r'})
				const prefix = "BIVOUAC_HCS_STEP:"
				if bytes.HasPrefix(line, []byte(prefix)) {
					number, err := strconv.ParseUint(string(line[len(prefix):]), 10, 32)
					if err == nil && validValidationStep(uint32(number)) {
						p.observe(uint32(number))
					}
				}
			}
			clear(p.line[:])
			p.length = 0
			p.overflow = false
		case p.length < len(p.line):
			p.line[p.length] = b
			p.length++
		default:
			p.overflow = true
		}
	}
	return len(data), nil
}
func validValidationStep(step uint32) bool {
	switch step {
	case 1, 2, 3, 4, 17, 19, 20, 21, 22, 23, 24, 25, 26, 27:
		return true
	}
	return false
}

func (p *validationProgress) observe(step uint32) {
	p.step = step
	// Repeated guest checkpoints cannot reset an already observed timestamp.
	if p.received[step].IsZero() {
		now := time.Now
		if p.now != nil {
			now = p.now
		}
		p.received[step] = now()
	}
}

func (p *validationProgress) spanMS(start, end uint32) uint64 {
	if start >= uint32(len(p.received)) || end >= uint32(len(p.received)) || p.received[start].IsZero() || p.received[end].IsZero() {
		return 0
	}
	return durationMS(p.received[end].Sub(p.received[start]))
}
