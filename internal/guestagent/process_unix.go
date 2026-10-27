//go:build darwin || linux

package guestagent

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
)

func RunAgent(ctx context.Context) error {
	l, err := listen(Port)
	if err != nil {
		return err
	}
	return Serve(ctx, l)
}

// RunCLI preserves the macOS/Linux command line.
func RunCLI(ctx context.Context, args []string, _ io.Reader) error {
	if len(args) != 0 {
		return errors.New("invalid guest agent arguments")
	}
	return RunAgent(ctx)
}

type unixCommand struct{ cmd *exec.Cmd }

func startCommand(ctx context.Context, req request, stdout, stderr io.Writer) (commandProcess, io.WriteCloser, error) {
	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = stdout, stderr, outputDelay
	var stdin io.WriteCloser
	var err error
	if req.Stdin {
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return nil, nil, err
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return &unixCommand{cmd}, stdin, nil
}

func (p *unixCommand) Close() {}
func (p *unixCommand) Wait() (int32, error) {
	err := p.cmd.Wait()
	state := p.cmd.ProcessState
	if state == nil {
		return 0, errors.New("command lost")
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return 0, err
	}
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int32(ws.Signal()), nil //nolint:gosec // Signal numbers are small.
	}
	return int32(state.ExitCode()), nil //nolint:gosec // Exit codes fit in a byte.
}
