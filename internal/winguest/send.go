package winguest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Send writes size bytes from data to name in the SSH user's home directory,
// speaking the scp sink protocol to the guest's own OpenSSH scp. The name is a
// fixed base name chosen by the caller, never guest or job input.
func Send(ctx context.Context, client *ssh.Client, name string, data io.Reader, size int64) error {
	if name == "" || path.Base(name) != name || strings.ContainsAny(name, " \\/:\"*?<>|\x00\r\n") || size < 0 || size > 1<<30 {
		return errors.New("invalid fixed guest transfer")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	if err = session.Start("scp -t " + name); err != nil {
		return err
	}
	acks := bufio.NewReaderSize(io.LimitReader(stdout, 64<<10), 512)
	ack := func() error {
		b, err := acks.ReadByte()
		if err != nil {
			return errors.New("guest scp sink closed")
		}
		if b != 0 {
			// 1 is a warning and 2 a fatal error, each followed by a guest
			// message line that is discarded unread.
			return errors.New("guest scp sink refused the transfer")
		}
		return nil
	}
	if err = ack(); err != nil {
		return err
	}
	if _, err = fmt.Fprintf(stdin, "C0600 %d %s\n", size, name); err != nil {
		return err
	}
	if err = ack(); err != nil {
		return err
	}
	n, err := io.Copy(stdin, io.LimitReader(data, size))
	if err != nil || n != size {
		return errors.Join(errors.New("guest transfer source ended early"), err)
	}
	if _, err = stdin.Write([]byte{0}); err != nil {
		return err
	}
	if err = ack(); err != nil {
		return err
	}
	_ = stdin.Close()
	if err = session.Wait(); err != nil {
		return errors.New("guest scp sink failed")
	}
	return ctx.Err()
}
