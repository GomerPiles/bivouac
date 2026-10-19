//go:build windows

package vmhost

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Error is a refusal or failure reported by the VM host.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return "VM host: " + e.Message }

// IsCode reports whether err is a VM host error with code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Client is the unprivileged side of the pipe protocol.
type Client struct {
	pipe         string
	verifyServer func(windows.Handle) error
}

func NewClient() *Client { return &Client{pipe: PipeName, verifyServer: elevatedServer} }

// elevatedServer refuses a pipe served by an unprivileged process: a user
// process that created the name first must not be trusted as the VM host.
func elevatedServer(pipe windows.Handle) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &pid); err != nil {
		return err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(process) }()
	var token windows.Token
	if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer func() { _ = token.Close() }()
	if token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err == nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return errors.New("VM host pipe is served by an unprivileged process")
}

func (c *Client) do(ctx context.Context, req Request) (Response, error) {
	// Identification lets the VM host learn the caller's account without
	// being able to act as it.
	conn, err := winio.DialPipeAccessImpLevel(ctx, c.pipe, clientAccess, winio.PipeImpLevelIdentification)
	if err != nil {
		return Response{}, errors.Join(errors.New("VM host unavailable"), err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Response{}, errors.New("VM host connection is not a pipe")
	}
	if err = c.verifyServer(windows.Handle(f.Fd())); err != nil {
		return Response{}, err
	}
	deadline := time.Now().Add(requestTimeout + time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return Response{}, err
	}
	if err = json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, errors.Join(errors.New("VM host request failed"), err)
	}
	var resp Response
	if err = json.NewDecoder(io.LimitReader(conn, maxResponse)).Decode(&resp); err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, errors.Join(errors.New("VM host response unavailable"), err)
	}
	if resp.Code != "" {
		return resp, &Error{Code: resp.Code, Message: resp.Error}
	}
	return resp, nil
}

func (c *Client) Info(ctx context.Context) (Info, error) {
	resp, err := c.do(ctx, Request{Op: "info"})
	if err != nil || resp.Info == nil {
		return Info{}, errors.Join(err, missing(err == nil && resp.Info == nil))
	}
	return *resp.Info, nil
}

func (c *Client) Create(ctx context.Context, req CreateRequest) (GuestInfo, error) {
	return c.guest(ctx, Request{Op: "create", Create: &req})
}

func (c *Client) Status(ctx context.Context, name string) (GuestInfo, error) {
	return c.guest(ctx, Request{Op: "status", Name: name})
}

func (c *Client) Destroy(ctx context.Context, name string) error {
	_, err := c.guest(ctx, Request{Op: "destroy", Name: name})
	return err
}

func (c *Client) List(ctx context.Context) ([]GuestInfo, error) {
	resp, err := c.do(ctx, Request{Op: "list"})
	return resp.Guests, err
}

func (c *Client) guest(ctx context.Context, req Request) (GuestInfo, error) {
	resp, err := c.do(ctx, req)
	if err != nil || resp.Guest == nil {
		return GuestInfo{}, errors.Join(err, missing(err == nil && resp.Guest == nil))
	}
	return *resp.Guest, nil
}

func missing(absent bool) error {
	if absent {
		return errors.New("VM host response incomplete")
	}
	return nil
}
