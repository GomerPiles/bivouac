//go:build windows

package vmhost

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/GomerPiles/bivouac/internal/sandboxdiscovery"
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

func NewClient() *Client { return &Client{pipe: PipeName, verifyServer: privilegedServer} }

// privilegedServer refuses a pipe an unprivileged process created: a user
// process that created the name first must not be trusted as the VM host.
// The pipe's owner is its creator's default owner, and only an elevated or
// SYSTEM process can own an object as Administrators or SYSTEM (a filtered
// token holds Administrators for deny only). The server's process token is
// not checked: an unelevated client cannot open a SYSTEM service's process.
func privilegedServer(pipe windows.Handle) error {
	sd, err := windows.GetSecurityInfo(pipe, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return errors.New("VM host pipe was created by an unprivileged account")
}

func (c *Client) do(ctx context.Context, req Request) (Response, error) {
	// Identification lets the VM host learn the caller's account without
	// being able to act as it. READ_CONTROL lets the client read the pipe's
	// owner.
	conn, err := winio.DialPipeAccessImpLevel(ctx, c.pipe, clientAccess|windows.READ_CONTROL, winio.PipeImpLevelIdentification)
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

func (c *Client) SandboxCandidates(ctx context.Context) ([]sandboxdiscovery.Candidate, error) {
	response, err := c.do(ctx, Request{Op: "sandbox-candidates"})
	if err != nil {
		return nil, err
	}
	if len(response.SandboxCandidates) > 16 {
		return nil, errors.New("sandbox metadata bound exceeded")
	}
	for _, item := range response.SandboxCandidates {
		if !item.Valid() {
			return nil, errors.New("sandbox metadata invalid")
		}
	}
	return response.SandboxCandidates, nil
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
