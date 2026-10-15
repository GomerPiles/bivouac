//go:build !windows

package main

import "context"

func loginRun(context.Context, []string) error { return errUsage }
