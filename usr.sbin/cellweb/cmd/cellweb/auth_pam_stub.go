//go:build !netbsd || !cgo

package main

import (
	"context"
	"errors"
)

type unsupportedAuthenticator struct{}

func newPAMAuthenticator(_ string) authenticator {
	return unsupportedAuthenticator{}
}

func (unsupportedAuthenticator) Authenticate(ctx context.Context, _, _ string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return errors.New("PAM authentication is only available on NetBSD builds with cgo enabled")
}
