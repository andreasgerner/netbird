package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/auth"
)

// pkceFlowStub stands in for a non-device flow: pendingOAuthFlowResponse only
// needs the client ID and the concrete type to decide whether to reuse.
type pkceFlowStub struct {
	clientID string
}

func (f *pkceFlowStub) RequestAuthInfo(context.Context) (auth.AuthFlowInfo, error) {
	return auth.AuthFlowInfo{}, nil
}

func (f *pkceFlowStub) WaitToken(context.Context, auth.AuthFlowInfo) (auth.TokenInfo, error) {
	return auth.TokenInfo{}, nil
}

func (f *pkceFlowStub) GetClientID(context.Context) string { return f.clientID }

func TestPendingOAuthFlowResponse(t *testing.T) {
	// A zero-value DeviceAuthorizationFlow reports an empty client ID, so it
	// matches a pkceFlowStub with the same empty ID and the flow type is the
	// only thing left to differ on.
	deviceFlow := func() auth.OAuthFlow { return &auth.DeviceAuthorizationFlow{} }
	pkceFlow := func() auth.OAuthFlow { return &pkceFlowStub{} }

	tests := []struct {
		name       string
		cached     auth.OAuthFlow
		requested  auth.OAuthFlow
		expiresIn  time.Duration
		wantReuse  bool
		wantCancel bool
	}{
		{
			name:      "no cached flow starts fresh",
			requested: deviceFlow(),
			expiresIn: 10 * time.Minute,
		},
		{
			// The flag-based comparison rejected this: on a headless client
			// --use-device-auth is unset yet NewOAuthFlow still returns a
			// device flow, so a repeated login issued a second device code.
			name:      "device flow selected without the force flag is reused",
			cached:    deviceFlow(),
			requested: deviceFlow(),
			expiresIn: 10 * time.Minute,
			wantReuse: true,
		},
		{
			name:      "pkce flow is reused",
			cached:    pkceFlow(),
			requested: pkceFlow(),
			expiresIn: 10 * time.Minute,
			wantReuse: true,
		},
		{
			name:       "switching from pkce to device cancels the pending waiter",
			cached:     pkceFlow(),
			requested:  deviceFlow(),
			expiresIn:  10 * time.Minute,
			wantCancel: true,
		},
		{
			name:       "switching from device to pkce cancels the pending waiter",
			cached:     deviceFlow(),
			requested:  pkceFlow(),
			expiresIn:  10 * time.Minute,
			wantCancel: true,
		},
		{
			name:       "matching flow too close to expiry cancels the pending waiter",
			cached:     deviceFlow(),
			requested:  deviceFlow(),
			expiresIn:  30 * time.Second,
			wantCancel: true,
		},
		{
			name:      "mismatched client ID starts fresh without cancelling",
			cached:    &pkceFlowStub{clientID: "client-a"},
			requested: &pkceFlowStub{clientID: "client-b"},
			expiresIn: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cancelled := false

			s := &Server{}
			s.oauthAuthFlow.flow = tt.cached
			s.oauthAuthFlow.expiresAt = time.Now().Add(tt.expiresIn)
			s.oauthAuthFlow.info.UserCode = "pending-code"
			s.oauthAuthFlow.waitCancel = func() { cancelled = true }

			resp := s.pendingOAuthFlowResponse(context.Background(), tt.requested)

			if tt.wantReuse {
				require.NotNil(t, resp, "expected the pending flow to be reused")
				require.True(t, resp.NeedsSSOLogin)
				require.Equal(t, "pending-code", resp.UserCode)
			} else {
				require.Nil(t, resp, "expected the caller to start a fresh flow")
			}

			require.Equal(t, tt.wantCancel, cancelled, "unexpected waitCancel behaviour")
		})
	}
}
