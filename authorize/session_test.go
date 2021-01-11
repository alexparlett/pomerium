package authorize

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestAuthorize_getJWTClaimHeaders(t *testing.T) {
	opt := &config.Options{
		AuthenticateURL: mustParseURL("https://authenticate.example.com"),
		Policies: []config.Policy{{
			Source: &config.StringURL{URL: &url.URL{Host: "example.com"}},
			SubPolicies: []config.SubPolicy{{
				Rego: []string{"allow = true"},
			}},
		}},
	}
	a := &Authorize{currentOptions: config.NewAtomicOptions(), state: newAtomicAuthorizeState(new(authorizeState))}
	encoder, _ := jws.NewHS256Signer([]byte{0, 0, 0, 0})
	a.state.Load().encoder = encoder
	a.currentOptions.Store(opt)
	a.store = evaluator.NewStore()
	pe, err := newPolicyEvaluator(opt, a.store)
	require.NoError(t, err)
	a.state.Load().evaluator = pe
	signedJWT, _ := pe.SignedJWT(pe.JWTPayload(&evaluator.Request{
		DataBrokerData: evaluator.DataBrokerData{
			"type.googleapis.com/session.Session": map[string]interface{}{
				"SESSION_ID": &session.Session{
					UserId: "USER_ID",
				},
			},
			"type.googleapis.com/user.User": map[string]interface{}{
				"USER_ID": &user.User{
					Id:    "USER_ID",
					Name:  "foo",
					Email: "foo@example.com",
				},
			},
			"type.googleapis.com/directory.User": map[string]interface{}{
				"USER_ID": &directory.User{
					Id:       "USER_ID",
					GroupIds: []string{"admin_id", "test_id"},
				},
			},
			"type.googleapis.com/directory.Group": map[string]interface{}{
				"admin_id": &directory.Group{
					Id:   "admin_id",
					Name: "admin",
				},
				"test_id": &directory.Group{
					Id:   "test_id",
					Name: "test",
				},
			},
		},
		HTTP: evaluator.RequestHTTP{URL: "https://example.com"},
		Session: evaluator.RequestSession{
			ID: "SESSION_ID",
		},
	}))

	tests := []struct {
		name            string
		signedJWT       string
		jwtHeaders      []string
		expectedHeaders map[string]string
	}{
		{"good with email", signedJWT, []string{"email"}, map[string]string{"x-pomerium-claim-email": "foo@example.com"}},
		{"good with groups", signedJWT, []string{"groups"}, map[string]string{"x-pomerium-claim-groups": "admin_id,test_id,admin,test"}},
		{"empty signed JWT", "", nil, make(map[string]string)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opt.JWTClaimsHeaders = tc.jwtHeaders
			gotHeaders, err := a.getJWTClaimHeaders(opt, tc.signedJWT)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedHeaders, gotHeaders)
		})
	}
}
