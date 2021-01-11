package authorize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

const (
	serviceAccountTypeURL = "type.googleapis.com/user.ServiceAccount"
	sessionTypeURL        = "type.googleapis.com/session.Session"
)

// A Session is either a session stored in the databroker, or a service account.
type Session interface {
	GetId() string
	GetExpiresAt() *timestamppb.Timestamp
	GetIssuedAt() *timestamppb.Timestamp
	GetUserId() string
	GetImpersonateUserId() string
	GetImpersonateEmail() string
	GetImpersonateGroups() []string
}

type nilSession struct{}

func newNilSession() *nilSession {
	return nil
}

func (*nilSession) GetId() string                        { return "" } //nolint
func (*nilSession) GetExpiresAt() *timestamppb.Timestamp { return nil }
func (*nilSession) GetIssuedAt() *timestamppb.Timestamp  { return nil }
func (*nilSession) GetUserId() string                    { return "" } //nolint
func (*nilSession) GetImpersonateUserId() string         { return "" } //nolint
func (*nilSession) GetImpersonateEmail() string          { return "" }
func (*nilSession) GetImpersonateGroups() []string       { return nil }

func (a *Authorize) loadSessionFromRequest(ctx context.Context, req *http.Request) (Session, error) {
	state := a.state.Load()
	options := a.currentOptions.Load()

	rawJWT, err := loadRawJWT(req, options, state.encoder)
	if err != nil {
		return newNilSession(), err
	}

	var jwt struct {
		ID string `json:"jti"`
	}
	err = state.encoder.Unmarshal(rawJWT, &jwt)
	if err != nil {
		return newNilSession(), err
	}

	return a.loadSession(ctx, jwt.ID)
}

func (a *Authorize) loadSession(ctx context.Context, id string) (Session, error) {
	state := a.state.Load()

	a.dataBrokerDataLock.RLock()
	s, _ := a.dataBrokerData.Get(sessionTypeURL, id).(*session.Session)
	sa, _ := a.dataBrokerData.Get(serviceAccountTypeURL, id).(*user.ServiceAccount)
	a.dataBrokerDataLock.RUnlock()

	if s != nil {
		return s, nil
	} else if sa != nil {
		return sa, nil
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		res, err := state.dataBrokerClient.Get(ctx, &databroker.GetRequest{
			Type: sessionTypeURL,
			Id:   id,
		})
		if err != nil {
			return
		}

		a.dataBrokerDataLock.Lock()
		if current := a.dataBrokerData.Get(sessionTypeURL, id); current == nil {
			a.dataBrokerData.Update(res.GetRecord())
		}
		s, _ = a.dataBrokerData.Get(sessionTypeURL, id).(*session.Session)
		a.dataBrokerDataLock.Unlock()
		return
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		res, err := state.dataBrokerClient.Get(ctx, &databroker.GetRequest{
			Type: serviceAccountTypeURL,
			Id:   id,
		})
		if err != nil {
			return
		}

		a.dataBrokerDataLock.Lock()
		if current := a.dataBrokerData.Get(serviceAccountTypeURL, id); current == nil {
			a.dataBrokerData.Update(res.GetRecord())
		}
		sa, _ = a.dataBrokerData.Get(sessionTypeURL, id).(*user.ServiceAccount)
		a.dataBrokerDataLock.Unlock()
		return
	}()

	if s != nil {
		return s, nil
	} else if sa != nil {
		return sa, nil
	}

	return newNilSession(), sessions.ErrNoSessionFound
}

func (a *Authorize) loadUser(ctx context.Context, id string) (*user.User, error) {
	state := a.state.Load()

	a.dataBrokerDataLock.RLock()
	u, _ := a.dataBrokerData.Get(userTypeURL, id).(*user.User)
	a.dataBrokerDataLock.RUnlock()

	if u == nil {
		return u, nil
	}

	res, err := state.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: userTypeURL,
		Id:   id,
	})
	if err != nil {
		return nil, err
	}

	a.dataBrokerDataLock.Lock()
	if current := a.dataBrokerData.Get(userTypeURL, id); current == nil {
		a.dataBrokerData.Update(res.GetRecord())
	}
	u, _ = a.dataBrokerData.Get(userTypeURL, id).(*user.User)
	a.dataBrokerDataLock.Unlock()

	if u == nil {
		return u, nil
	}

	return nil, errors.New("user not found")
}

func loadRawJWT(req *http.Request, options *config.Options, encoder encoding.MarshalUnmarshaler) ([]byte, error) {
	var loaders []sessions.SessionLoader
	cookieStore, err := getCookieStore(options, encoder)
	if err != nil {
		return nil, err
	}
	loaders = append(loaders,
		cookieStore,
		header.NewStore(encoder, httputil.AuthorizationTypePomerium),
		queryparam.NewStore(encoder, urlutil.QuerySession),
	)

	for _, loader := range loaders {
		sess, err := loader.LoadSession(req)
		if err != nil && !errors.Is(err, sessions.ErrNoSessionFound) {
			return nil, err
		} else if err == nil {
			return []byte(sess), nil
		}
	}

	return nil, sessions.ErrNoSessionFound
}

func loadSession(encoder encoding.MarshalUnmarshaler, rawJWT []byte) (*sessions.State, error) {
	var s sessions.State
	err := encoder.Unmarshal(rawJWT, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func getCookieStore(options *config.Options, encoder encoding.MarshalUnmarshaler) (sessions.SessionStore, error) {
	cookieStore, err := cookie.NewStore(func() cookie.Options {
		return cookie.Options{
			Name:     options.CookieName,
			Domain:   options.CookieDomain,
			Secure:   options.CookieSecure,
			HTTPOnly: options.CookieHTTPOnly,
			Expire:   options.CookieExpire,
		}
	}, encoder)
	if err != nil {
		return nil, err
	}
	return cookieStore, nil
}

func getJWTSetCookieHeaders(cookieStore sessions.SessionStore, rawjwt []byte) (map[string]string, error) {
	recorder := httptest.NewRecorder()
	err := cookieStore.SaveSession(recorder, nil /* unused by cookie store */, string(rawjwt))
	if err != nil {
		return nil, fmt.Errorf("authorize: error saving cookie: %w", err)
	}

	res := recorder.Result()
	res.Body.Close()

	hdrs := make(map[string]string)
	for k, vs := range res.Header {
		for _, v := range vs {
			hdrs[k] = v
		}
	}
	return hdrs, nil
}

func (a *Authorize) getJWTClaimHeaders(options *config.Options, signedJWT string) (map[string]string, error) {
	if len(signedJWT) == 0 {
		return make(map[string]string), nil
	}

	state := a.state.Load()

	var claims map[string]interface{}
	payload, err := state.evaluator.ParseSignedJWT(signedJWT)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	hdrs := make(map[string]string)
	for _, name := range options.JWTClaimsHeaders {
		if claim, ok := claims[name]; ok {
			switch value := claim.(type) {
			case string:
				hdrs["x-pomerium-claim-"+name] = value
			case []interface{}:
				hdrs["x-pomerium-claim-"+name] = strings.Join(toSliceStrings(value), ",")
			}
		}
	}
	return hdrs, nil
}

func toSliceStrings(sliceIfaces []interface{}) []string {
	sliceStrings := make([]string, 0, len(sliceIfaces))
	for _, e := range sliceIfaces {
		sliceStrings = append(sliceStrings, fmt.Sprint(e))
	}
	return sliceStrings
}
