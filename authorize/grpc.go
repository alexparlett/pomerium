package authorize

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
)

const (
	userTypeURL = "type.googleapis.com/user.User"
)

// Check implements the envoy auth server gRPC endpoint.
func (a *Authorize) Check(ctx context.Context, in *envoy_service_auth_v2.CheckRequest) (*envoy_service_auth_v2.CheckResponse, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.Check")
	defer span.End()

	state := a.state.Load()

	// convert the incoming envoy-style http request into a go-style http request
	hreq := getHTTPRequestFromCheckRequest(in)

	isForwardAuth := a.isForwardAuth(in)
	if isForwardAuth {
		// update the incoming http request's uri to match the forwarded URI
		fwdAuthURI := getForwardAuthURL(hreq)
		in.Attributes.Request.Http.Scheme = fwdAuthURI.Scheme
		in.Attributes.Request.Http.Host = fwdAuthURI.Host
		in.Attributes.Request.Http.Path = fwdAuthURI.EscapedPath()
		if fwdAuthURI.RawQuery != "" {
			in.Attributes.Request.Http.Path += "?" + fwdAuthURI.RawQuery
		}
	}

	session, err := a.loadSessionFromRequest(ctx, hreq)
	if err != nil {
		log.Warn().Err(err).Msg("load session error")
	}
	a.forceSyncUser(ctx, session)

	a.dataBrokerDataLock.RLock()
	defer a.dataBrokerDataLock.RUnlock()

	req := a.getEvaluatorRequestFromCheckRequest(in, session)
	reply, err := state.evaluator.Evaluate(ctx, req)
	if err != nil {
		log.Error().Err(err).Msg("error during OPA evaluation")
		return nil, err
	}
	logAuthorizeCheck(ctx, in, reply)

	switch {
	case reply.Status == http.StatusOK:
		return a.okResponse(reply), nil
	case reply.Status == http.StatusUnauthorized:
		if isForwardAuth && hreq.URL.Path == "/verify" {
			return a.deniedResponse(in, http.StatusUnauthorized, "Unauthenticated", nil), nil
		}
		return a.redirectResponse(in), nil
	}
	return a.deniedResponse(in, int32(reply.Status), reply.Message, nil), nil
}

func (a *Authorize) forceSyncUser(ctx context.Context, session Session) {
	ctx, span := trace.StartSpan(ctx, "authorize.forceSyncUser")
	defer span.End()

	// sync user id
	if userID := session.GetUserId(); userID != "" {
		_, err := a.loadUser(ctx, userID)
		if err != nil {
			log.Warn().Err(err).Msg("load user error")
		}
	}
	if userID := session.GetImpersonateUserId(); userID != "" {
		_, err := a.loadUser(ctx, userID)
		if err != nil {
			log.Warn().Err(err).Msg("load user error")
		}
	}
}

func (a *Authorize) getEnvoyRequestHeaders(signedJWT string) ([]*envoy_api_v2_core.HeaderValueOption, error) {
	var hvos []*envoy_api_v2_core.HeaderValueOption

	hdrs, err := a.getJWTClaimHeaders(a.currentOptions.Load(), signedJWT)
	if err != nil {
		return nil, err
	}
	for k, v := range hdrs {
		hvos = append(hvos, mkHeader(k, v, false))
	}

	return hvos, nil
}

func getForwardAuthURL(r *http.Request) *url.URL {
	urqQuery := r.URL.Query().Get("uri")
	u, _ := urlutil.ParseAndValidateURL(urqQuery)
	if u == nil {
		u = &url.URL{
			Scheme: r.Header.Get(httputil.HeaderForwardedProto),
			Host:   r.Header.Get(httputil.HeaderForwardedHost),
			Path:   r.Header.Get(httputil.HeaderForwardedURI),
		}
	}
	originalURL := r.Header.Get(httputil.HeaderOriginalURL)
	if originalURL != "" {
		k, _ := urlutil.ParseAndValidateURL(originalURL)
		if k != nil {
			u = k
		}
	}
	return u
}

// isForwardAuth returns if the current request is a forward auth route.
func (a *Authorize) isForwardAuth(req *envoy_service_auth_v2.CheckRequest) bool {
	opts := a.currentOptions.Load()

	if opts.ForwardAuthURL == nil {
		return false
	}

	checkURL := getCheckRequestURL(req)

	return urlutil.StripPort(checkURL.Host) == urlutil.StripPort(opts.GetForwardAuthURL().Host)
}

func (a *Authorize) getEvaluatorRequestFromCheckRequest(in *envoy_service_auth_v2.CheckRequest, session Session) *evaluator.Request {
	requestURL := getCheckRequestURL(in)
	req := &evaluator.Request{
		DataBrokerData: a.dataBrokerData,
		HTTP: evaluator.RequestHTTP{
			Method:            in.GetAttributes().GetRequest().GetHttp().GetMethod(),
			URL:               requestURL.String(),
			Headers:           getCheckRequestHeaders(in),
			ClientCertificate: getPeerCertificate(in),
		},
		Session: evaluator.RequestSession{
			ID:                session.GetId(),
			ExpiresAt:         session.GetExpiresAt(),
			IssuedAt:          session.GetIssuedAt(),
			UserID:            session.GetUserId(),
			ImpersonateUserID: session.GetImpersonateUserId(),
			ImpersonateEmail:  session.GetImpersonateEmail(),
			ImpersonateGroups: session.GetImpersonateGroups(),
		},
	}
	p := a.getMatchingPolicy(requestURL)
	if p != nil {
		for _, sp := range p.SubPolicies {
			req.CustomPolicies = append(req.CustomPolicies, sp.Rego...)
		}
	}
	return req
}

func (a *Authorize) getMatchingPolicy(requestURL *url.URL) *config.Policy {
	options := a.currentOptions.Load()

	for _, p := range options.Policies {
		if p.Matches(requestURL) {
			return &p
		}
	}

	return nil
}

func getHTTPRequestFromCheckRequest(req *envoy_service_auth_v2.CheckRequest) *http.Request {
	hattrs := req.GetAttributes().GetRequest().GetHttp()
	hreq := &http.Request{
		Method:     hattrs.GetMethod(),
		URL:        getCheckRequestURL(req),
		Header:     make(http.Header),
		Body:       ioutil.NopCloser(strings.NewReader(hattrs.GetBody())),
		Host:       hattrs.GetHost(),
		RequestURI: hattrs.GetPath(),
	}
	for k, v := range getCheckRequestHeaders(req) {
		hreq.Header.Set(k, v)
	}
	return hreq
}

func getCheckRequestHeaders(req *envoy_service_auth_v2.CheckRequest) map[string]string {
	hdrs := make(map[string]string)
	ch := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	for k, v := range ch {
		hdrs[http.CanonicalHeaderKey(k)] = v
	}
	return hdrs
}

func getCheckRequestURL(req *envoy_service_auth_v2.CheckRequest) *url.URL {
	h := req.GetAttributes().GetRequest().GetHttp()
	u := &url.URL{
		Scheme: h.GetScheme(),
		Host:   h.GetHost(),
	}
	u.Host = urlutil.GetDomainsForURL(u)[0]
	// envoy sends the query string as part of the path
	path := h.GetPath()
	if idx := strings.Index(path, "?"); idx != -1 {
		u.Path, u.RawQuery = path[:idx], path[idx+1:]
	} else {
		u.Path = path
	}
	return u
}

// getPeerCertificate gets the PEM-encoded peer certificate from the check request
func getPeerCertificate(in *envoy_service_auth_v2.CheckRequest) string {
	// ignore the error as we will just return the empty string in that case
	cert, _ := url.QueryUnescape(in.GetAttributes().GetSource().GetCertificate())
	return cert
}

func logAuthorizeCheck(
	ctx context.Context,
	in *envoy_service_auth_v2.CheckRequest,
	reply *evaluator.Result,
) {
	hdrs := getCheckRequestHeaders(in)
	hattrs := in.GetAttributes().GetRequest().GetHttp()
	evt := log.Info().Str("service", "authorize")
	// request
	evt = evt.Str("request-id", requestid.FromContext(ctx))
	evt = evt.Str("check-request-id", hdrs["X-Request-Id"])
	evt = evt.Str("method", hattrs.GetMethod())
	evt = evt.Str("path", hattrs.GetPath())
	evt = evt.Str("host", hattrs.GetHost())
	evt = evt.Str("query", hattrs.GetQuery())
	// reply
	if reply != nil {
		evt = evt.Bool("allow", reply.Status == http.StatusOK)
		evt = evt.Int("status", reply.Status)
		evt = evt.Str("message", reply.Message)
		evt = evt.Str("user", reply.UserEmail)
		evt = evt.Strs("groups", reply.UserGroups)
	}

	// potentially sensitive, only log if debug mode
	if zerolog.GlobalLevel() <= zerolog.DebugLevel {
		evt = evt.Interface("headers", hdrs)
	}

	evt.Msg("authorize check")
}
