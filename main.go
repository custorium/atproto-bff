package main

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/carlmjohnson/versioninfo"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/gorilla/sessions"
	"github.com/urfave/cli/v2"
)

const serverListenerBootTimeout = 5 * time.Second

func main() {
	app := cli.App{
		Name:   "oauth-web-demo",
		Usage:  "atproto OAuth web server demo",
		Action: runServer,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "session-secret",
				Usage:    "random string/token used for session cookie security",
				Required: true,
				EnvVars:  []string{"SESSION_SECRET"},
			},
			&cli.StringFlag{
				Name:    "hostname",
				Usage:   "public host name for this client (if not localhost dev mode)",
				EnvVars: []string{"CLIENT_HOSTNAME"},
			},
			&cli.StringFlag{
				Name:    "client-secret-key",
				Usage:   "confidential client secret key. should be P-256 private key in multibase encoding",
				EnvVars: []string{"CLIENT_SECRET_KEY"},
			},
			&cli.StringFlag{
				Name:    "client-secret-key-id",
				Usage:   "key id for client-secret-key",
				Value:   "primary",
				EnvVars: []string{"CLIENT_SECRET_KEY_ID"},
			},
			&cli.StringFlag{
				Name:    "plc-host",
				Usage:   "method, hostname, and port of PLC registry",
				Value:   "https://plc.directory",
				EnvVars: []string{"PLC_HOST"},
			},
			&cli.StringFlag{
				Name:  "listen",
				Usage: "listen address",
				Value: ":4201",
			},
			&cli.StringSliceFlag{
				Name:  "proxy",
				Usage: "<proxy prefix>:<did service>",
				Value: cli.NewStringSlice("/xrpc:atproto_pds"),
				Action: func(ctx *cli.Context, s []string) error {
					return nil
				},
			},
			&cli.StringSliceFlag{
				Name:  "static",
				Usage: "<statix prefix>:<static path>",
			},
			&cli.StringFlag{
				Name:  "redirect",
				Usage: "<statix prefix>:<static path>",
			},
		},
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(h))
	app.Run(os.Args)
}

type Server struct {
	IsLocalHost bool
	CookieStore *sessions.CookieStore
	OAuth       *oauth.ClientApp
}

type TmplData struct {
	DID           *syntax.DID
	Handle        string
	CodeChallenge string
	Error         string
}

type SuccessTmplData struct {
	DID    *syntax.DID
	Handle string
	PdsUrl string
	Repo   string
	Rkey   string
	AtUri  string
}

//go:embed "base.html"
var tmplBaseText string

//go:embed "home.html"
var tmplHomeText string
var tmplHome = template.Must(template.Must(template.New("home.html").Parse(tmplBaseText)).Parse(tmplHomeText))

//go:embed "login.html"
var tmplLoginText string
var tmplLogin = template.Must(template.Must(template.New("login.html").Parse(tmplBaseText)).Parse(tmplLoginText))

//go:embed "error.html"
var tmplErrorText string
var tmplError = template.Must(template.Must(template.New("error.html").Parse(tmplBaseText)).Parse(tmplErrorText))

func runServer(cctx *cli.Context) error {

	var lc net.ListenConfig
	ctx, cancel := context.WithTimeout(context.Background(), serverListenerBootTimeout)
	defer cancel()

	li, err := lc.Listen(ctx, "tcp", cctx.String("listen"))
	if err != nil {
		return cli.Exit(err.Error(), 1)
	}

	e := echo.New()
	e.HideBanner = true
	e.Listener = li
	httpServer := &http.Server{}
	e.Use(middleware.RequestLogger())

	scopes := []string{"atproto", "include:org.farmapps.temp.ecrop.authFull"}

	var config oauth.ClientConfig
	hostname := cctx.String("hostname")
	if hostname == "" {
		config = oauth.NewLocalhostConfig(
			fmt.Sprintf("http://127.0.0.1:%s/oauth/callback", li.Addr().String()),
			scopes,
		)
		slog.Info("configuring localhost OAuth client", "CallbackURL", config.CallbackURL)
	} else {
		config = oauth.NewPublicConfig(
			fmt.Sprintf("https://%s/oauth-client-metadata.json", hostname),
			fmt.Sprintf("https://%s/oauth/callback", hostname),
			scopes,
		)
	}

	// If a client secret key is provided (as a multibase string), turn this in to a confidential client
	if cctx.String("client-secret-key") != "" && hostname != "" {
		priv, err := atcrypto.ParsePrivateMultibase(cctx.String("client-secret-key"))
		if err != nil {
			return cli.Exit(err.Error(), 1)
		}
		if err := config.SetClientSecret(priv, cctx.String("client-secret-key-id")); err != nil {
			return cli.Exit(err.Error(), 1)
		}
		slog.Info("configuring confidential OAuth client")
	}

	store, err := NewSqliteStore(&SqliteStoreConfig{
		DatabasePath:              "oauth_sessions.sqlite3",
		SessionExpiryDuration:     time.Hour * 24 * 90,
		SessionInactivityDuration: time.Hour * 24 * 14,
		AuthRequestExpiryDuration: time.Minute * 30,
	})
	if err != nil {
		return cli.Exit(err.Error(), 1)
	}
	plchost := cctx.String("plc-host")
	directory := NewDirectory(plchost)

	oauthClient := oauth.NewClientApp(&config, store)
	oauthClient.Dir = directory

	srv := Server{
		IsLocalHost: hostname == "",
		CookieStore: sessions.NewCookieStore([]byte(cctx.String("session-secret"))),
		OAuth:       oauthClient,
	}

	if redirect := cctx.String("redirect"); redirect != "" {
		parts := strings.Split(redirect, ":")
		if len(parts) != 2 {
			return cli.Exit("Invalid redirect", 1)
		}
		e.GET(parts[0], func(c echo.Context) error {
			return c.Redirect(301, parts[1])
		})
	}

	//These endpoint implement the verifier
	e.GET("/verifier-client-metadata.json", srv.VerifierClientMetadata)
	e.GET("/verifier/callback", srv.VerifierClientMetadata)

	// These endpoints are part of the "external" oauth interface, used by the Authorization Server (PDS or Entryway)
	e.GET("/oauth-client-metadata.json", srv.ClientMetadata) // must correspond to ClientConfig
	oauth := e.Group("/oauth")
	oauth.GET("/jwks.json", srv.JWKS)         // only needed for confidential clients. must match endpoint listed in client metadata
	oauth.GET("/callback", srv.OAuthCallback) // must correspond to ClientConfig
	// The AS redirects the user's browser to the callback endpoint, after auth (successful or otherwise)

	// These are user-facing endpoints for managing oauth session lifecycle, called via the user's browser.
	// The endpoint names here are arbitrary although they are also referenced in the HTML templates.
	oauth.GET("/login", srv.OAuthLogin)
	oauth.POST("/login", srv.OAuthLogin)
	oauth.GET("/logout", srv.OAuthLogout)
	oauth.GET("/authenticated", srv.Authenticated)

	for _, p := range cctx.StringSlice("proxy") {
		parts := strings.Split(p, ":")
		if len(parts) != 2 {
			return cli.Exit("Invalid proxy", 1)
		}
		proxy := Proxy{
			server:  &srv,
			prefix:  parts[0],
			service: parts[1],
		}
		api := e.Group(proxy.prefix)
		api.Any("/*", proxy.HandleProxyRequest)
	}

	for _, s := range cctx.StringSlice("static") {
		parts := strings.Split(s, ":")
		if len(parts) != 2 {
			return cli.Exit("Invalid static", 1)
		}
		static := e.Group(parts[0])
		static.Use(middleware.StaticWithConfig(middleware.StaticConfig{
			Root:   parts[1],
			Browse: false,
			HTML5:  true,
		}))
	}

	// http.HandleFunc("POST /oauth/fedcmlogin", srv.FedCMLogin)
	// http.HandleFunc("GET /oauth/walletlogin", srv.AtprotoWalletLogin)

	slog.Info("starting http server", "bind", li.Addr().String())
	return e.StartServer(httpServer)
}

func NewDirectory(plcHost string) identity.Directory {
	base := identity.BaseDirectory{
		PLCURL: plcHost,
		HTTPClient: http.Client{
			Timeout: time.Second * 10,
			Transport: &http.Transport{
				// would want this around 100ms for services doing lots of handle resolution. Impacts PLC connections as well, but not too bad.
				IdleConnTimeout: time.Millisecond * 1000,
				MaxIdleConns:    100,
			},
		},
		Resolver: net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Second * 3}
				return d.DialContext(ctx, network, address)
			},
		},
		TryAuthoritativeDNS: true,
		// primary Bluesky PDS instance only supports HTTP resolution method
		SkipDNSDomainSuffixes: []string{".bsky.social"},
		UserAgent:             "atproto-bff/" + versioninfo.Short(),
	}
	cached := identity.NewCacheDirectory(&base, 250_000, time.Hour*24, time.Minute*2, time.Minute*5)
	return &cached
}

func (s *Server) currentSessionDID(r *http.Request) (*syntax.DID, string, string) {
	sess, _ := s.CookieStore.Get(r, "oauth-demo")
	accountDID, ok := sess.Values["account_did"].(string)
	if !ok || accountDID == "" {
		return nil, "", ""
	}
	did, err := syntax.ParseDID(accountDID)
	if err != nil {
		return nil, "", ""
	}
	sessionID, ok := sess.Values["session_id"].(string)
	if !ok || sessionID == "" {
		return nil, "", ""
	}
	handle, ok := sess.Values["handle"].(string)
	if !ok || handle == "" {
		return nil, "", ""
	}

	return &did, sessionID, handle
}

func strPtr(raw string) *string {
	return &raw
}

func (s *Server) ClientMetadata(c echo.Context) error {
	slog.Info("client metadata request", "url", c.Request().URL, "host", c.Request().Host)

	meta := s.OAuth.Config.ClientMetadata()
	if s.OAuth.Config.IsConfidential() {
		meta.JWKSURI = strPtr(fmt.Sprintf("https://%s/oauth/jwks.json", c.Request().Host))
	}
	meta.ClientName = strPtr("Farmapps Explorer")
	meta.ClientURI = strPtr(fmt.Sprintf("https://%s", c.Request().Host))
	tosUri := "https://explorer.farmapps.eu/tos.html"
	meta.TosURI = &tosUri
	policyUri := "https://explorer.farmapps.eu/policy.html"
	meta.PolicyURI = &policyUri

	// internal consistency check
	if err := meta.Validate(s.OAuth.Config.ClientID); err != nil {
		slog.Error("validating client metadata", "err", err)
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, meta)
}

func (s *Server) JWKS(c echo.Context) error {
	body := s.OAuth.Config.PublicJWKS()
	return c.JSON(http.StatusOK, body)
}

func (s *Server) Homepage(c echo.Context) error {
	// attempts to load Session to display links
	did, sessionID, handle := s.currentSessionDID(c.Request())
	if did == nil {

		//PKCE challenge for fedcm
		verifier := secureRandomBase64(48)
		codeChallenge := oauth.S256CodeChallenge(verifier)

		tmplHome.Execute(c.Response(), TmplData{CodeChallenge: codeChallenge})
		return nil
	}

	_, err := s.OAuth.ResumeSession(c.Request().Context(), *did, sessionID)
	if err != nil {
		tmplHome.Execute(c.Response(), nil)
		return nil
	}
	tmplHome.Execute(c.Response(), TmplData{DID: did, Handle: handle})
	return nil
}

func (s *Server) Authenticated(c echo.Context) error {

	// attempts to load Session to display links
	did, sessionID, _ := s.currentSessionDID(c.Request())
	if did == nil {
		return c.JSON(http.StatusUnauthorized, false)
	}

	_, err := s.OAuth.ResumeSession(c.Request().Context(), *did, sessionID)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, false)
	}
	return c.JSON(http.StatusOK, true)
}

func (s *Server) OAuthLogin(c echo.Context) error {
	if c.Request().Method != "POST" {
		tmplLogin.Execute(c.Response(), nil)
		return nil
	}

	if err := c.Request().ParseForm(); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Errorf("parsing form data: %w", err))
	}

	username, _ := strings.CutPrefix(c.Request().PostFormValue("username"), "@")

	slog.Info("OAuthLogin", "client_id", s.OAuth.Config.ClientID, "callback_url", s.OAuth.Config.CallbackURL)

	redirectURL, err := s.OAuth.StartAuthFlow(c.Request().Context(), username)
	if err != nil {
		var oauthErr = fmt.Errorf("OAuth login failed: %w", err).Error()
		slog.Error(oauthErr)
		tmplLogin.Execute(c.Response(), TmplData{Error: oauthErr})
		return nil
	}

	return c.Redirect(http.StatusFound, redirectURL)
}

func (s *Server) OAuthCallback(c echo.Context) error {
	params := c.Request().URL.Query()
	slog.Info("received callback", "params", params)

	sessData, err := s.OAuth.ProcessCallback(c.Request().Context(), c.Request().URL.Query())
	if err != nil {
		var callbackErr = fmt.Errorf("failed processing oauth callback: %w", err).Error()
		slog.Error(callbackErr)
		tmplError.Execute(c.Response(), TmplData{Error: callbackErr})
		return nil
	}

	// retrieve session metadata
	oauthSess, err := s.OAuth.ResumeSession(c.Request().Context(), sessData.AccountDID, sessData.SessionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "not authenticated")
	}
	clnt := oauthSess.APIClient()
	var resp struct {
		Handle string `json:"handle"`
		// TODO: more fields?
	}
	if err := clnt.Get(c.Request().Context(), "com.atproto.server.getSession", nil, &resp); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// create signed cookie session, indicating account DID
	sess, _ := s.CookieStore.Get(c.Request(), "oauth-demo")
	if s.IsLocalHost {
		sess.Options.Secure = false
		sess.Options.SameSite = http.SameSiteLaxMode
	}
	sess.Values["account_did"] = sessData.AccountDID.String()
	sess.Values["session_id"] = sessData.SessionID
	sess.Values["handle"] = resp.Handle
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	slog.Info("login successful", "did", sessData.AccountDID.String())
	return c.Redirect(http.StatusFound, "/")
}

func (s *Server) OAuthLogout(c echo.Context) error {

	// revoke tokens and delete session from auth store
	did, sessionID, _ := s.currentSessionDID(c.Request())
	if did != nil {
		if err := s.OAuth.Logout(c.Request().Context(), *did, sessionID); err != nil {
			slog.Error("failed to delete session", "did", did, "err", err)
		}
	}

	// wipe all secure cookie session data
	sess, _ := s.CookieStore.Get(c.Request(), "oauth-demo")
	sess.Values = make(map[any]any)
	err := sess.Save(c.Request(), c.Response())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	slog.Info("logged out")
	return c.Redirect(http.StatusFound, "/")
}

func copyHeader(src http.Header, target http.Header, header string) {
	values := src.Values(header)
	for _, v := range values {
		target.Add(header, v)
	}
}

type Proxy struct {
	server  *Server
	prefix  string
	service string
}

func (p *Proxy) HandleProxyRequest(c echo.Context) error {

	did, sessionID, _ := p.server.currentSessionDID(c.Request())
	if did == nil {
		return c.JSON(http.StatusUnauthorized, false)
	}

	session, err := p.server.OAuth.ResumeSession(c.Request().Context(), *did, sessionID)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, false)
	}

	doc, err := p.server.OAuth.Dir.LookupDID(c.Request().Context(), session.Data.AccountDID)
	if err != nil {
		return c.String(http.StatusBadGateway, fmt.Sprintf("Bad gateway: did %s not found", session.Data.AccountDID))
	}

	endpoint := doc.GetServiceEndpoint(p.service)
	if endpoint == "" {
		return c.String(http.StatusBadGateway, fmt.Sprintf("Bad gateway: service %s not found for did %s", p.service, session.Data.AccountDID))
	}
	target, err := url.Parse(endpoint)
	if err != nil {
		return c.String(http.StatusBadGateway, fmt.Sprintf("Bad gateway: service %s not found for did %s", p.service, session.Data.AccountDID))
	}

	headers := http.Header{}
	copyHeader(c.Request().Header, headers, "accept")
	copyHeader(c.Request().Header, headers, "accept-encoding")
	copyHeader(c.Request().Header, headers, "accept-language")
	copyHeader(c.Request().Header, headers, "atproto-accept-labelers")
	copyHeader(c.Request().Header, headers, "atproto-accept-labelers")
	copyHeader(c.Request().Header, headers, "x-bsky-topics")
	copyHeader(c.Request().Header, headers, "content-type")
	copyHeader(c.Request().Header, headers, "content-encoding")
	copyHeader(c.Request().Header, headers, "content-length")
	copyHeader(c.Request().Header, headers, "origin")
	copyHeader(c.Request().Header, headers, "access-control-request-headers")
	copyHeader(c.Request().Header, headers, "access-control-request-method")

	rt := &RoundTripper{session: session, server: p.server}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Header = headers
		},
		Transport: rt,
	}

	proxy.ServeHTTP(c.Response(), c.Request())

	return nil
}

// VP Verifier

func (s *Server) VerifierClientMetadata(c echo.Context) error {
	slog.Info("verifier client metadata request", "url", c.Request().URL, "host", c.Request().Host)
	meta := VerifierClientMetadata{}
	meta.ClientID = fmt.Sprintf("https://%s/verifier-client-metadata.json", c.Request().Host)
	meta.Scope = "atproto "
	meta.ResponseTypes = append(meta.ResponseTypes, "vp_token")
	meta.RedirectURIs = append(meta.RedirectURIs, fmt.Sprintf("https://%s/verifier/callback", c.Request().Host))

	return c.JSON(http.StatusOK, meta)
}

func (s *Server) VerifierCallback(c echo.Context) error {
	params := c.Request().URL.Query()
	slog.Info("received verifier callback", "params", params)
	return nil
}

// copy a request URL and strip query params and fragment, for DPoP
func dpopURL(u *url.URL) string {
	u2 := *u
	u2.RawQuery = ""
	u2.ForceQuery = false
	u2.Fragment = ""
	u2.RawFragment = ""
	return u2.String()
}

// Parses a WWW-Authenticate response header to see if DPoP nonce update is indicated
func isNonceUpdateHeader(hdr string) bool {
	// Example from RFC9449:
	// WWW-Authenticate: DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"
	return strings.Contains(hdr, "error=\"use_dpop_nonce\"")
}

// Parses a WWW-Authenticate response header to see if access token has expired (needs refresh)
func isExpiredAccessTokenHeader(hdr string) bool {
	// Example from OAuth 2.1 draft:
	// WWW-Authenticate: Bearer error="invalid_token" error_description="The access token expired"
	// TODO: should this also look for "expired"?
	return strings.Contains(hdr, "error=\"invalid_token\"")
}

type RoundTripper struct {
	session *oauth.ClientSession
	server  *Server
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	// durl := dpopURL(req.URL)

	// accessToken, dpopNonce := rt.session.GetHostAccessData()
	accessToken, _ := rt.session.GetHostAccessData()

	// this method may need to retry twice, once for DPoP nonce update and once for token refresh
	var resp *http.Response
	var err error
	for range 1 {
		// dpopJWT, err := rt.session.NewHostDPoP(req.Method, durl)
		// if err != nil {
		// 	return nil, err
		// }
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		// req.Header.Set("Authorization", fmt.Sprintf("DPoP %s", accessToken))
		// req.Header.Set("DPoP", dpopJWT)

		resp, err = http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		// on Success, or many types of error, just return HTTP response
		// "Unauthorized" is HTTP status code 401
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" {
			return resp, nil
		}

		authHdr := resp.Header.Get("WWW-Authenticate")
		// dpopNonceHdr := resp.Header.Get("DPoP-Nonce")

		// // if DPoP nonce changed, update and retry request
		// if isNonceUpdateHeader(authHdr) && dpopNonceHdr != "" {
		// 	// TODO: validate or normalize dpopNonceHdr in some way? eg minimum length
		// 	if dpopNonceHdr == dpopNonce {
		// 		return nil, fmt.Errorf("OAuth PDS DPoP nonce failure, but no new nonce supplied")
		// 	}

		// 	// persist new nonce value via callback
		// 	rt.session.UpdateHostDPoPNonce(req.Context(), dpopNonceHdr)
		// 	dpopNonce = dpopNonceHdr

		// 	// retry request
		// 	retry := req.Clone(req.Context())
		// 	if req.GetBody != nil {
		// 		retry.Body, err = req.GetBody()
		// 		if err != nil {
		// 			return nil, fmt.Errorf("GetBody failed when retrying API request: %w", err)
		// 		}
		// 	}
		// 	req = retry
		// 	continue
		// }

		// if access token expired, refresh and retry
		if isExpiredAccessTokenHeader(authHdr) {
			accessToken, err = rt.session.RefreshTokens(req.Context())
			if err != nil {
				return nil, fmt.Errorf("failed to refresh OAuth tokens: %w", err)
			}

			retry := req.Clone(req.Context())
			if req.GetBody != nil {
				retry.Body, err = req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("GetBody failed when retrying API request: %w", err)
				}
			}
			req = retry
			continue
		}

		// otherwise, this was some other type of auth failure; just return the full response
		// NOTE: in theory we could return an APIError here instead
		return resp, nil
	}

	return nil, fmt.Errorf("OAuth client ran out of request retries")
}
