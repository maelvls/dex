// Package google implements logging in through Google's OpenID Connect provider.
package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/exp/slices"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	"github.com/dexidp/dex/connector"
	pkg_groups "github.com/dexidp/dex/pkg/groups"
	"github.com/dexidp/dex/storage"
)

const (
	issuerURL                  = "https://accounts.google.com"
	wildcardDomainToAdminEmail = "*"
)

// Config holds configuration options for Google logins.
type Config struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`

	Scopes []string `json:"scopes"` // defaults to "profile" and "email"

	// Optional list of whitelisted domains
	// If this field is nonempty, only users from a listed domain will be allowed to log in
	HostedDomains []string `json:"hostedDomains"`

	// Optional list of whitelisted groups
	// If this field is nonempty, only users from a listed group will be allowed to log in
	Groups []string `json:"groups"`

	// Optional path to service account json
	// If nonempty, and groups claim is made, will use authentication from file to
	// check groups with the admin directory api
	ServiceAccountFilePath string `json:"serviceAccountFilePath"`

	// Deprecated: Use DomainToAdminEmail
	AdminEmail string

	// Required if ServiceAccountFilePath
	// The map workspace domain to email of a GSuite super user which the service account will impersonate
	// when listing groups
	DomainToAdminEmail map[string]string

	// If this field is true, fetch direct group membership and transitive group membership
	FetchTransitiveGroupMembership bool `json:"fetchTransitiveGroupMembership"`

	// Optional value for the prompt parameter, defaults to consent when offline_access
	// scope is requested
	PromptType *string `json:"promptType"`
}

// Open returns a connector which can be used to login users through Google.
func (c *Config) Open(id string, logger *slog.Logger) (conn connector.Connector, err error) {
	logger = logger.With(slog.Group("connector", "type", "google", "id", id))
	if c.AdminEmail != "" {
		logger.Warn(`use "domainToAdminEmail.*" option instead of "adminEmail"`, "deprecated", true)
		if c.DomainToAdminEmail == nil {
			c.DomainToAdminEmail = make(map[string]string)
		}

		c.DomainToAdminEmail[wildcardDomainToAdminEmail] = c.AdminEmail
	}
	ctx, cancel := context.WithCancel(context.Background())

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	scopes := []string{oidc.ScopeOpenID}
	if len(c.Scopes) > 0 {
		scopes = append(scopes, c.Scopes...)
	} else {
		scopes = append(scopes, "profile", "email")
	}

	adminSrv := make(map[string]*admin.Service)

	// We know impersonation is required when using a service account credential
	// TODO: or is it?
	if len(c.DomainToAdminEmail) == 0 && c.ServiceAccountFilePath != "" {
		cancel()
		return nil, fmt.Errorf("directory service requires the domainToAdminEmail option to be configured")
	}

	if (len(c.DomainToAdminEmail) > 0) || slices.Contains(scopes, "groups") {
		for domain, adminEmail := range c.DomainToAdminEmail {
			srv, err := createDirectoryService(c.ServiceAccountFilePath, adminEmail, logger)
			if err != nil {
				cancel()
				return nil, fmt.Errorf("could not create directory service: %v", err)
			}

			adminSrv[domain] = srv
		}
	}

	promptType := "consent"
	if c.PromptType != nil {
		promptType = *c.PromptType
	}

	clientID := c.ClientID
	return &googleConnector{
		redirectURI: c.RedirectURI,
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
			RedirectURL:  c.RedirectURI,
		},
		verifier: provider.Verifier(
			&oidc.Config{ClientID: clientID},
		),
		logger:                         logger,
		cancel:                         cancel,
		hostedDomains:                  c.HostedDomains,
		groups:                         c.Groups,
		serviceAccountFilePath:         c.ServiceAccountFilePath,
		domainToAdminEmail:             c.DomainToAdminEmail,
		fetchTransitiveGroupMembership: c.FetchTransitiveGroupMembership,
		adminSrv:                       adminSrv,
		promptType:                     promptType,
	}, nil
}

var (
	_ connector.CallbackConnector = (*googleConnector)(nil)
	_ connector.RefreshConnector  = (*googleConnector)(nil)
)

type googleConnector struct {
	redirectURI                    string
	oauth2Config                   *oauth2.Config
	verifier                       *oidc.IDTokenVerifier
	cancel                         context.CancelFunc
	logger                         *slog.Logger
	hostedDomains                  []string
	groups                         []string
	serviceAccountFilePath         string
	domainToAdminEmail             map[string]string
	fetchTransitiveGroupMembership bool
	adminSrv                       map[string]*admin.Service
	promptType                     string
}

func (c *googleConnector) Close() error {
	c.cancel()
	return nil
}

func (c *googleConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	var opts []oauth2.AuthCodeOption
	if len(c.hostedDomains) > 0 {
		preferredDomain := c.hostedDomains[0]
		if len(c.hostedDomains) > 1 {
			preferredDomain = "*"
		}
		opts = append(opts, oauth2.SetAuthURLParam("hd", preferredDomain))
	}

	if s.OfflineAccess {
		opts = append(opts, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", c.promptType))
	}

	return c.oauth2Config.AuthCodeURL(state, opts...), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *googleConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}
	token, err := c.oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("google: failed to get token: %v", err)
	}

	return c.createIdentity(r.Context(), identity, s, token)
}

func (c *googleConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	t := &oauth2.Token{
		RefreshToken: string(identity.ConnectorData),
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.oauth2Config.TokenSource(ctx, t).Token()
	if err != nil {
		return identity, fmt.Errorf("google: failed to get token: %v", err)
	}

	return c.createIdentity(ctx, identity, s, token)
}

func (c *googleConnector) createIdentity(ctx context.Context, identity connector.Identity, s connector.Scopes, token *oauth2.Token) (connector.Identity, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity, errors.New("google: no id_token in token response")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return identity, fmt.Errorf("google: failed to verify ID Token: %v", err)
	}

	var claims struct {
		Username      string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HostedDomain  string `json:"hd"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return identity, fmt.Errorf("oidc: failed to decode claims: %v", err)
	}

	if len(c.hostedDomains) > 0 {
		found := false
		for _, domain := range c.hostedDomains {
			if claims.HostedDomain == domain {
				found = true
				break
			}
		}

		if !found {
			return identity, fmt.Errorf("oidc: unexpected hd claim %v", claims.HostedDomain)
		}
	}

	var groups []string
	if s.Groups && len(c.adminSrv) > 0 {
		checkedGroups := make(map[string]struct{})
		groups, err = c.getGroups(claims.Email, c.fetchTransitiveGroupMembership, checkedGroups)
		if err != nil {
			return identity, fmt.Errorf("google: could not retrieve groups: %v", err)
		}

		if len(c.groups) > 0 {
			groups = pkg_groups.Filter(groups, c.groups)
			if len(groups) == 0 {
				return identity, fmt.Errorf("google: user %q is not in any of the required groups", claims.Username)
			}
		}
	}

	identity = connector.Identity{
		UserID:        idToken.Subject,
		Username:      claims.Username,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		ConnectorData: []byte(token.RefreshToken),
		Groups:        groups,
	}
	return identity, nil
}

// getGroups creates a connection to the admin directory service and lists
// all groups the user is a member of
func (c *googleConnector) getGroups(email string, fetchTransitiveGroupMembership bool, checkedGroups map[string]struct{}) ([]string, error) {
	var userGroups []string
	var err error
	groupsList := &admin.Groups{}
	domain := c.extractDomainFromEmail(email)
	adminSrv, err := c.findAdminService(domain)
	if err != nil {
		return nil, err
	}

	for {
		groupsList, err = adminSrv.Groups.List().
			UserKey(email).PageToken(groupsList.NextPageToken).Do()
		if err != nil {
			return nil, fmt.Errorf("could not list groups: %v", err)
		}

		for _, group := range groupsList.Groups {
			if _, exists := checkedGroups[group.Email]; exists {
				continue
			}

			checkedGroups[group.Email] = struct{}{}
			// TODO (joelspeed): Make desired group key configurable
			userGroups = append(userGroups, group.Email)

			if !fetchTransitiveGroupMembership {
				continue
			}

			// getGroups takes a user's email/alias as well as a group's email/alias
			transitiveGroups, err := c.getGroups(group.Email, fetchTransitiveGroupMembership, checkedGroups)
			if err != nil {
				return nil, fmt.Errorf("could not list transitive groups: %v", err)
			}

			userGroups = append(userGroups, transitiveGroups...)
		}

		if groupsList.NextPageToken == "" {
			break
		}
	}

	return userGroups, nil
}

func (c *googleConnector) findAdminService(domain string) (*admin.Service, error) {
	adminSrv, ok := c.adminSrv[domain]
	if !ok {
		adminSrv, ok = c.adminSrv[wildcardDomainToAdminEmail]
		c.logger.Debug("using wildcard admin email to fetch groups", "admin_email", c.domainToAdminEmail[wildcardDomainToAdminEmail])
	}

	if !ok {
		return nil, fmt.Errorf("unable to find super admin email, domainToAdminEmail for domain: %s not set, %s is also empty", domain, wildcardDomainToAdminEmail)
	}

	return adminSrv, nil
}

// extracts the domain name from an email input. If the email is valid, it returns the domain name after the "@" symbol.
// However, in the case of a broken or invalid email, it returns a wildcard symbol.
func (c *googleConnector) extractDomainFromEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at >= 0 {
		_, domain := email[:at], email[at+1:]

		return domain
	}

	return wildcardDomainToAdminEmail
}

// getCredentialsFromFilePath reads and returns the service account credentials from the file at the provided path.
// If an error occurs during the read, it is returned.
func getCredentialsFromFilePath(serviceAccountFilePath string) ([]byte, error) {
	jsonCredentials, err := os.ReadFile(serviceAccountFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading credentials from file: %v", err)
	}
	return jsonCredentials, nil
}

// getCredentialsFromDefault retrieves the application's default credentials.
// If the default credential is empty, it attempts to create a new service with metadata credentials.
// If successful, it returns the service and nil error.
// If unsuccessful, it returns the error and a nil service.
func getCredentialsFromDefault(ctx context.Context, email string, logger *slog.Logger) ([]byte, *admin.Service, error) {
	credential, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch application default credentials: %w", err)
	}

	if credential.JSON == nil {
		logger.Info("JSON is empty, using flow for GCE")
		service, err := createServiceWithMetadataServer(ctx, email, logger)
		if err != nil {
			return nil, nil, err
		}
		return nil, service, nil
	}

	return credential.JSON, nil, nil
}

// createServiceWithMetadataServer creates a new service using metadata server.
// If an error occurs during the process, it is returned along with a nil service.
func createServiceWithMetadataServer(ctx context.Context, adminEmail string, logger *slog.Logger) (*admin.Service, error) {
	serviceAccountEmail, err := metadata.EmailWithContext(ctx, "default")
	logger.Info("discovered serviceAccountEmail", "email", serviceAccountEmail)

	if err != nil {
		return nil, fmt.Errorf("unable to get service account email from metadata server: %v", err)
	}

	config := impersonate.CredentialsConfig{
		TargetPrincipal: serviceAccountEmail,
		Scopes:          []string{admin.AdminDirectoryGroupReadonlyScope},
		Lifetime:        0,
		Subject:         adminEmail,
	}

	tokenSource, err := impersonate.CredentialsTokenSource(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to impersonate with %s, error: %v", adminEmail, err)
	}

	return admin.NewService(ctx, option.WithHTTPClient(oauth2.NewClient(ctx, tokenSource)))
}

// createDirectoryService sets up super user impersonation and creates an admin client for calling
// the google admin api. If no serviceAccountFilePath is defined, the application default credential
// is used.
func createDirectoryService(serviceAccountFilePath, email string, logger *slog.Logger) (service *admin.Service, err error) {
	var jsonCredentials []byte

	ctx := context.Background()
	if serviceAccountFilePath == "" {
		logger.Warn("the application default credential is used since the service account file path is not used")
		jsonCredentials, service, err = getCredentialsFromDefault(ctx, email, logger)
		if err != nil {
			return
		}
		if service != nil {
			return
		}
	} else {
		jsonCredentials, err = getCredentialsFromFilePath(serviceAccountFilePath)
		if err != nil {
			return
		}
	}
	config, err := google.JWTConfigFromJSON(jsonCredentials, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse client secret file to config: %v", err)
	}

	// Only attempt impersonation when there is a user configured
	if email != "" {
		config.Subject = email
	}

	return admin.NewService(ctx, option.WithHTTPClient(config.Client(ctx)))
}

var _ = (connector.PayloadExtender)(&googleConnector{})

type User struct {
	TwoFAStatus bool   `json:"2fa_status"`
	Description string `json:"description"`
	Email       string `json:"email"`
	Expired     string `json:"expired"`
	Name        string `json:"name"`
}

var (
	mu    *sync.Mutex
	users []User
)

func init() {
	passwd := os.Getenv("SYNO_PASSWD")
	if passwd == "" {
		panic("SYNO_PASSWD not set, this is required to connect to Synology")
	}

	user := os.Getenv("SYNO_USER")
	if user == "" {
		panic("SYNO_USER not set, this is required to connect to Synology")
	} else {
		log.Printf("SYNO_USER was set set '%s', using it to connect to Synology", user)
	}

	synoURL := os.Getenv("SYNO_URL")
	if synoURL == "" {
		log.Println("SYNO_URL not set, defaulting to http://localhost:5000")
		synoURL = "http://localhost:5000"
	} else {
		log.Printf("SYNO_URL was set, using '%s' to connect to Synology", synoURL)
	}

	mu = &sync.Mutex{}

	// Let's refresh the user list every hour. Use a backoff strategy in case of
	// errors.
	go func() {
		log.Println("Starting Synology Users refresh loop. This will run every hour.")
		for {
			var list []User
			err := retryWithBackoff(10, 5*time.Second, 1*time.Hour, func() error {
				// If we fail to get the users, we will retry with exponential backoff.
				var err error
				ctx := context.Background()
				list, err = getSynologyUsers(ctx, user, passwd, synoURL)
				if isNotRetriable(err) {
					// Crash to signify to the user that they need to fix the
					// error.
					log.Fatalf("non-retryable error while getting Synology users: %v", err)
				}
				if err != nil {
					return fmt.Errorf("while getting Synology users: %w", err)
				}

				return nil
			})
			if err != nil {
				log.Printf("failed to get Synology users after retries: %v", err)
				continue
			}

			mu.Lock()
			users = list
			mu.Unlock()

			time.Sleep(60 * time.Minute)
		}
	}()
}

// Exponential backoff, no need for jitter.
func retryWithBackoff(maxRetries int, baseDelay time.Duration, maxDelay time.Duration, fn func() error) error {
	delay := baseDelay

	for i := range maxRetries {
		err := fn()
		if err == nil {
			return nil
		}

		// Exponential backoff, no need for jitter.
		sleep := min(delay, maxDelay)

		fmt.Printf("retry %d failed: %v, sleeping %v\n", i+1, err, sleep)
		time.Sleep(sleep)

		// Double the delay for next iteration.
		delay *= 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}

	return errors.New("all retries failed")
}

func getSynologyUsers(ctx context.Context, synoUser, synoPasswd, synoURL string) ([]User, error) {
	mu.Lock()
	defer mu.Unlock()

	// First, get the session cookie.
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	client := &http.Client{Jar: jar}

	// URL-encode the password.
	form := url.Values{}
	form.Add("api", "SYNO.API.Auth")
	form.Add("method", "login")
	form.Add("version", "6")
	form.Add("account", synoUser)
	form.Add("passwd", synoPasswd)
	req, err := http.NewRequestWithContext(ctx, "POST", synoURL+"/webapi/entry.cgi", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request %s: %w", req.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bytes, _ := io.ReadAll(resp.Body)
		return nil, httpErr{fmt.Errorf("unexpected status code: %d, body: %v", resp.StatusCode, string(bytes)), resp.StatusCode}
	}

	// Now, get the user list.
	form = url.Values{}
	form.Add("api", "SYNO.Core.User")
	form.Add("method", "list")
	form.Add("version", "1")
	form.Add("type", "local")
	form.Add("offset", "0")
	form.Add("limit", "-1")
	form.Add("additional", `["email","description","expired","2fa_status"]`)
	req, err = http.NewRequestWithContext(ctx, "POST", synoURL+"/webapi/entry.cgi", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request %s: %w", req.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bytes, _ := io.ReadAll(resp.Body)
		return nil, httpErr{fmt.Errorf("unexpected status code: %d, body: %v", resp.StatusCode, string(bytes)), resp.StatusCode}
	}

	// Now, parse the response.
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Example:
	//
	//    {
	//      "data": {
	//        "offset": 0,
	//        "total": 9,
	//        "users": [
	//          {
	//            "2fa_status": false,
	//            "description": "Maël Valais",
	//            "email": "mael.valais@gmail.com",
	//            "expired": "normal",
	//            "name": "mael.valais"
	//        ]
	//      },
	//      "success": true
	//    }

	type Data struct {
		Offset int    `json:"offset"`
		Total  int    `json:"total"`
		Users  []User `json:"users"`
	}

	var response struct {
		Data    Data   `json:"data"`
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	err = json.Unmarshal(bytes, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("error: %s: body: %s", resp.Status, string(bytes))
	}

	return response.Data.Users, nil
}

func (c *googleConnector) ExtendPayload(ctx context.Context, scopes []string, claims storage.Claims, payload []byte, cdata []byte) ([]byte, error) {
	email := claims.Email
	c.logger.Debug("ExtendPayload called", "claims", claims, "payload", string(payload), "email", email)

	// Now, search the email in the list of users.
	var usr User
	mu.Lock()
	for _, u := range users {
		if u.Email == email {
			usr = u
			break
		}
	}
	mu.Unlock()

	if usr == (User{}) {
		return payload, fmt.Errorf("could not find user with email %s", email)
	}

	// Now, extend the payload with the user data.
	var originalClaims map[string]any
	err := json.Unmarshal(payload, &originalClaims)
	if err != nil {
		return payload, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	originalClaims["username"] = usr.Name
	extendedPayload, err := json.Marshal(originalClaims)
	if err != nil {
		return payload, fmt.Errorf("failed to marshal claims: %w", err)
	}
	c.logger.Debug("Payload was extended", "payload", extendedPayload)
	return extendedPayload, nil
}

type httpErr struct {
	err  error
	code int
}

func (e httpErr) Error() string {
	return fmt.Sprintf("%d %v", e.code, e.err)
}

func (e httpErr) Unwrap() error {
	return e.err
}

func (e httpErr) Is(target error) bool {
	if _, ok := target.(httpErr); ok {
		return true
	}
	return false
}

func isNotRetriable(err error) bool {
	var httpErr httpErr
	if errors.As(err, &httpErr) {
		switch httpErr.code {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusConflict, http.StatusGone, http.StatusPreconditionFailed, http.StatusUnprocessableEntity:
			return true
		}
	}
	return false
}
