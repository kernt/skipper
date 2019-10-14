package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/stretchr/testify/assert"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/secrets"
	"github.com/zalando/skipper/secrets/secrettest"
)

const (
	testRedirectUrl = "http://redirect-somewhere.com/some-path?arg=param"
)

func createOIDCServer() *httptest.Server {
	s := `{
 "issuer": "https://accounts.google.com",
 "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
 "token_endpoint": "https://oauth2.googleapis.com/token",
 "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
 "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
 "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
 "response_types_supported": [
  "code",
  "token",
  "id_token",
  "code token",
  "code id_token",
  "token id_token",
  "code token id_token",
  "none"
 ],
 "subject_types_supported": [
  "public"
 ],
 "id_token_signing_alg_values_supported": [
  "RS256"
 ],
 "scopes_supported": [
  "openid",
  "email",
  "profile"
 ],
 "token_endpoint_auth_methods_supported": [
  "client_secret_post",
  "client_secret_basic"
 ],
 "claims_supported": [
  "aud",
  "email",
  "email_verified",
  "exp",
  "family_name",
  "given_name",
  "iat",
  "iss",
  "locale",
  "name",
  "picture",
  "sub"
 ],
 "code_challenge_methods_supported": [
  "plain",
  "S256"
 ]
}`
	var oidcServer *httptest.Server
	oidcServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		println(r.RequestURI)
		switch r.RequestURI {
		case "/.well-known/openid-configuration":

			st := strings.Replace(s, "https://accounts.google.com", oidcServer.URL, -1)
			st = strings.Replace(st, "https://oauth2.googleapis.com", oidcServer.URL, -1)
			st = strings.Replace(st, "https://www.googleapis.com", oidcServer.URL, -1)
			st = strings.Replace(st, "https://openidconnect.googleapis.com", oidcServer.URL, -1)
			_, _ = w.Write([]byte(st))
		case "/o/oauth2/v2/auth":
			w.WriteHeader(120)
		case "/token":
			w.WriteHeader(121)
		case "/v1/userinfo":
			w.WriteHeader(122)
		case "/revoke":
			w.WriteHeader(123)
		case "/oauth2/v3/certs":
			w.WriteHeader(124)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	return oidcServer
}

func makeTestingFilter(claims []string) (*tokenOidcFilter, error) {
	r := secrettest.NewTestRegistry()
	encrypter, err := r.NewEncrypter("key")
	if err != nil {
		return nil, err
	}

	f := &tokenOidcFilter{
		typ:    checkOIDCAnyClaims,
		claims: claims,
		config: &oauth2.Config{
			ClientID: "test",
			Endpoint: google.Endpoint,
		},
		encrypter: encrypter,
	}
	return f, err
}

func TestEncryptDecryptState(t *testing.T) {
	f, err := makeTestingFilter([]string{})
	assert.NoError(t, err, "could not refresh ciphers")

	nonce, err := f.encrypter.CreateNonce()
	if err != nil {
		t.Errorf("Failed to create nonce: %v", err)
	}

	// enc
	state, err := createState(nonce, testRedirectUrl)
	assert.NoError(t, err, "failed to create state")
	stateEnc, err := f.encrypter.Encrypt(state)
	if err != nil {
		t.Errorf("Failed to encrypt data block: %v", err)
	}
	stateEncHex := fmt.Sprintf("%x", stateEnc)

	// dec
	stateQueryEnc := make([]byte, len(stateEncHex))
	if _, err := fmt.Sscanf(stateEncHex, "%x", &stateQueryEnc); err != nil && err != io.EOF {
		t.Errorf("Failed to read hex string: %v", err)
	}
	stateQueryPlain, err := f.encrypter.Decrypt(stateQueryEnc)
	if err != nil {
		t.Errorf("token from state query is invalid: %v", err)
	}

	// test same
	if len(stateQueryPlain) != len(state) {
		t.Errorf("encoded and decoded states do no match")
	}
	for i, b := range stateQueryPlain {
		if b != state[i] {
			t.Errorf("encoded and decoded states do no match")
			break
		}
	}
	decOauthState, err := extractState(stateQueryPlain)
	if err != nil {
		t.Errorf("failed to recreate state from decrypted byte array.")
	}
	ts := time.Unix(decOauthState.Validity, 0)
	if time.Now().After(ts) {
		t.Errorf("now is after time from state but should be before: %s", ts)
	}

	if decOauthState.RedirectUrl != testRedirectUrl {
		t.Errorf("Decrypted Redirect Url %s does not match input %s", decOauthState.RedirectUrl, testRedirectUrl)
	}
}

func TestOidcValidateAllClaims(t *testing.T) {
	oidcFilter, err := makeTestingFilter([]string{"uid", "email", "hd"})
	assert.NoError(t, err, "error creating test filter")
	assert.True(t, oidcFilter.validateAllClaims(
		map[string]interface{}{"uid": "test", "email": "test@example.org", "hd": "example.org"}),
		"claims should be valid but filter returned false.")
	assert.False(t, oidcFilter.validateAllClaims(
		map[string]interface{}{}), "claims are invalid but filter returned true.")
	assert.False(t, oidcFilter.validateAllClaims(
		map[string]interface{}{"uid": "test", "email": "test@example.org"}),
		"claims are invalid but filter returned true.")
	assert.True(t, oidcFilter.validateAllClaims(
		map[string]interface{}{"uid": "test", "email": "test@example.org", "hd": "something.com", "empty": ""}),
		"claims are valid but filter returned false.")
}

func TestOidcValidateAnyClaims(t *testing.T) {
	oidcFilter, err := makeTestingFilter([]string{"uid", "email", "hd"})
	assert.NoError(t, err, "error creating test filter")
	assert.True(t, oidcFilter.validateAnyClaims(
		map[string]interface{}{"uid": "test", "email": "test@example.org", "hd": "example.org"}),
		"claims should be valid but filter returned false.")
	assert.False(t, oidcFilter.validateAnyClaims(
		map[string]interface{}{}), "claims are invalid but filter returned true.")
	assert.True(t, oidcFilter.validateAnyClaims(
		map[string]interface{}{"uid": "test", "email": "test@example.org"}),
		"claims are invalid but filter returned true.")
	assert.True(t, oidcFilter.validateAnyClaims(
		map[string]interface{}{"uid": "test", "email": "test@example.org", "hd": "something.com", "empty": ""}),
		"claims are valid but filter returned false.")
}

func TestExtractDomainFromHost(t *testing.T) {

	for _, ht := range []struct {
		given    string
		expected string
	}{
		{"localhost", "localhost"},
		{"localhost.localdomain", "localhost.localdomain"},
		{"www.example.local", "example.local"},
		{"one.two.three.www.example.local", "two.three.www.example.local"},
		{"localhost:9990", "localhost"},
		{"www.example.local:9990", "example.local"},
		{"127.0.0.1:9090", "127.0.0.1"},
	} {
		t.Run(fmt.Sprintf("test:%s", ht.given), func(t *testing.T) {
			got := extractDomainFromHost(ht.given)
			assert.Equal(t, ht.expected, got)
		})
	}
}

func TestNewOidc(t *testing.T) {
	reg := secrets.NewRegistry()
	for _, tt := range []struct {
		name string
		args string
		f    func(string, *secrets.Registry) filters.Spec
		want *tokenOidcSpec
	}{
		{
			name: "test UserInfo",
			args: "/foo",
			f:    NewOAuthOidcUserInfos,
			want: &tokenOidcSpec{typ: checkOIDCUserInfo, SecretsFile: "/foo", secretsRegistry: reg},
		},
		{
			name: "test AnyClaims",
			args: "/foo",
			f:    NewOAuthOidcAnyClaims,
			want: &tokenOidcSpec{typ: checkOIDCAnyClaims, SecretsFile: "/foo", secretsRegistry: reg},
		},
		{
			name: "test AllClaims",
			args: "/foo",
			f:    NewOAuthOidcAllClaims,
			want: &tokenOidcSpec{typ: checkOIDCAllClaims, SecretsFile: "/foo", secretsRegistry: reg},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f(tt.args, reg); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Failed to create object: Want %v, got %v", tt.want, got)
			}
		})
	}

}

func TestCreateFilterOIDC(t *testing.T) {
	for _, tt := range []struct {
		name    string
		args    []interface{}
		want    filters.Filter
		wantErr bool
	}{
		{
			name:    "test no args",
			args:    nil,
			wantErr: true,
		},
		{
			name:    "test wrong number of args",
			args:    []interface{}{"s"},
			wantErr: true,
		},
		{
			name:    "test wrong number of args",
			args:    []interface{}{"s", "d"},
			wantErr: true,
		},
		{
			name:    "test wrong number of args",
			args:    []interface{}{"s", "d", "a"},
			wantErr: true,
		},
		{
			name:    "test wrong args",
			args:    []interface{}{"s", "d", "a", "f"},
			wantErr: true,
		},
		{
			name:    "test args",
			args:    []interface{}{"http://localhost:12345/", "", "", "http://localhost:12345redirect", "", ""},
			wantErr: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			spec := &tokenOidcSpec{typ: checkOIDCAllClaims, SecretsFile: "/foo"}

			got, err := spec.CreateFilter(tt.args)
			if tt.wantErr && err == nil {
				t.Errorf("Failed to get error but wanted, got: %v", got)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Failed to get no error: %v", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Failed to create filter: Want %v, got %v", tt.want, got)
			}
		})
	}

}

func TestOIDCSetup(t *testing.T) {
	for _, tc := range []struct {
		msg            string
		provider       string
		client         string
		clientsecret   string
		callback       string
		scopes         []string
		claims         map[string]string
		authType       roleCheckType // checkOIDCAnyClaims checkOIDCAllClaims
		authCodeOption []oauth2.AuthCodeOption
		expected       int
		expectErr      bool
	}{{
		msg:          "wrong provider, no callback",
		provider:     "no url",
		client:       "myclient",
		clientsecret: "mysec",
		callback:     "",
		expectErr:    true,
	}, {
		msg:          "no provider, but no callback",
		client:       "myclient",
		clientsecret: "mysec",
		callback:     "",
		expectErr:    false,
	}} {
		t.Run(tc.msg, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("OK"))
			}))
			t.Logf("backend listener: %v", backend.Listener)
			//var dat *oidc.Provider
			oidcServer := createOIDCServer()
			t.Logf("oidc/auth server listener: %v", oidcServer.Listener)

			// create filter
			sargs := []interface{}{
				tc.client,
				tc.clientsecret,
				tc.callback,
			}
			if tc.provider != "" {
				sargs = append([]interface{}{oidcServer.URL}, sargs...)
			} else {
				sargs = append([]interface{}{tc.provider}, sargs...)
			}

			sargs = append(sargs, strings.Join(tc.scopes, " "))
			switch tc.authType {
			case checkOIDCAnyClaims:
				fallthrough
			case checkOIDCAllClaims:
				claims := make([]string, 0, 2*len(tc.claims))
				for k, v := range tc.claims {
					claims = append(claims, k, v)
				}
				sargs = append(sargs, strings.Join(claims, " "))
			}

			spec := &tokenOidcSpec{
				typ:             tc.authType,
				SecretsFile:     "/tmp/foo", // TODO(sszuecs): random
				secretsRegistry: secrettest.NewTestRegistry(),
			}
			fr := make(filters.Registry)

			fr.Register(spec)

			f, err := spec.CreateFilter(sargs)
			if err != nil && !tc.expectErr {
				t.Fatalf("Failed to create filter: %v", err)
			} else if tc.expectErr {
				t.Fatalf("Want error but got filter: %v", f)
			}

			fOIDC := f.(*tokenOidcFilter)
			defer fOIDC.Close()

			t.Logf("sargs: %v", sargs)

			/////////////////////////////////////

			// //u := oidcServer.URL + tc.authBaseURL

			/////////////////////////////////////
			//                         fr := make(filters.Registry)
			//                         fr.Register(spec)
			//                         r := &eskip.Route{Filters: []*eskip.Filter{{Name: spec.Name(), Args: args}}, Backend: backend.U
			// RL}

			//                         proxy := proxytest.New(fr, r)
			//                         defer proxy.Close()
			//                         reqURL, err := url.Parse(proxy.URL)
			//                         if err != nil {
			//                                 t.Errorf("Failed to parse url %s: %v", proxy.URL, err)
			//                         }

			//                         req, err := http.NewRequest("GET", reqURL.String(), nil)
			//                         if err != nil {
			//                                 t.Error(err)
			//                                 return
			//                         }
			//                         req.Header.Set(authHeaderName, authHeaderPrefix+testToken)

			//                         resp, err := http.DefaultClient.Do(req)

			//                         if err != nil {
			//                                 t.Error(err)
			//                                 return
			//                         }

			//                         defer resp.Body.Close()

			//                         if resp.StatusCode != ti.expected {
			//                                 t.Errorf("auth filter failed got=%d, expected=%d, route=%s", resp.StatusCode, ti.expected, r)
			//                                 buf := make([]byte, resp.ContentLength)
			//                                 resp.Body.Read(buf)
			//                         }

		})
	}
}
