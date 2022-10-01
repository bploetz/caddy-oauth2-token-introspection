package oauth2_token_introspection

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(OAuth2TokenIntrospection{})
	httpcaddyfile.RegisterHandlerDirective("oauth2_token_introspection", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var o OAuth2TokenIntrospection
	err := o.UnmarshalCaddyfile(h.Dispenser)

	return o, err
}

func (o *OAuth2TokenIntrospection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.NextArg()
	for d.NextBlock(0) {
		switch d.Val() {
		case "authentication_strategy":
			if !d.AllArgs(&o.AuthenticationStrategy) {
				return d.ArgErr()
			}
		case "token_location":
			if !d.AllArgs(&o.TokenLocation) {
				return d.ArgErr()
			}
		case "introspection_endpoint":
			if !d.AllArgs(&o.IntrospectionEndpoint) {
				return d.ArgErr()
			}
		case "introspection_client_id":
			if !d.AllArgs(&o.IntrospectionClientID) {
				return d.ArgErr()
			}
		case "introspection_client_secret":
			if !d.AllArgs(&o.IntrospectionClientSecret) {
				return d.ArgErr()
			}
		case "set_header":
			if o.InboundHeaders == nil {
				o.InboundHeaders = make(map[string]string)
			}
			var key, val string
			for d.AllArgs(&key, &val) {
				o.InboundHeaders[key] = val
			}
		default:
			return d.Errf("%s not a valid oauth2_token_introspection option", d.Val())
		}
	}

	return nil
}

// OAuth2TokenIntrospection is a Caddy http.handlers Module for authorizing requests via OAuth2 Token Introspection
type OAuth2TokenIntrospection struct {
	logger                    *zap.Logger
	AuthenticationStrategy    string            `json:"authentication_strategy"`
	TokenLocation             string            `json:"token_location"`
	IntrospectionEndpoint     string            `json:"introspection_endpoint"`
	IntrospectionClientID     string            `json:"introspection_client_id"`
	IntrospectionClientSecret string            `json:"introspection_client_secret"`
	InboundHeaders            map[string]string `json:"inbound_headers"`
}

const ClientCredentialsAuthenticationStrategy = "client_credentials"
const BearerTokenAuthenticationStrategy = "bearer_token"

var authenticationStrategies = map[string]bool{
	ClientCredentialsAuthenticationStrategy: true,
	BearerTokenAuthenticationStrategy:       true,
}

const BearerTokenLocation = "bearer_token"

var tokenLocations = map[string]bool{
	BearerTokenLocation: true,
}

// CaddyModule returns the Caddy module information.
func (OAuth2TokenIntrospection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oauth2_token_introspection",
		New: func() caddy.Module { return new(OAuth2TokenIntrospection) },
	}
}

// Provision sets up the module.
func (o *OAuth2TokenIntrospection) Provision(ctx caddy.Context) error {
	o.logger = ctx.Logger()
	o.logger.Info("http.handlers.oauth2_token_introspection module provisioned")
	return nil
}

// Validate validates that the module has a usable config.
func (o *OAuth2TokenIntrospection) Validate() error {
	if o.AuthenticationStrategy == "" {
		return errors.New("'authentication_strategy' is required")
	}
	if !authenticationStrategies[o.AuthenticationStrategy] {
		return errors.New("invalid authentication_strategy")
	}
	if o.TokenLocation == "" {
		return errors.New("'token_location' is required")
	}
	if !tokenLocations[o.TokenLocation] {
		return errors.New("invalid token_location")
	}
	if o.IntrospectionEndpoint == "" {
		return errors.New("'introspection_endpoint' is required")
	}
	if o.IntrospectionClientID == "" {
		return errors.New("'introspection_client_id' is required")
	}
	if o.IntrospectionClientSecret == "" {
		return errors.New("'introspection_client_secret' is required")
	}
	return nil
}

type response struct {
	Message string `json:"message"`
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (o OAuth2TokenIntrospection) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var introspectionRequestBody = []byte("")
	if o.TokenLocation == BearerTokenLocation {
		token, tokenerr := o.getTokenFromBearerToken(r)
		if tokenerr != nil {
			o.haltRequest(w, "")
			return nil
		}
		introspectionRequestBody = []byte(fmt.Sprintf(`token=%s`, token))
	}

	introspectionRequest, _ := http.NewRequest(http.MethodPost, o.IntrospectionEndpoint, bytes.NewBuffer(introspectionRequestBody))
	introspectionRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if o.AuthenticationStrategy == ClientCredentialsAuthenticationStrategy {
		introspectionRequestBasicAuth := fmt.Sprintf("%s:%s", o.IntrospectionClientID, o.IntrospectionClientSecret)
		introspectionRequest.Header.Set("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(introspectionRequestBasicAuth))))
	}
	if o.AuthenticationStrategy == BearerTokenAuthenticationStrategy {
		// TODO
	}

	introspectionResponse, huerr := http.DefaultClient.Do(introspectionRequest)
	if huerr != nil {
		o.haltRequest(w, fmt.Sprintf("error performing token introspection. %s", huerr))
		return nil
	}
	defer introspectionResponse.Body.Close()
	introspectionResponseBody, raerr := ioutil.ReadAll(introspectionResponse.Body)
	if raerr != nil {
		o.haltRequest(w, fmt.Sprintf("error performing token introspection. %s", raerr))
		return nil
	}
	if introspectionResponse.StatusCode != 200 {
		o.haltRequest(w, fmt.Sprintf("error performing token introspection. Status: %d, Response: %s", introspectionResponse.StatusCode, string(introspectionResponseBody)))
		return nil
	} else {
		var introspectionResponseDocument = make(map[string]interface{})
		// var introspectionResponseDocument IntrospectionResponse
		muerr := json.Unmarshal(introspectionResponseBody, &introspectionResponseDocument)
		if muerr != nil {
			o.haltRequest(w, fmt.Sprintf("error performing token introspection. %s", muerr))
			return nil
		}

		if active, ok := introspectionResponseDocument["active"]; ok {
			if activeBool, ok := active.(bool); ok {
				if !activeBool {
					o.haltRequest(w, "")
					return nil
				}
			} else {
				o.haltRequest(w, "error performing token introspection. 'active' property is not a boolean.")
				return nil
			}
		} else {
			o.haltRequest(w, "error performing token introspection. 'active' property not found in response.")
			return nil
		}

		if len(o.InboundHeaders) != 0 {
			for header, tokenPath := range o.InboundHeaders {
				tokenPathParts := strings.Split(tokenPath, ".")
				document := introspectionResponseDocument
				var pathPropertyValue interface{}
				for _, pathProperty := range tokenPathParts {
					pathPropertyValue = document[pathProperty]
					pathPropertyType := fmt.Sprintf("%T", pathPropertyValue)
					if pathPropertyType == "map[string]interface {}" {
						nestedDocument, ok := pathPropertyValue.(map[string]interface{})
						if ok {
							document = nestedDocument
						}
					}
				}

				pathPropertyValueType := fmt.Sprintf("%T", pathPropertyValue)
				var pathPropertyValueString string
				if pathPropertyValueType == "float64" {
					// removes trailing 0's done by the conversion, and a trailing . if there's no non-zero decimal values left
					pathPropertyValueString = strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", pathPropertyValue), "0"), ".")
				} else if strings.HasPrefix(pathPropertyValueType, "map") {
					o.logger.Error(fmt.Sprintf("path '%s' for header '%s' is not a scalar (found object)", header, tokenPath))
				} else if strings.HasPrefix(pathPropertyValueType, "[]") {
					o.logger.Error(fmt.Sprintf("path '%s' for header '%s' is not a scalar (found array)", header, tokenPath))
				} else {
					pathPropertyValueString = fmt.Sprintf("%v", pathPropertyValue)
				}
				r.Header.Set(header, pathPropertyValueString)
			}
		}
	}

	return next.ServeHTTP(w, r)
}

func (o OAuth2TokenIntrospection) haltRequest(w http.ResponseWriter, errorMessage string) {
	if errorMessage != "" {
		o.logger.Error(errorMessage)
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// gets the token from an HTTP header matching the format
// `Authorization: Bearer ...mytoken....`
func (o OAuth2TokenIntrospection) getTokenFromBearerToken(r *http.Request) (string, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		return "", fmt.Errorf("Authorization header not found")
	}
	authorizationHeaderFields := strings.Split(authorizationHeader, " ")
	if len(authorizationHeaderFields) != 2 {
		return "", fmt.Errorf(fmt.Sprintf("invalid Authorization header: %s", authorizationHeader))
	} else if strings.ToLower(authorizationHeaderFields[0]) != "bearer" {
		return "", fmt.Errorf(fmt.Sprintf("invalid Authorization header: %s", authorizationHeader))
	}
	token := authorizationHeaderFields[1]
	return token, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*OAuth2TokenIntrospection)(nil)
	_ caddy.Validator             = (*OAuth2TokenIntrospection)(nil)
	_ caddyhttp.MiddlewareHandler = (*OAuth2TokenIntrospection)(nil)
)