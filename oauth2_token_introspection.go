package oauth2_token_introspection

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

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
		case "token_location":
			if !d.AllArgs(&o.TokenLocation) {
				return d.ArgErr()
			}
		case "introspection_authentication_strategy":
			if !d.AllArgs(&o.IntrospectionAuthenticationStrategy) {
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
		case "introspection_timeout":
			var timeoutString string
			if !d.AllArgs(&timeoutString) {
				return d.ArgErr()
			}
			timeoutInt, err := strconv.Atoi(timeoutString)
			if err != nil {
				return d.Errf("%v not a valid introspection_timeout value (expecting integer)", timeoutString)
			} else {
				o.IntrospectionTimeout = timeoutInt
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
	logger                              *zap.Logger
	TokenLocation                       string            `json:"token_location"`
	IntrospectionEndpoint               string            `json:"introspection_endpoint"`
	IntrospectionAuthenticationStrategy string            `json:"introspection_authentication_strategy"`
	IntrospectionClientID               string            `json:"introspection_client_id"`
	IntrospectionClientSecret           string            `json:"introspection_client_secret"`
	IntrospectionBearerToken            string            `json:"introspection_bearer_token"`
	IntrospectionTimeout                int               `json:"introspection_timeout"`
	InboundHeaders                      map[string]string `json:"inbound_headers"`
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
	o.logger.Info("module provisioned")
	return nil
}

// Validate validates that the module has a usable config.
func (o *OAuth2TokenIntrospection) Validate() error {
	if o.TokenLocation == "" {
		return errors.New("'token_location' is required")
	}
	if !tokenLocations[o.TokenLocation] {
		return errors.New("invalid token_location")
	}
	if o.IntrospectionEndpoint == "" {
		return errors.New("'introspection_endpoint' is required")
	}
	if o.IntrospectionAuthenticationStrategy == "" {
		return errors.New("'introspection_authentication_strategy' is required")
	}
	if !authenticationStrategies[o.IntrospectionAuthenticationStrategy] {
		return errors.New("invalid introspection_authentication_strategy")
	}
	if o.IntrospectionAuthenticationStrategy == ClientCredentialsAuthenticationStrategy {
		if o.IntrospectionClientID == "" {
			return errors.New("'introspection_client_id' is required")
		}
		if o.IntrospectionClientSecret == "" {
			return errors.New("'introspection_client_secret' is required")
		}
	}
	if o.IntrospectionAuthenticationStrategy == BearerTokenAuthenticationStrategy {
		if o.IntrospectionBearerToken == "" {
			return errors.New("'introspection_bearer_token' is required")
		}
	}
	return nil
}

type response struct {
	Message string `json:"message"`
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (o OAuth2TokenIntrospection) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	o.logger.Debug("authorizing request")
	var introspectionRequestBody = []byte("")
	if o.TokenLocation == BearerTokenLocation {
		o.logger.Debug("getting token from 'Authorization: Bearer' header")
		token, tokenerr := o.getTokenFromBearerToken(r)
		if tokenerr != nil {
			o.haltRequest(w, "")
			return nil
		}
		introspectionRequestBody = []byte(fmt.Sprintf(`token=%s`, token))
	}

	introspectionRequest, _ := http.NewRequest(http.MethodPost, o.IntrospectionEndpoint, bytes.NewBuffer(introspectionRequestBody))
	introspectionRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if o.IntrospectionAuthenticationStrategy == ClientCredentialsAuthenticationStrategy {
		o.logger.Debug("using client credentials authentication strategy with token introspection endpoint")
		introspectionRequestBasicAuth := fmt.Sprintf("%s:%s", o.IntrospectionClientID, o.IntrospectionClientSecret)
		introspectionRequest.Header.Set("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(introspectionRequestBasicAuth))))
	}
	if o.IntrospectionAuthenticationStrategy == BearerTokenAuthenticationStrategy {
		o.logger.Debug("using bearer token authentication strategy with token introspection endpoint")
		introspectionRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", o.IntrospectionBearerToken))
	}

	timeout := 2000
	if o.IntrospectionTimeout != 0 {
		timeout = o.IntrospectionTimeout
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer timeoutCancel()

	introspectionResponse, huerr := http.DefaultClient.Do(introspectionRequest.WithContext(timeoutCtx))
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

	o.logger.Debug(fmt.Sprintf("response status code was %d from token introspection endpoint", introspectionResponse.StatusCode))
	if introspectionResponse.StatusCode != 200 {
		o.haltRequest(w, fmt.Sprintf("error performing token introspection. Status: %d, Response: %s", introspectionResponse.StatusCode, string(introspectionResponseBody)))
		return nil
	} else {
		var introspectionResponseDocument = make(map[string]interface{})
		muerr := json.Unmarshal(introspectionResponseBody, &introspectionResponseDocument)
		if muerr != nil {
			o.haltRequest(w, fmt.Sprintf("error performing token introspection. %s", muerr))
			return nil
		}

		if active, ok := introspectionResponseDocument["active"]; ok {
			if activeBool, ok := active.(bool); ok {
				if !activeBool {
					o.logger.Debug("oauth2 token is not active. halting request.")
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

	o.logger.Debug("request authorized via oauth2 token introspection endpoint")
	return next.ServeHTTP(w, r)
}

func (o OAuth2TokenIntrospection) haltRequest(w http.ResponseWriter, errorMessage string) {
	if errorMessage != "" {
		o.logger.Error(errorMessage)
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// gets the bearer token from an HTTP Authorization header matching the format `Authorization: Bearer ...mytoken....`
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
