package oauth2_token_introspection

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/caddyserver/caddy/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
)

type mockNext struct{}

func (h mockNext) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	switch r.URL.Path {
	case "/ok":
		w.WriteHeader(200)
		w.Write([]byte{})
	case "/error":
		w.WriteHeader(500)
		w.Write([]byte{})
	}

	return nil
}

var _ = Describe("OAuth2TokenIntrospection", func() {
	var oauth2TokenIntrospection OAuth2TokenIntrospection

	JustBeforeEach(func() {
		oauth2TokenIntrospection = OAuth2TokenIntrospection{logger: zap.NewNop(), IntrospectionEndpoint: "https://some.server/oauth2/introspect"}
	})

	Describe("CaddyModule()", func() {
		It("ID is mapped to the correct namespace", func() {
			moduleInfo := oauth2TokenIntrospection.CaddyModule()
			Expect(moduleInfo.ID.Namespace()).To(Equal("http.handlers"))
		})

		It("ID has the correct name", func() {
			moduleInfo := oauth2TokenIntrospection.CaddyModule()
			Expect(moduleInfo.ID.Name()).To(Equal("oauth2_token_introspection"))
		})

		It("New() returns an OAuth2TokenIntrospection instance", func() {
			moduleInfo := oauth2TokenIntrospection.CaddyModule()
			Expect(fmt.Sprintf("%T", moduleInfo.New())).To(Equal("*oauth2_token_introspection.OAuth2TokenIntrospection"))
		})
	})

	Describe("Provision()", func() {
		It("sets the logger field", func() {
			ctx := context.Background()
			cctx, cancel := caddy.NewContext(caddy.Context{Context: ctx})
			defer cancel()
			oauth2TokenIntrospection := OAuth2TokenIntrospection{}
			err := oauth2TokenIntrospection.Provision(cctx)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(oauth2TokenIntrospection.logger).ToNot(BeNil())
		})
	})

	Describe("Validate()", func() {
		It("returns an error if TokenLocation is not set", func() {
			oauth2TokenIntrospectionToValidate := OAuth2TokenIntrospection{}
			err := oauth2TokenIntrospectionToValidate.Validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(Equal("'token_location' is required"))
		})

		It("returns an error if TokenLocation is invalid", func() {
			oauth2TokenIntrospectionToValidate := OAuth2TokenIntrospection{TokenLocation: "nope"}
			err := oauth2TokenIntrospectionToValidate.Validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(Equal("invalid token_location"))
		})

		It("returns an error if IntrospectionEndpoint is not set", func() {
			oauth2TokenIntrospectionToValidate := OAuth2TokenIntrospection{TokenLocation: "bearer_token"}
			err := oauth2TokenIntrospectionToValidate.Validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(Equal("'introspection_endpoint' is required"))
		})

		It("returns an error if IntrospectionAuthenticationStrategy is not set", func() {
			oauth2TokenIntrospectionToValidate := OAuth2TokenIntrospection{TokenLocation: "bearer_token", IntrospectionEndpoint: "https://some.server/oauth2/introspect"}
			err := oauth2TokenIntrospectionToValidate.Validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(Equal("'introspection_authentication_strategy' is required"))
		})

		It("returns an error if IntrospectionAuthenticationStrategy is invalid", func() {
			oauth2TokenIntrospectionToValidate := OAuth2TokenIntrospection{TokenLocation: "bearer_token", IntrospectionEndpoint: "https://some.server/oauth2/introspect", IntrospectionAuthenticationStrategy: "nope"}
			err := oauth2TokenIntrospectionToValidate.Validate()
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(Equal("invalid introspection_authentication_strategy"))
		})

		Describe("client_credentials authentication strategy", func() {
			It("returns an error if IntrospectionClientID is not set", func() {
				oauth2TokenIntrospectionToValidate := OAuth2TokenIntrospection{TokenLocation: "bearer_token", IntrospectionEndpoint: "https://some.server/oauth2/introspect", IntrospectionAuthenticationStrategy: "client_credentials", IntrospectionClientSecret: "bar"}
				err := oauth2TokenIntrospectionToValidate.Validate()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(Equal("'introspection_client_id' is required"))
			})

			It("returns an error if IntrospectionClientSecret is not set", func() {
				oauth2TokenIntrospectionToValidate := OAuth2TokenIntrospection{TokenLocation: "bearer_token", IntrospectionEndpoint: "https://some.server/oauth2/introspect", IntrospectionAuthenticationStrategy: "client_credentials", IntrospectionClientID: "foo"}
				err := oauth2TokenIntrospectionToValidate.Validate()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(Equal("'introspection_client_secret' is required"))
			})
		})

		Describe("bearer_token authentication strategy", func() {
			It("returns an error if IntrospectionBearerToken is not set", func() {
				oauth2TokenIntrospectionToValidate := OAuth2TokenIntrospection{TokenLocation: "bearer_token", IntrospectionEndpoint: "https://some.server/oauth2/introspect", IntrospectionAuthenticationStrategy: "bearer_token"}
				err := oauth2TokenIntrospectionToValidate.Validate()
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(Equal("'introspection_bearer_token' is required"))
			})
		})

		It("does not return an error for a valid instance", func() {
			oauth2TokenIntrospectionToValidate := OAuth2TokenIntrospection{TokenLocation: "bearer_token", IntrospectionEndpoint: "https://some.server/oauth2/introspect", IntrospectionAuthenticationStrategy: "client_credentials", IntrospectionClientID: "foo", IntrospectionClientSecret: "bar"}
			err := oauth2TokenIntrospectionToValidate.Validate()
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Describe("ServeHTTP()", func() {
		var mockIntrospectionServer *httptest.Server

		JustAfterEach(func() {
			defer mockIntrospectionServer.Close()
		})

		Describe("client_credentials authentication strategy", func() {
			JustBeforeEach(func() {
				oauth2TokenIntrospection.IntrospectionAuthenticationStrategy = ClientCredentialsAuthenticationStrategy
				oauth2TokenIntrospection.IntrospectionClientID = "foo"
				oauth2TokenIntrospection.IntrospectionClientSecret = "bar"
			})

			It("authenticates with the configured client_id and client_secret", func() {
				var clientIDSentToIntrospectionServer, clientSecretSentToIntrospectionServer string
				var basicAuthToIntrospectionServerOK bool
				mockIntrospectionServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					clientIDSentToIntrospectionServer, clientSecretSentToIntrospectionServer, basicAuthToIntrospectionServerOK = r.BasicAuth()
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"active":true}`))
				}))
				oauth2TokenIntrospection.IntrospectionEndpoint = fmt.Sprintf("%s/%s", mockIntrospectionServer.URL, "oauth2/introspect")

				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(basicAuthToIntrospectionServerOK).To(Equal(true))
				Expect(clientIDSentToIntrospectionServer).To(Equal(oauth2TokenIntrospection.IntrospectionClientID))
				Expect(clientSecretSentToIntrospectionServer).To(Equal(oauth2TokenIntrospection.IntrospectionClientSecret))

			})
		})

		Describe("bearer_token authentication strategy", func() {
			JustBeforeEach(func() {
				oauth2TokenIntrospection.IntrospectionAuthenticationStrategy = BearerTokenAuthenticationStrategy
				oauth2TokenIntrospection.IntrospectionBearerToken = "foo"
			})

			It("authenticates with the configured bearer token", func() {
				var bearerTokenSentToIntrospectionServer string
				mockIntrospectionServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					bearerTokenSentToIntrospectionServer = r.Header.Get("Authorization")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"active":true}`))
				}))
				oauth2TokenIntrospection.IntrospectionEndpoint = fmt.Sprintf("%s/%s", mockIntrospectionServer.URL, "oauth2/introspect")

				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(bearerTokenSentToIntrospectionServer).To(Equal(fmt.Sprintf("Bearer %s", oauth2TokenIntrospection.IntrospectionBearerToken)))
			})
		})

		Describe("bearer_token token location", func() {
			JustBeforeEach(func() {
				oauth2TokenIntrospection.IntrospectionAuthenticationStrategy = ClientCredentialsAuthenticationStrategy
				oauth2TokenIntrospection.IntrospectionClientID = "foo"
				oauth2TokenIntrospection.IntrospectionClientSecret = "bar"
				oauth2TokenIntrospection.TokenLocation = BearerTokenLocation
			})

			It("returns an unauthorized response if the Authorization header is not found", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, nil)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("returns an unauthorized response if the Authorization header does not contain two values separated by a space", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "foo")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, nil)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("returns an unauthorized response if the Authorization header does not contain a bearer token", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "foo bar")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, nil)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("sends the bearer token to the introspection endpoint", func() {
				var tokenSentToIntrospectionServer string
				mockIntrospectionServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					tokenSentToIntrospectionServer = r.FormValue("token")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"active":true}`))
				}))
				oauth2TokenIntrospection.IntrospectionEndpoint = fmt.Sprintf("%s/%s", mockIntrospectionServer.URL, "oauth2/introspect")

				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(tokenSentToIntrospectionServer).To(Equal("mytoken"))
				Expect(w.Code).To(Equal(200))
			})

			It("returns an unauthorized response if the introspection endpoint returns a status other than 200", func() {
				mockIntrospectionServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusForbidden)
				}))
				oauth2TokenIntrospection.IntrospectionEndpoint = fmt.Sprintf("%s/%s", mockIntrospectionServer.URL, "oauth2/introspect")

				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("returns an unauthorized response if the introspection endpoint returns a response body that can't be parsed into JSON", func() {
				mockIntrospectionServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`}"oops"{`))
				}))
				oauth2TokenIntrospection.IntrospectionEndpoint = fmt.Sprintf("%s/%s", mockIntrospectionServer.URL, "oauth2/introspect")

				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("returns an unauthorized response if the introspection endpoint returns a response JSON that doesn't include an 'active' property", func() {
				mockIntrospectionServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"foo":"bar"}`))
				}))
				oauth2TokenIntrospection.IntrospectionEndpoint = fmt.Sprintf("%s/%s", mockIntrospectionServer.URL, "oauth2/introspect")

				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("returns an unauthorized response if the introspection endpoint returns a response JSON where the 'active' property is not a boolean", func() {
				mockIntrospectionServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"active":1}`))
				}))
				oauth2TokenIntrospection.IntrospectionEndpoint = fmt.Sprintf("%s/%s", mockIntrospectionServer.URL, "oauth2/introspect")

				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("returns an unauthorized response if the introspection endpoint returns a response JSON where the 'active' property is false", func() {
				mockIntrospectionServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"active":false}`))
				}))
				oauth2TokenIntrospection.IntrospectionEndpoint = fmt.Sprintf("%s/%s", mockIntrospectionServer.URL, "oauth2/introspect")

				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})

		Describe("InboundHeaders", func() {
			JustBeforeEach(func() {
				oauth2TokenIntrospection.IntrospectionAuthenticationStrategy = ClientCredentialsAuthenticationStrategy
				oauth2TokenIntrospection.IntrospectionClientID = "foo"
				oauth2TokenIntrospection.IntrospectionClientSecret = "bar"
				oauth2TokenIntrospection.TokenLocation = BearerTokenLocation
				oauth2TokenIntrospection.InboundHeaders = map[string]string{"X-OAUTH2-TOKEN-SCOPE": "scope", "X-OAUTH2-TOKEN-OBJECT": "object", "X-OAUTH2-TOKEN-OBJECT-PROP1": "object.prop1", "X-OAUTH2-TOKEN-EXP": "exp", "X-OAUTH2-TOKEN-AMOUNT": "object.prop3.amount", "X-OAUTH2-TOKEN-BOOLEAN": "boolean", "X-OAUTH2-TOKEN-ARRAY": "array"}
				mockIntrospectionServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"active":true,"scope":"user tier1","exp":1664563022182,"boolean":false,"string":"blah","float":123.456,"int":99999,"array":["hey","hi"],"object":{"prop1":"foo","prop2":1,"prop3":{"amount":"12345678.90"}}}`))
				}))
				oauth2TokenIntrospection.IntrospectionEndpoint = fmt.Sprintf("%s/%s", mockIntrospectionServer.URL, "oauth2/introspect")
			})

			It("adds headers to the inbound request for top level properties in the introspection response", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(req.Header.Get("X-OAUTH2-TOKEN-SCOPE")).To(Equal("user tier1"))
			})

			It("adds headers to the inbound request for nested object properties in the introspection response", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(req.Header.Get("X-OAUTH2-TOKEN-OBJECT-PROP1")).To(Equal("foo"))
			})

			It("formats integers as strings correctly", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(req.Header.Get("X-OAUTH2-TOKEN-EXP")).To(Equal("1664563022182"))
			})

			It("formats floats as strings correctly", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(req.Header.Get("X-OAUTH2-TOKEN-AMOUNT")).To(Equal("12345678.90"))
			})

			It("formats booleans as strings correctly", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(req.Header.Get("X-OAUTH2-TOKEN-BOOLEAN")).To(Equal("false"))
			})

			It("does not add the header if the path points at an object", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(req.Header.Get("X-OAUTH2-TOKEN-OBJECT")).To(Equal(""))
			})

			It("does not add the header if the path points at an array", func() {
				req := httptest.NewRequest("GET", "/v1/blah", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", "Bearer mytoken")
				w := httptest.NewRecorder()
				err := oauth2TokenIntrospection.ServeHTTP(w, req, mockNext{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(req.Header.Get("X-OAUTH2-TOKEN-ARRAY")).To(Equal(""))
			})
		})
	})
})
