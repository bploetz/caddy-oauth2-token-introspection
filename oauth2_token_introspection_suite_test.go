package oauth2_token_introspection

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestOAuth2TokenIntrospection(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "caddy-oauth2-token-introspection module suite")
}
