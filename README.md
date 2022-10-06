caddy-oauth2-token-introspection
=========

A [Caddy](https://caddyserver.com) module which performs [OAuth2 Token Introspection (RFC 7662)](https://www.rfc-editor.org/rfc/rfc7662.html) to authorize requests containing an [OAuth2](https://www.rfc-editor.org/rfc/rfc6749) access token.

When using Caddy as an API Gateway that sits in front of multiple upstream microservices, this module allows Caddy to authorize requests containing an OAuth2 access token by validating the access token with an [OAuth2 Authorization server](https://www.rfc-editor.org/rfc/rfc6749#section-1.1), rather than each individual upstream microservice from having to do so themselves.

This module is an [HTTP handler](http.handlers) middleware module, and thus can be used inside HTTP handler based directives (e.g. `route`, `handle`, etc).

# Installation

Build Caddy using [xcaddy](https://github.com/caddyserver/xcaddy) and include the caddy-oauth2-token-introspection module:

```
xcaddy build v2.6.1 --with github.com/bploetz/caddy-oauth2-token-introspection
```

# Usage

Example Caddyfile

```
# reusable snippet
(oauth2_protected) {
	oauth2_token_introspection {
		token_location bearer_token
		introspection_endpoint {$OAUTH2_SERVER_URI}/oauth2/introspect
		introspection_authentication_strategy client_credentials
		introspection_client_id {$OAUTH2_INTROSPECTION_CLIENT_ID}
		introspection_client_secret {$OAUTH2_INTROSPECTION_CLIENT_SECRET}
		introspection_timeout 1000
		set_header X-API-GATEWAY-SCOPE scope
		set_header X-API-GATEWAY-SUBJECT sub
		set_header X-API-GATEWAY-EMAIL-ADDRESS email
	}
}

# your API site
{$API_HOST} {
	@service_a_public_paths {
		path /v1/foo
		path /v1/bar
	}
	route {
		reverse_proxy @service_a_public_paths {$SERVICE_A_URI}
	}

	@service_a_protected_paths {
		path /v1/private
		path /v1/very-private
	}
	route {
		import oauth2_protected
		reverse_proxy @service_a_protected_paths {$SERVICE_A_URI}
	}
}
```


# Configuration

The `oauth2_token_introspection` middleware supports the following configuration parameters:

## token_location
Where to find the OAuth2 access token in the HTTP request coming into Caddy. Allowable values:

* `bearer_token` - The access token is in the standard `Authorization: Bearer <mytoken>` HTTP headder

## introspection_endpoint
The URL of the OAuth2 Token Introspection endpoint

## introspection_authentication_strategy
How to authenticate with the OAuth2 Token Introspection endpoint. Allowable values:

* `client_credentials` - Use a client_id and client_secret to form a Basic Authentication request
* `bearer_token` - Use an OAuth2 bearer token (note: this is different than the bearer token on the HTTP request coming into Caddy that we are trying to authorize)

## introspection_client_id
Required if the `introspection_authentication_strategy` is set to `client_credentials`

## introspection_client_secret
Required if the `introspection_authentication_strategy` is set to `client_credentials`

## introspection_bearer_token
Required if the `introspection_authentication_strategy` is set to `bearer_token`

## introspection_timeout
The max length, in milliseconds, the token introspection request should finish in before timing out.

## set_header
Exposes properties from a successful token introspection response as HTTP headers to upstream microservices. For example, for a token introspection response that looks like this:

```
{"active": true, "scope": "member", "sub": "abcd1234", "email": "john.doe@someone.com"}
```

The following headers can be added to the request proxied to the upstream so it has some context about the client making the API call:

```
set_header X-API-GATEWAY-SCOPE scope
set_header X-API-GATEWAY-SUBJECT sub
set_header X-API-GATEWAY-EMAIL-ADDRESS email
```

You may use dot notation to traverse nested objects in the token introspection response. An error will be raised if a `set_header` is pointed at a property that is not a scalar (i.e. you point at an object or an array.

For example, for a token introspection response that looks like this:

```
{"active": true, "scope": "member", "sub": "abcd1234", "user": {"email": "john.doe@someone.com", "first_name": "John", "last_name": "Doe", "preferences": ["foo, "bar"]}}
```

You can expose properties from the `user` object like so:

```
set_header X-API-GATEWAY-EMAIL user.email
set_header X-API-GATEWAY-FIRST-NAME user.first_name
set_header X-API-GATEWAY-LAST-NAME user.last_name
```

But these would result in errors since they point at an object/array:
```
set_header X-API-GATEWAY-USER: user
set_header X-API-GATEWAY-USER-PREFS: user.preferences
```
