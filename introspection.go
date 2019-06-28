/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	phttp "github.com/coreos/go-oidc/http"
	"github.com/coreos/go-oidc/oauth2"
)

// getTokenIntrospectClient returns a client for introspection
func (r *oauthProxy) NewTokenIntrospectionClient(httpClient phttp.Client) (*TokenIntrospectionClient, error) {
	return &TokenIntrospectionClient{
		hc: httpClient,
		Credentials: oauth2.ClientCredentials{
			ID:     r.config.ClientID,
			Secret: r.config.ClientSecret,
		},
		authMethod:            r.config.ClientAuthMethod,
		TokenIntrospectionURL: r.config.TokenIntrospectionEndpoint,
	}, nil
}

type TokenIntrospectionClient struct {
	hc                    phttp.Client
	Credentials           oauth2.ClientCredentials
	authMethod            string
	TokenIntrospectionURL string
}

// introspectToken is responsible for introspecting the token
func (c *TokenIntrospectionClient) Introspect(token string) (TokenIntrospectionResponse, error) {
	start := time.Now()
	result, err := c.requestTokenIntrospection(c.TokenIntrospectionURL, token)
	if err != nil {
		return result, err
	}
	taken := time.Since(start).Seconds()
	oauthTokensMetric.WithLabelValues("introspect").Inc()
	oauthLatencyMetric.WithLabelValues("introspect").Observe(taken)

	return result, err
}

func (c *TokenIntrospectionClient) requestTokenIntrospection(endpoint, token string) (result TokenIntrospectionResponse, err error) {
	v := url.Values{
		"token": {token},
	}

	req, err := c.newAuthenticatedRequest(endpoint, v)
	if err != nil {
		return
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	return parseTokenIntrospectionResponse(resp)
}

func (c *TokenIntrospectionClient) newAuthenticatedRequest(urlToken string, values url.Values) (*http.Request, error) {
	var req *http.Request
	var err error
	switch c.authMethod {
	case authMethodBody:
		values.Set("client_id", c.Credentials.ID)
		values.Set("client_secret", c.Credentials.Secret)
		req, err = http.NewRequest("POST", urlToken, strings.NewReader(values.Encode()))
		if err != nil {
			return nil, err
		}
	case authMethodBasic:
		req, err = http.NewRequest("POST", urlToken, strings.NewReader(values.Encode()))
		if err != nil {
			return nil, err
		}
		encodedID := url.QueryEscape(c.Credentials.ID)
		encodedSecret := url.QueryEscape(c.Credentials.Secret)
		req.SetBasicAuth(encodedID, encodedSecret)
	default:
		panic("misconfigured client: auth method not supported")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil

}

type TokenIntrospectionResponse struct {
	Active       bool
	Scope        string
	ClientID     string
	Username     string
	TokenType    string
	Expires      int
	IssuedAt     int
	NotBefore    int
	Subject      string
	Audience     []string
	Issuer       string
	JWTID        string
	Confirmation map[string]interface{}
}

func parseTokenIntrospectionResponse(resp *http.Response) (result TokenIntrospectionResponse, err error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	badStatusCode := resp.StatusCode < 200 || resp.StatusCode > 299

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return
	}

	newError := func(typ, desc string) error {
		if typ == "" {
			return fmt.Errorf("unrecognized error %s", body)
		}
		return &oauth2.Error{typ, desc, ""}
	}

	if contentType != "application/json" {
		err = newError("", "unexpected contentType: "+contentType)
		return
	}

	var r struct {
		Active       bool                   `json:"active"`
		Scope        string                 `json:"scope"`
		ClientID     string                 `json:"client_id"`
		Username     string                 `json:"username"`
		TokenType    string                 `json:"token_type"`
		Expires      int                    `json:"exp"`
		IssuedAt     int                    `json:"iat"`
		NotBefore    int                    `json:"nbf"`
		Subject      string                 `json:"sub"`
		Audience     interface{}            `json:"aud"`
		Issuer       string                 `json:"iss"`
		JWTID        string                 `json:"jti"`
		Confirmation map[string]interface{} `json:"cnf"`
		Error        string                 `json:"error"`
		Desc         string                 `json:"error_description"`
	}

	if err = json.Unmarshal(body, &r); err != nil {
		return
	}
	if r.Error != "" || badStatusCode {
		err = newError(r.Error, r.Desc)
		return
	}

	result = TokenIntrospectionResponse{
		Active:       r.Active,
		Scope:        r.Scope,
		ClientID:     r.ClientID,
		Username:     r.Username,
		TokenType:    r.TokenType,
		Expires:      r.Expires,
		IssuedAt:     r.IssuedAt,
		NotBefore:    r.NotBefore,
		Subject:      r.Subject,
		Audience:     asStrings(r.Audience),
		Issuer:       r.Issuer,
		JWTID:        r.JWTID,
		Confirmation: r.Confirmation,
	}

	return
}

func asStrings(v interface{}) []string {
	if val, ok := v.([]string); ok {
		return val
	}
	if val, ok := v.(string); ok {
		return []string{val}
	}
	return []string{}
}
