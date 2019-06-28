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
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultConfig(t *testing.T) {
	if config := newDefaultConfig(); config == nil {
		t.Error("we should have received a config")
	}
}

func TestIsConfig(t *testing.T) {
	tests := []struct {
		Config *Config
		Ok     bool
	}{
		{
			Config: &Config{},
		},
		{
			Config: &Config{
				DiscoveryURL:     "http://127.0.0.1:8080",
				ClientAuthMethod: "secret-basic",
			},
		},
		{
			Config: &Config{
				DiscoveryURL:     "http://127.0.0.1:8080",
				ClientAuthMethod: "secret-basic",
				ClientID:         "client",
				ClientSecret:     "client",
			},
		},
		{
			Config: &Config{
				Listen:           ":8080",
				DiscoveryURL:     "http://127.0.0.1:8080",
				ClientAuthMethod: "secret-basic",
				ClientID:         "client",
				ClientSecret:     "client",
				RedirectionURL:   "http://120.0.0.1",
			},
		},
		{
			Config: &Config{
				Listen:           ":8080",
				DiscoveryURL:     "http://127.0.0.1:8080",
				ClientAuthMethod: "secret-basic",
				ClientID:         "client",
				ClientSecret:     "client",
				RedirectionURL:   "http://120.0.0.1",
				Upstream:         "http://120.0.0.1",
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientAuthMethod:    "secret-basic",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
			Ok: true,
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientAuthMethod:    "secret-basic",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        0,
				MaxIdleConnsPerHost: 0,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientAuthMethod:    "secret-basic",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 200,
			},
		},
		{
			Config: &Config{
				Listen:           ":8080",
				DiscoveryURL:     "http://127.0.0.1:8080",
				ClientAuthMethod: "secret-basic",
				ClientID:         "client",
				ClientSecret:     "client",
				RedirectionURL:   "http://120.0.0.1",
				Upstream:         "http://120.0.0.1",
				MatchClaims: map[string]string{
					"test": "&&&[",
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:                ":8080",
				SkipTokenVerification: true,
				Upstream:              "http://120.0.0.1",
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
			},
			Ok: true,
		},
		{
			Config: &Config{
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientAuthMethod:    "secret-basic",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientAuthMethod:    "secret-basic",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientAuthMethod:    "secret-basic",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "this should fail",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientAuthMethod:    "secret-basic",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "this should fail",
				SecureCookie:        true,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientAuthMethod:    "secret-basic",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "https://120.0.0.1",
				Upstream:            "this should fail",
				SecureCookie:        true,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
			Ok: true,
		},
	}

	for i, c := range tests {
		if err := c.Config.isValid(); err != nil && c.Ok {
			t.Errorf("test case %d, the config should not have errored, error: %s", i, err)
		}
	}
}

func TestParseTLS(t *testing.T) {
	tlsConfigFixture := tlsAdvancedConfig{
		tlsPreferServerCipherSuites: true,
		tlsMinVersion:               "TLS1.1",
		tlsCipherSuites:             []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		tlsCurvePreferences:         []string{"P384"},
	}
	res, err := parseTLS(&tlsConfigFixture)
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		assert.Equal(t, &tlsSettings{
			tlsPreferServerCipherSuites: true,
			tlsMinVersion:               tls.VersionTLS11,
			tlsCipherSuites:             []uint16{tls.TLS_FALLBACK_SCSV, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			tlsCurvePreferences:         []tls.CurveID{tls.CurveP384},
		}, res)
	}

	tlsConfigFixture = tlsAdvancedConfig{
		tlsUseModernSettings: true,
	}
	res, err = parseTLS(&tlsConfigFixture)
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		assert.Equal(t, &tlsSettings{
			tlsPreferServerCipherSuites: true,
			tlsMinVersion:               tls.VersionTLS12,
			tlsCipherSuites: []uint16{
				tls.TLS_FALLBACK_SCSV,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			tlsCurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		}, res)
	}
}
