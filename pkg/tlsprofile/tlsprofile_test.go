// Copyright Contributors to the Open Cluster Management project

package tlsprofile

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestConvertTLSProfileToConfig(t *testing.T) {
	tests := []struct {
		name           string
		profile        *configv1.TLSSecurityProfile
		expectedMinTLS uint16
		expectCiphers  bool
	}{
		{
			name:           "Nil profile defaults to TLS 1.2",
			profile:        nil,
			expectedMinTLS: tls.VersionTLS12,
			expectCiphers:  false,
		},
		{
			name: "Old profile uses TLS 1.0",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
			},
			expectedMinTLS: tls.VersionTLS10,
			expectCiphers:  true,
		},
		{
			name: "Intermediate profile uses TLS 1.2",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			},
			expectedMinTLS: tls.VersionTLS12,
			expectCiphers:  true,
		},
		{
			name: "Modern profile uses TLS 1.3",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			},
			expectedMinTLS: tls.VersionTLS13,
			expectCiphers:  false, // TLS 1.3 doesn't use configurable ciphers
		},
		{
			name: "Custom profile with TLS 1.2",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers: []string{
							"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
							"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
						},
					},
				},
			},
			expectedMinTLS: tls.VersionTLS12,
			expectCiphers:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ConvertTLSProfileToConfig(tt.profile)

			if config == nil {
				t.Fatal("Expected non-nil TLS config")
			}

			if config.MinVersion != tt.expectedMinTLS {
				t.Errorf("Expected MinVersion %v, got %v", tt.expectedMinTLS, config.MinVersion)
			}

			if tt.expectCiphers && len(config.CipherSuites) == 0 {
				t.Error("Expected cipher suites to be configured")
			}

			if !tt.expectCiphers && len(config.CipherSuites) > 0 {
				t.Errorf("Expected no cipher suites for this profile, got %d", len(config.CipherSuites))
			}
		})
	}
}

func TestGetTLSVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected uint16
	}{
		{"TLS 1.0", string(configv1.VersionTLS10), tls.VersionTLS10},
		{"TLS 1.1", string(configv1.VersionTLS11), tls.VersionTLS11},
		{"TLS 1.2", string(configv1.VersionTLS12), tls.VersionTLS12},
		{"TLS 1.3", string(configv1.VersionTLS13), tls.VersionTLS13},
		{"Unknown defaults to TLS 1.2", "unknown", tls.VersionTLS12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTLSVersion(tt.version)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetCipherSuites(t *testing.T) {
	cipherNames := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"UNKNOWN_CIPHER", // Should be ignored with a warning
	}

	ciphers := getCipherSuites(cipherNames)

	// Should have 2 valid ciphers (the unknown one is skipped)
	if len(ciphers) != 2 {
		t.Errorf("Expected 2 cipher suites, got %d", len(ciphers))
	}

	// Verify the ciphers match
	expectedCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}

	for i, expected := range expectedCiphers {
		if ciphers[i] != expected {
			t.Errorf("Expected cipher %v at index %d, got %v", expected, i, ciphers[i])
		}
	}
}
