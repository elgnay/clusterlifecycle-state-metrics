// Copyright Contributors to the Open Cluster Management project

package tlsprofile

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestTLSProfileChanged(t *testing.T) {
	tests := []struct {
		name     string
		old      *configv1.TLSSecurityProfile
		new      *configv1.TLSSecurityProfile
		expected bool
	}{
		{
			name:     "Both nil - no change",
			old:      nil,
			new:      nil,
			expected: false,
		},
		{
			name:     "Old nil, new set - changed",
			old:      nil,
			new:      &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			expected: true,
		},
		{
			name:     "Old set, new nil - changed",
			old:      &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			new:      nil,
			expected: true,
		},
		{
			name:     "Same profile type - no change",
			old:      &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			new:      &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			expected: false,
		},
		{
			name:     "Different profile types - changed",
			old:      &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			new:      &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			expected: true,
		},
		{
			name: "Same custom profile - no change",
			old: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
					},
				},
			},
			new: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
					},
				},
			},
			expected: false,
		},
		{
			name: "Custom profile with different MinTLSVersion - changed",
			old: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
					},
				},
			},
			new: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS13,
						Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
					},
				},
			},
			expected: true,
		},
		{
			name: "Custom profile with different ciphers - changed",
			old: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
					},
				},
			},
			new: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
					},
				},
			},
			expected: true,
		},
		{
			name: "Custom profile with additional cipher - changed",
			old: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
					},
				},
			},
			new: &configv1.TLSSecurityProfile{
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
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tlsProfileChanged(tt.old, tt.new)
			if result != tt.expected {
				t.Errorf("tlsProfileChanged() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetTLSProfileType(t *testing.T) {
	tests := []struct {
		name     string
		profile  *configv1.TLSSecurityProfile
		expected string
	}{
		{
			name:     "Nil profile",
			profile:  nil,
			expected: "nil (default Intermediate)",
		},
		{
			name:     "Old profile type",
			profile:  &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
			expected: string(configv1.TLSProfileOldType),
		},
		{
			name:     "Intermediate profile type",
			profile:  &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			expected: string(configv1.TLSProfileIntermediateType),
		},
		{
			name:     "Modern profile type",
			profile:  &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			expected: string(configv1.TLSProfileModernType),
		},
		{
			name:     "Custom profile type",
			profile:  &configv1.TLSSecurityProfile{Type: configv1.TLSProfileCustomType},
			expected: string(configv1.TLSProfileCustomType),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTLSProfileType(tt.profile)
			if result != tt.expected {
				t.Errorf("getTLSProfileType() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
