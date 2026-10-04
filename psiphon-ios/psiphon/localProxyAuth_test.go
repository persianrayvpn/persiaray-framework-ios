package psiphon

import "testing"

func TestLocalProxyAuthRequiredForClient(t *testing.T) {
	config := &Config{
		LocalProxyUsername: "user",
		LocalProxyPassword: "pass",
	}

	testCases := []struct {
		name       string
		config     *Config
		remoteAddr string
		expected   bool
	}{
		{
			name:       "no credentials",
			config:     new(Config),
			remoteAddr: "192.168.1.10:12345",
			expected:   false,
		},
		{
			name:       "IPv4 loopback",
			config:     config,
			remoteAddr: "127.0.0.1:12345",
			expected:   false,
		},
		{
			name:       "IPv6 loopback",
			config:     config,
			remoteAddr: "[::1]:12345",
			expected:   false,
		},
		{
			name:       "LAN client",
			config:     config,
			remoteAddr: "192.168.1.10:12345",
			expected:   true,
		},
		{
			name:       "unparseable address with credentials",
			config:     config,
			remoteAddr: "not-an-ip-address",
			expected:   true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := localProxyAuthRequiredForClient(
				testCase.config, testCase.remoteAddr)
			if actual != testCase.expected {
				t.Fatalf("localProxyAuthRequiredForClient() = %v, want %v",
					actual, testCase.expected)
			}
		})
	}
}
