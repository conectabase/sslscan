package config

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/sslscan/sslscan-go/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.Options)
	assert.Equal(t, "127.0.0.1", cfg.Options.Host)
	assert.Equal(t, 443, cfg.Options.Port)
	assert.False(t, cfg.Options.Verbose)
}

func TestLoadFromFlags(t *testing.T) {
	cfg := NewConfig()
	cmd := &cobra.Command{}

	// Test with valid host argument
	args := []string{"example.com"}
	err := cfg.LoadFromFlags(cmd, args)

	assert.NoError(t, err)
	assert.Equal(t, "example.com", cfg.Options.Host)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				Options: &models.SSLCheckOptions{
					Host:            "example.com",
					Port:            443,
					ConnectTimeout:  models.DefaultConnectTimeout,
				},
			},
			wantErr: false,
		},
		{
			name: "missing host",
			cfg: &Config{
				Options: &models.SSLCheckOptions{
					Host:            "",
					Port:            443,
					ConnectTimeout:  models.DefaultConnectTimeout,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			cfg: &Config{
				Options: &models.SSLCheckOptions{
					Host:            "example.com",
					Port:            70000, // Invalid port
					ConnectTimeout:  models.DefaultConnectTimeout,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid timeout",
			cfg: &Config{
				Options: &models.SSLCheckOptions{
					Host:            "example.com",
					Port:            443,
					ConnectTimeout:  -1, // Invalid timeout
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseSSLVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"ssl2", models.SSLV2},
		{"ssl3", models.SSLV3},
		{"tls1", models.TLSV10},
		{"tls1.1", models.TLSV11},
		{"tls1.2", models.TLSV12},
		{"tls1.3", models.TLSV13},
		{"unknown", models.SSLAll},
		{"", models.SSLAll},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseSSLVersion(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetVersion(t *testing.T) {
	version := getVersion()
	assert.NotEmpty(t, version)
	assert.Contains(t, version, "1.0.0")
}
