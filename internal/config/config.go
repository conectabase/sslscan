package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/sslscan/sslscan-go/internal/models"
	"github.com/sslscan/sslscan-go/pkg/utils"
)

// Config represents the global application configuration
type Config struct {
	Options *models.SSLCheckOptions
	Verbose bool
	Version bool
	Help    bool
}

// flagConfig defines flag configuration
type flagConfig struct {
	name         string
	short        string
	defaultValue interface{}
	description  string
	viperKey     string
}

// NewConfig creates a new config instance
func NewConfig() *Config {
	return &Config{
		Options: &models.SSLCheckOptions{
			Host:            "127.0.0.1",
			Port:            443,
			ConnectTimeout:  models.DefaultConnectTimeout,
			ReadTimeout:     models.DefaultReadTimeout,
			WriteTimeout:    models.DefaultWriteTimeout,
			SSLVersion:      models.SSLAll,
			Verbose:         false,
			ShowTimes:       false,
			ShowCipherIds:   false,
			ShowCipherDetails: false,
			IPv4:            true,
			IPv6:            true,
		},
	}
}

// LoadFromFlags loads configuration from CLI flags
func (c *Config) LoadFromFlags(cmd *cobra.Command, args []string) error {
	// Basic flags
	if c.Help {
		return cmd.Help()
	}

	if c.Version {
		fmt.Printf("sslscan-go version %s\n", getVersion())
		return nil
	}

	// Configure host and port
	if len(args) > 0 {
		c.Options.Host = args[0]
	}

	// Configure port if specified
	if port := viper.GetString("port"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			c.Options.Port = p
		}
	}

	// Configure SNI
	if sni := viper.GetString("sni"); sni != "" {
		c.Options.SNIName = sni
		c.Options.SNISet = true
	}

	// Configure timeouts
	if timeout := viper.GetString("timeout"); timeout != "" {
		if t, err := time.ParseDuration(timeout); err == nil {
			c.Options.ConnectTimeout = t
			c.Options.ReadTimeout = t
			c.Options.WriteTimeout = t
		}
	}

	// Configure verbosity
	c.Options.Verbose = viper.GetBool("verbose")

	// Configure outputs
	if xmlFile := viper.GetString("xml"); xmlFile != "" {
		c.Options.XMLOutput = &models.OutputWriter{
			File: &models.File{Path: xmlFile},
		}
	}

	if junitFile := viper.GetString("junit"); junitFile != "" {
		c.Options.JUnitOutput = &models.OutputWriter{
			File: &models.File{Path: junitFile},
		}
	}

	// Configure specific tests
	c.Options.ShowCertificate = viper.GetBool("certificate")
	c.Options.ShowCertificates = viper.GetBool("certificates")
	c.Options.CheckCertificate = viper.GetBool("check-certificate")
	c.Options.ShowTrustedCAs = viper.GetBool("trusted-cas")
	c.Options.ShowClientCiphers = viper.GetBool("client-ciphers")
	c.Options.TestRenegotiation = viper.GetBool("renegotiation")
	c.Options.TestFallback = viper.GetBool("fallback")
	c.Options.TestCompression = viper.GetBool("compression")
	c.Options.TestHeartbleed = viper.GetBool("heartbleed")
	c.Options.TestSupportedGroups = viper.GetBool("groups")
	c.Options.TestSignatureAlgorithms = viper.GetBool("signature-algorithms")
	c.Options.TestMissingCiphers = viper.GetBool("missing-ciphers")

	// Configure SSL/TLS version
	if sslVersion := viper.GetString("ssl-version"); sslVersion != "" {
		c.Options.SSLVersion = parseSSLVersion(sslVersion)
	}

	// Configure cipher string
	if cipherString := viper.GetString("ciphers"); cipherString != "" {
		c.Options.CipherString = cipherString
	}

	// Configure client certificates
	if clientCerts := viper.GetString("client-certs"); clientCerts != "" {
		c.Options.ClientCertsFile = clientCerts
	}

	if privateKey := viper.GetString("private-key"); privateKey != "" {
		c.Options.PrivateKeyFile = privateKey
	}

	if privateKeyPass := viper.GetString("private-key-password"); privateKeyPass != "" {
		c.Options.PrivateKeyPassword = privateKeyPass
	}

	// Configure output options
	c.Options.ShowTimes = viper.GetBool("times")
	c.Options.ShowCipherIds = viper.GetBool("cipher-ids")
	c.Options.ShowCipherDetails = viper.GetBool("cipher-details")

	// Configure network options
	c.Options.IPv4 = viper.GetBool("ipv4")
	c.Options.IPv6 = viper.GetBool("ipv6")

	return nil
}

// SetupFlags sets up CLI flags
func SetupFlags(cmd *cobra.Command) {
	// Define flag configurations
	flags := []flagConfig{
		// Basic flags
		{"port", "p", "443", "Port to connect to", "port"},
		{"sni", "", "", "SNI name to use", "sni"},
		{"timeout", "", "10s", "Timeout for connections", "timeout"},
		{"verbose", "v", false, "Verbose output", "verbose"},

		// Output flags
		{"xml", "", "", "XML output file", "xml"},
		{"junit", "", "", "JUnit output file", "junit"},

		// Test flags
		{"certificate", "", false, "Show certificate", "certificate"},
		{"certificates", "", false, "Show all certificates", "certificates"},
		{"check-certificate", "", false, "Check certificate", "check-certificate"},
		{"trusted-cas", "", false, "Show trusted CAs", "trusted-cas"},
		{"client-ciphers", "", false, "Show client ciphers", "client-ciphers"},
		{"renegotiation", "", false, "Test renegotiation", "renegotiation"},
		{"fallback", "", false, "Test fallback", "fallback"},
		{"compression", "", false, "Test compression", "compression"},
		{"heartbleed", "", false, "Test Heartbleed", "heartbleed"},
		{"groups", "", false, "Test supported groups", "groups"},
		{"signature-algorithms", "", false, "Test signature algorithms", "signature-algorithms"},
		{"missing-ciphers", "", false, "Test missing ciphers", "missing-ciphers"},

		// SSL/TLS config flags
		{"ssl-version", "", "", "Specific SSL/TLS version (ssl2, ssl3, tls1, tls1.1, tls1.2, tls1.3)", "ssl-version"},
		{"ciphers", "", "", "Cipher string to test", "ciphers"},

		// Certificate flags
		{"client-certs", "", "", "Client certificates file", "client-certs"},
		{"private-key", "", "", "Private key file", "private-key"},
		{"private-key-password", "", "", "Private key password", "private-key-password"},

		// Detailed output flags
		{"times", "", false, "Show response times", "times"},
		{"cipher-ids", "", false, "Show cipher IDs", "cipher-ids"},
		{"cipher-details", "", false, "Show cipher details", "cipher-details"},

		// Network flags
		{"ipv4", "", true, "Use IPv4", "ipv4"},
		{"ipv6", "", true, "Use IPv6", "ipv6"},
	}

	// Add flags and bind to viper
	for _, flag := range flags {
		addFlag(cmd, flag)
		viper.BindPFlag(flag.viperKey, cmd.Flags().Lookup(flag.name))
	}
}

// addFlag adds a flag to the command based on configuration
func addFlag(cmd *cobra.Command, config flagConfig) {
	switch v := config.defaultValue.(type) {
	case string:
		if config.short != "" {
			cmd.Flags().StringP(config.name, config.short, v, config.description)
		} else {
			cmd.Flags().String(config.name, v, config.description)
		}
	case bool:
		if config.short != "" {
			cmd.Flags().BoolP(config.name, config.short, v, config.description)
		} else {
			cmd.Flags().Bool(config.name, v, config.description)
		}
	}
}

// parseSSLVersion converts string SSL/TLS version to constant
func parseSSLVersion(version string) int {
	switch strings.ToLower(version) {
	case "ssl2", "sslv2":
		return models.SSLV2
	case "ssl3", "sslv3":
		return models.SSLV3
	case "tls1", "tls1.0":
		return models.TLSV10
	case "tls1.1":
		return models.TLSV11
	case "tls1.2":
		return models.TLSV12
	case "tls1.3":
		return models.TLSV13
	case "all":
		return models.SSLAll
	default:
		return models.SSLAll
	}
}

// getVersion returns the current program version
func getVersion() string {
	// In a real implementation, this would come from a build variable
	return "1.0.0"
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Options.Host == "" {
		return utils.NewValidationError("host is required")
	}

	if c.Options.Port <= 0 || c.Options.Port > 65535 {
		return utils.NewValidationError("port must be between 1 and 65535")
	}

	if c.Options.ConnectTimeout <= 0 {
		return utils.NewValidationError("connection timeout must be positive")
	}

	return nil
}
