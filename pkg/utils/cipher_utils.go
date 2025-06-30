package utils

import (
	"crypto/tls"
	"strings"
)

// CipherInfo contains information about a cipher suite
type CipherInfo struct {
	ID   uint16
	Name string
	Bits int
}

// CipherRegistry provides centralized cipher management
type CipherRegistry struct {
	cipherMap     map[string]uint16
	cipherNameMap map[uint16]string
	cipherBitsMap map[uint16]int
}

// NewCipherRegistry creates a new cipher registry with all supported ciphers
func NewCipherRegistry() *CipherRegistry {
	registry := &CipherRegistry{
		cipherMap:     make(map[string]uint16),
		cipherNameMap: make(map[uint16]string),
		cipherBitsMap: make(map[uint16]int),
	}

	// TLS 1.3 ciphers
	tls13Ciphers := []CipherInfo{
		{tls.TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", 128},
		{tls.TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", 256},
		{tls.TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256", 256},
	}

	// ECDHE ciphers
	ecdheCiphers := []CipherInfo{
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 128},
		{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 256},
		{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 128},
		{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 256},
		{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", 256},
		{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", 256},
	}

	// RSA ciphers
	rsaCiphers := []CipherInfo{
		{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256", 128},
		{tls.TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384", 256},
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA256, "TLS_RSA_WITH_AES_128_CBC_SHA256", 128},
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA", 128},
		{tls.TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA", 256},
		{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 168},
	}

	// Legacy ciphers
	legacyCiphers := []CipherInfo{
		{0x0004, "SSL_RSA_WITH_RC4_128_MD5", 128},
		{0x0005, "SSL_RSA_WITH_RC4_128_SHA", 128},
		{0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", 256},
		{0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 128},
		{0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 256},
		{0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 128},
		{0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 256},
	}

	// Register all ciphers
	allCiphers := append(append(append(tls13Ciphers, ecdheCiphers...), rsaCiphers...), legacyCiphers...)
	for _, cipher := range allCiphers {
		registry.cipherMap[cipher.Name] = cipher.ID
		registry.cipherNameMap[cipher.ID] = cipher.Name
		registry.cipherBitsMap[cipher.ID] = cipher.Bits
	}

	return registry
}

// GetCipherID returns the cipher ID for a given name
func (r *CipherRegistry) GetCipherID(name string) (uint16, bool) {
	id, exists := r.cipherMap[name]
	return id, exists
}

// GetCipherName returns the cipher name for a given ID
func (r *CipherRegistry) GetCipherName(id uint16) string {
	if name, exists := r.cipherNameMap[id]; exists {
		return name
	}
	return ""
}

// GetCipherBits returns the cipher bits for a given ID
func (r *CipherRegistry) GetCipherBits(id uint16) int {
	if bits, exists := r.cipherBitsMap[id]; exists {
		return bits
	}
	return -1
}

// ParseCipherString parses a cipher string and returns cipher IDs
func (r *CipherRegistry) ParseCipherString(cipherString string) []uint16 {
	var ciphers []uint16

	// Handle special keywords
	switch strings.ToUpper(cipherString) {
	case "ALL":
		// Return all available ciphers
		for _, cipher := range tls.CipherSuites() {
			ciphers = append(ciphers, cipher.ID)
		}
		return ciphers
	case "DEFAULT":
		// Return default ciphers (TLS 1.2+ secure ciphers)
		defaultCiphers := []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		}
		return defaultCiphers
	case "HIGH":
		// Return high security ciphers
		highCiphers := []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
		return highCiphers
	}

	// Handle comma-separated cipher lists
	if strings.Contains(cipherString, ",") {
		cipherNames := strings.Split(cipherString, ",")
		for _, name := range cipherNames {
			name = strings.TrimSpace(name)
			if id, exists := r.GetCipherID(name); exists {
				ciphers = append(ciphers, id)
			}
		}
		return ciphers
	}

	// Handle single cipher
	if id, exists := r.GetCipherID(cipherString); exists {
		ciphers = append(ciphers, id)
	}

	return ciphers
}

// GetCiphersToTest returns all ciphers for testing
func (r *CipherRegistry) GetCiphersToTest() []uint16 {
	var ciphers []uint16

	// Get all available ciphers from Go's crypto/tls package
	availableCiphers := tls.CipherSuites()
	for _, cipher := range availableCiphers {
		ciphers = append(ciphers, cipher.ID)
	}

	// Add additional legacy ciphers for comprehensive testing
	legacyCiphers := []uint16{
		0x0004, 0x0005, 0x000A, // SSLv3 ciphers
		0x002F, 0x0035, 0x003C, 0x003D, // TLS 1.0/1.1 ciphers
		0xC013, 0xC014, 0xC027, 0xC028, // ECDHE ciphers
	}

	ciphers = append(ciphers, legacyCiphers...)
	return ciphers
}

// Global registry instance
var GlobalCipherRegistry = NewCipherRegistry()
