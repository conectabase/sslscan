package models

import (
	"net"
	"os"
	"time"
)

// SSLCipher representa um cipher SSL/TLS
type SSLCipher struct {
	Name        string
	Version     string
	Bits        int
	Description string
	Next        *SSLCipher
}

// SSLCheckOptions contém todas as opções de configuração para o scan
type SSLCheckOptions struct {
	// Configurações básicas
	Host            string
	Port            int
	SNIName         string
	SNISet          bool
	AddrStr         string
	Verbose         bool
	ShowTimes       bool
	ShowCipherIds   bool
	ShowCipherDetails bool

	// Configurações de teste
	ShowCertificate     bool
	ShowCertificates    bool
	CheckCertificate    bool
	ShowTrustedCAs      bool
	ShowClientCiphers   bool
	TestRenegotiation   bool
	TestFallback        bool
	TestCompression     bool
	TestHeartbleed      bool
	TestSupportedGroups bool
	TestSignatureAlgorithms bool
	TestMissingCiphers  bool

	// Configurações de rede
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IPv4           bool
	IPv6           bool

	// Configurações de saída
	XMLOutput   *OutputWriter
	JUnitOutput *OutputWriter

	// Configurações SSL/TLS
	SSLVersion     int
	CipherString   string
	ClientCertsFile string
	PrivateKeyFile string
	PrivateKeyPassword string

	// Resultados dos testes
	TLS10Supported bool
	TLS11Supported bool
	TLS12Supported bool
	TLS13Supported bool
}

// OutputWriter gerencia a saída para diferentes formatos
type OutputWriter struct {
	File     *File
	IsStdout bool
}

// File representa um arquivo de saída
type File struct {
	Path   string
	Handle *os.File
}

// TestResult representa o resultado de um teste individual
type TestResult struct {
	Name        string
	Status      TestStatus
	Description string
	Duration    time.Duration
	Error       error
	Details     map[string]interface{}
}

// TestStatus representa o status de um teste
type TestStatus int

const (
	TestStatusUnknown TestStatus = iota
	TestStatusPass
	TestStatusFail
	TestStatusWarning
	TestStatusInfo
)

// CertificateInfo contém informações sobre um certificado
type CertificateInfo struct {
	Subject     string
	Issuer      string
	ValidFrom   time.Time
	ValidTo     time.Time
	SerialNumber string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	KeySize     int
	DNSNames    []string
	IPAddresses []net.IP
	Extensions  map[string]interface{}
}

// CipherSuiteInfo contém informações sobre um cipher suite
type CipherSuiteInfo struct {
	ID          uint16
	Name        string
	Version     string
	Bits        int
	Description string
	Accepted    bool
	Duration    time.Duration
}

// ProtocolTestResult contém o resultado de um teste de protocolo
type ProtocolTestResult struct {
	Protocol string
	Version  string
	Enabled  bool
	Secure   bool
	Details  string
}

// ScanResult contém o resultado completo do scan
type ScanResult struct {
	Host            string
	Port            int
	ScanTime        time.Time
	Duration        time.Duration
	Protocols       []ProtocolTestResult
	Ciphers         []CipherSuiteInfo
	Certificate     *CertificateInfo
	Vulnerabilities []Vulnerability
	Errors          []error
}

// Vulnerability representa uma vulnerabilidade encontrada
type Vulnerability struct {
	Name        string
	Severity    string
	Description string
	CVE         string
	Details     map[string]interface{}
}
