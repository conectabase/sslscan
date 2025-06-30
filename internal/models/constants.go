package models

import "time"

// SSL/TLS version constants
const (
	SSLAll  = 0
	SSLV2   = 1
	SSLV3   = 2
	TLSAll  = 3
	TLSV10  = 4
	TLSV11  = 5
	TLSV12  = 6
	TLSV13  = 7
)

// Operation modes
const (
	ModeHelp     = 0
	ModeVersion  = 1
	ModeSingle   = 2
	ModeMultiple = 3
)

// Buffer sizes
const (
	BufferSize = 1024
)

// Default timeouts
const (
	DefaultConnectTimeout = 10 * time.Second
	DefaultReadTimeout    = 30 * time.Second
	DefaultWriteTimeout   = 30 * time.Second
)

// Default ports
const (
	DefaultHTTPSPort = 443
	DefaultHTTPPort  = 80
)

// Vulnerability severity levels
const (
	VulnSeverityLow      = "LOW"
	VulnSeverityMedium   = "MEDIUM"
	VulnSeverityHigh     = "HIGH"
	VulnSeverityCritical = "CRITICAL"
)

// Signature algorithms
const (
	SigAlgRSA     = "RSA"
	SigAlgDSA     = "DSA"
	SigAlgECDSA   = "ECDSA"
	SigAlgEd25519 = "Ed25519"
	SigAlgEd448   = "Ed448"
)

// Hash algorithms
const (
	HashMD5    = "MD5"
	HashSHA1   = "SHA1"
	HashSHA256 = "SHA256"
	HashSHA384 = "SHA384"
	HashSHA512 = "SHA512"
)

// Program banner
const ProgramBanner = `                   _
           ___ ___| |___  ___ __ _ _ __
          / __/ __| / __|/ __/ _` + "`" + ` | '_ \
          \__ \__ \ \__ \ (_| (_| | | | |
          |___/___/_|___/\___\__,_|_| |_|

`

// Color codes for console output
type Colors struct {
	Reset    string
	Red      string
	Green    string
	Yellow   string
	Blue     string
	Purple   string
	Grey     string
	RedBg    string
}

// ConsoleColors provides color codes for different platforms
var ConsoleColors = Colors{
	Reset:    "\033[0m",
	Red:      "\033[31m",
	Green:    "\033[32m",
	Yellow:   "\033[33m",
	Blue:     "\033[1;34m",
	Purple:   "\033[35m",
	Grey:     "\033[1;30m",
	RedBg:    "\033[41m",
}

// WindowsColors provides color codes for Windows
var WindowsColors = Colors{
	Reset:    "\033[0m",
	Red:      "\033[91m",
	Green:    "\033[92m",
	Yellow:   "\033[93m",
	Blue:     "\033[1;36m",
	Purple:   "\033[95m",
	Grey:     "\033[1;30m",
	RedBg:    "\033[41m",
}
