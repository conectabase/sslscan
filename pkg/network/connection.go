package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/sslscan/sslscan-go/internal/models"
	"github.com/sslscan/sslscan-go/pkg/utils"
)

// Connection represents a network connection
type Connection struct {
	conn    net.Conn
	tlsConn *tls.Conn
	options *models.SSLCheckOptions
}

// NewConnection creates a new connection
func NewConnection(options *models.SSLCheckOptions) *Connection {
	return &Connection{
		options: options,
	}
}

// Connect establishes a TCP connection to the host
func (c *Connection) Connect() error {
	address := fmt.Sprintf("%s:%d", c.options.Host, c.options.Port)

	// Configure dialer with timeout
	dialer := &net.Dialer{
		Timeout: c.options.ConnectTimeout,
	}

	// Try to connect
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return utils.NewConnectionError(fmt.Sprintf("failed to connect to %s", address), err)
	}

	c.conn = conn
	return nil
}

// ConnectTLS establishes a TLS connection
func (c *Connection) ConnectTLS() error {
	// First connect TCP
	if err := c.Connect(); err != nil {
		return err
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // For security testing
		ServerName:         c.options.Host,
	}

	// If SNI is configured, use it
	if c.options.SNISet {
		tlsConfig.ServerName = c.options.SNIName
	}

	// Configure client certificates if provided
	if c.options.ClientCertsFile != "" && c.options.PrivateKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.options.ClientCertsFile, c.options.PrivateKeyFile)
		if err != nil {
			return utils.NewCertificateError("failed to load client certificate", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Configure min and max version based on options
	switch c.options.SSLVersion {
	case models.SSLV2:
		tlsConfig.MinVersion = tls.VersionSSL30 // SSLv2 not supported by Go
		tlsConfig.MaxVersion = tls.VersionSSL30
	case models.SSLV3:
		tlsConfig.MinVersion = tls.VersionSSL30
		tlsConfig.MaxVersion = tls.VersionSSL30
	case models.TLSV10:
		tlsConfig.MinVersion = tls.VersionTLS10
		tlsConfig.MaxVersion = tls.VersionTLS10
	case models.TLSV11:
		tlsConfig.MinVersion = tls.VersionTLS11
		tlsConfig.MaxVersion = tls.VersionTLS11
	case models.TLSV12:
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
	case models.TLSV13:
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
	default:
		// Use all supported versions
		tlsConfig.MinVersion = tls.VersionSSL30
		tlsConfig.MaxVersion = tls.VersionTLS13
	}

	// Configure cipher string if provided
	if c.options.CipherString != "" {
		ciphers := utils.GlobalCipherRegistry.ParseCipherString(c.options.CipherString)
		tlsConfig.CipherSuites = ciphers
	}

	// Configure timeouts
	_, cancel := context.WithTimeout(context.Background(), c.options.ConnectTimeout)
	defer cancel()

	// Establish TLS connection
	tlsConn := tls.Client(c.conn, tlsConfig)

	// Set deadline for handshake
	tlsConn.SetDeadline(time.Now().Add(c.options.ConnectTimeout))

	if err := tlsConn.Handshake(); err != nil {
		return utils.NewTLSError("failed TLS handshake", err)
	}

	c.tlsConn = tlsConn
	return nil
}

// GetConnectionState returns the TLS connection state
func (c *Connection) GetConnectionState() *tls.ConnectionState {
	if c.tlsConn != nil {
		state := c.tlsConn.ConnectionState()
		return &state
	}
	return nil
}

// GetPeerCertificates returns the peer certificates
func (c *Connection) GetPeerCertificates() []*x509.Certificate {
	if c.tlsConn != nil {
		return c.tlsConn.ConnectionState().PeerCertificates
	}
	return nil
}

// GetCipherSuite returns the negotiated cipher suite
func (c *Connection) GetCipherSuite() uint16 {
	if c.tlsConn != nil {
		return c.tlsConn.ConnectionState().CipherSuite
	}
	return 0
}

// GetVersion returns the negotiated TLS version
func (c *Connection) GetVersion() uint16 {
	if c.tlsConn != nil {
		return c.tlsConn.ConnectionState().Version
	}
	return 0
}

// Write sends data through the connection
func (c *Connection) Write(data []byte) error {
	if c.tlsConn != nil {
		c.tlsConn.SetWriteDeadline(time.Now().Add(c.options.WriteTimeout))
		_, err := c.tlsConn.Write(data)
		return err
	}
	if c.conn != nil {
		c.conn.SetWriteDeadline(time.Now().Add(c.options.WriteTimeout))
		_, err := c.conn.Write(data)
		return err
	}
	return utils.NewConnectionError("no connection established", nil)
}

// Read reads data from the connection
func (c *Connection) Read(buffer []byte) (int, error) {
	if c.tlsConn != nil {
		c.tlsConn.SetReadDeadline(time.Now().Add(c.options.ReadTimeout))
		return c.tlsConn.Read(buffer)
	}
	if c.conn != nil {
		c.conn.SetReadDeadline(time.Now().Add(c.options.ReadTimeout))
		return c.conn.Read(buffer)
	}
	return 0, utils.NewConnectionError("no connection established", nil)
}

// Close closes the connection
func (c *Connection) Close() error {
	if c.tlsConn != nil {
		return c.tlsConn.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// IsConnected checks if the connection is active
func (c *Connection) IsConnected() bool {
	return c.tlsConn != nil || c.conn != nil
}

// GetLocalAddr returns the local address
func (c *Connection) GetLocalAddr() net.Addr {
	if c.tlsConn != nil {
		return c.tlsConn.LocalAddr()
	}
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return nil
}

// GetRemoteAddr returns the remote address
func (c *Connection) GetRemoteAddr() net.Addr {
	if c.tlsConn != nil {
		return c.tlsConn.RemoteAddr()
	}
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return nil
}
