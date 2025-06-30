package output

import (
	"encoding/xml"
	"fmt"
	"os"

	"github.com/conectabase/sslscan/internal/models"
	"github.com/conectabase/sslscan/pkg/utils"
)

// OutputManager manages output in different formats
type OutputManager struct {
	options *models.SSLCheckOptions
}

// NewOutputManager creates a new output manager
func NewOutputManager(options *models.SSLCheckOptions) *OutputManager {
	return &OutputManager{
		options: options,
	}
}

// WriteResults writes results in all configured formats
func (om *OutputManager) WriteResults(results *models.ScanResult) error {
	// Output default (console)
	if err := om.writeConsole(results); err != nil {
		return fmt.Errorf("error in console output: %v", err)
	}

	// Output XML
	if om.options.XMLOutput != nil {
		if err := om.writeXML(results); err != nil {
			return fmt.Errorf("error in XML output: %v", err)
		}
	}

	// Output JUnit
	if om.options.JUnitOutput != nil {
		if err := om.writeJUnit(results); err != nil {
			return fmt.Errorf("error in JUnit output: %v", err)
		}
	}

	return nil
}

// writeConsole writes results to the console
func (om *OutputManager) writeConsole(results *models.ScanResult) error {
	fmt.Printf("\nSSL Scan Results for %s:%d\n", results.Host, results.Port)
	fmt.Printf("Scan completed in %v\n\n", results.Duration)

	// Display protocols
	if len(results.Protocols) > 0 {
		fmt.Println("Supported Protocols:")
		for _, protocol := range results.Protocols {
			status := "Disabled"
			if protocol.Enabled {
				status = "Enabled"
			}
			security := "Insecure"
			if protocol.Secure {
				security = "Secure"
			}
			fmt.Printf("  %s (%s) - %s - %s\n", protocol.Protocol, protocol.Version, status, security)
		}
		fmt.Println()
	}

	// Display ciphers
	if len(results.Ciphers) > 0 {
		fmt.Println("Supported Cipher Suites:")
		for _, cipher := range results.Ciphers {
			status := "Rejected"
			if cipher.Accepted {
				status = "Accepted"
			}
			fmt.Printf("  %s (%d bits) - %s\n", cipher.Name, cipher.Bits, status)
		}
		fmt.Println()
	}

	// Display certificate information
	if results.Certificate != nil {
		fmt.Println("Certificate Information:")
		fmt.Printf("  Subject: %s\n", results.Certificate.Subject)
		fmt.Printf("  Issuer: %s\n", results.Certificate.Issuer)
		fmt.Printf("  Valid From: %s\n", results.Certificate.ValidFrom.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Valid To: %s\n", results.Certificate.ValidTo.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Key Size: %d bits\n", results.Certificate.KeySize)
		fmt.Printf("  Signature Algorithm: %s\n", results.Certificate.SignatureAlgorithm)
		fmt.Printf("  Public Key Algorithm: %s\n", results.Certificate.PublicKeyAlgorithm)
		fmt.Println()
	}

	// Display vulnerabilities
	if len(results.Vulnerabilities) > 0 {
		fmt.Println("Vulnerabilities Found:")
		for _, vuln := range results.Vulnerabilities {
			fmt.Printf("  %s (%s) - %s\n", vuln.Name, vuln.Severity, vuln.Description)
			if vuln.CVE != "" {
				fmt.Printf("    CVE: %s\n", vuln.CVE)
			}
		}
		fmt.Println()
	}

	// Display errors
	if len(results.Errors) > 0 {
		fmt.Println("Errors:")
		for _, err := range results.Errors {
			fmt.Printf("  %v\n", err)
		}
		fmt.Println()
	}

	return nil
}

// writeXML writes results to XML file
func (om *OutputManager) writeXML(results *models.ScanResult) error {
	// Open file if needed
	file := om.options.XMLOutput.File
	if file.Handle == nil {
		var err error
		file.Handle, err = os.Create(file.Path)
		if err != nil {
			return utils.NewIOError("failed to create XML file", err)
		}
		defer file.Handle.Close()
	}

	// XML structure
	type XMLResults struct {
		XMLName         xml.Name `xml:"sslscan"`
		Host            string   `xml:"host,attr"`
		Port            int      `xml:"port,attr"`
		ScanTime        string   `xml:"scan_time,attr"`
		Duration        string   `xml:"duration,attr"`
		Protocols       []struct {
			Name    string `xml:"name,attr"`
			Version string `xml:"version,attr"`
			Enabled bool   `xml:"enabled,attr"`
			Secure  bool   `xml:"secure,attr"`
			Details string `xml:"details,attr"`
		} `xml:"protocol"`
		Ciphers []struct {
			ID          uint16 `xml:"id,attr"`
			Name        string `xml:"name,attr"`
			Bits        int    `xml:"bits,attr"`
			Accepted    bool   `xml:"accepted,attr"`
			Description string `xml:"description,attr"`
		} `xml:"cipher"`
		Certificate *struct {
			Subject            string `xml:"subject,attr"`
			Issuer             string `xml:"issuer,attr"`
			ValidFrom          string `xml:"valid_from,attr"`
			ValidTo            string `xml:"valid_to,attr"`
			KeySize            int    `xml:"key_size,attr"`
			SignatureAlgorithm string `xml:"signature_algorithm,attr"`
		} `xml:"certificate,omitempty"`
		Vulnerabilities []struct {
			Name        string `xml:"name,attr"`
			Severity    string `xml:"severity,attr"`
			Description string `xml:"description,attr"`
			CVE         string `xml:"cve,attr,omitempty"`
		} `xml:"vulnerability"`
	}

	// Build XML structure
	xmlResults := XMLResults{
		Host:     results.Host,
		Port:     results.Port,
		ScanTime: results.ScanTime.Format("2006-01-02 15:04:05"),
		Duration: results.Duration.String(),
	}

	// Add protocols
	for _, protocol := range results.Protocols {
		xmlResults.Protocols = append(xmlResults.Protocols, struct {
			Name    string `xml:"name,attr"`
			Version string `xml:"version,attr"`
			Enabled bool   `xml:"enabled,attr"`
			Secure  bool   `xml:"secure,attr"`
			Details string `xml:"details,attr"`
		}{
			Name:    protocol.Protocol,
			Version: protocol.Version,
			Enabled: protocol.Enabled,
			Secure:  protocol.Secure,
			Details: protocol.Details,
		})
	}

	// Add ciphers
	for _, cipher := range results.Ciphers {
		xmlResults.Ciphers = append(xmlResults.Ciphers, struct {
			ID          uint16 `xml:"id,attr"`
			Name        string `xml:"name,attr"`
			Bits        int    `xml:"bits,attr"`
			Accepted    bool   `xml:"accepted,attr"`
			Description string `xml:"description,attr"`
		}{
			ID:          cipher.ID,
			Name:        cipher.Name,
			Bits:        cipher.Bits,
			Accepted:    cipher.Accepted,
			Description: cipher.Description,
		})
	}

	// Add certificate
	if results.Certificate != nil {
		xmlResults.Certificate = &struct {
			Subject            string `xml:"subject,attr"`
			Issuer             string `xml:"issuer,attr"`
			ValidFrom          string `xml:"valid_from,attr"`
			ValidTo            string `xml:"valid_to,attr"`
			KeySize            int    `xml:"key_size,attr"`
			SignatureAlgorithm string `xml:"signature_algorithm,attr"`
		}{
			Subject:            results.Certificate.Subject,
			Issuer:             results.Certificate.Issuer,
			ValidFrom:          results.Certificate.ValidFrom.Format("2006-01-02 15:04:05"),
			ValidTo:            results.Certificate.ValidTo.Format("2006-01-02 15:04:05"),
			KeySize:            results.Certificate.KeySize,
			SignatureAlgorithm: results.Certificate.SignatureAlgorithm,
		}
	}

	// Add vulnerabilities
	for _, vuln := range results.Vulnerabilities {
		xmlResults.Vulnerabilities = append(xmlResults.Vulnerabilities, struct {
			Name        string `xml:"name,attr"`
			Severity    string `xml:"severity,attr"`
			Description string `xml:"description,attr"`
			CVE         string `xml:"cve,attr,omitempty"`
		}{
			Name:        vuln.Name,
			Severity:    vuln.Severity,
			Description: vuln.Description,
			CVE:         vuln.CVE,
		})
	}

	// Encode to XML
	encoder := xml.NewEncoder(file.Handle)
	encoder.Indent("", "  ")
	if err := encoder.Encode(xmlResults); err != nil {
		return utils.NewIOError("failed to encode XML", err)
	}

	return nil
}

// writeJUnit writes results to JUnit XML file
func (om *OutputManager) writeJUnit(results *models.ScanResult) error {
	// Open file if needed
	file := om.options.JUnitOutput.File
	if file.Handle == nil {
		var err error
		file.Handle, err = os.Create(file.Path)
		if err != nil {
			return utils.NewIOError("failed to create JUnit file", err)
		}
		defer file.Handle.Close()
	}

	// JUnit structure
	type JUnitTestSuite struct {
		XMLName    xml.Name `xml:"testsuite"`
		Name       string   `xml:"name,attr"`
		Host       string   `xml:"host,attr"`
		Port       int      `xml:"port,attr"`
		Tests      int      `xml:"tests,attr"`
		Failures   int      `xml:"failures,attr"`
		Errors     int      `xml:"errors,attr"`
		Time       string   `xml:"time,attr"`
		TestCases  []struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Time      string `xml:"time,attr,omitempty"`
			Failure   *struct {
				Message string `xml:"message,attr"`
				Details string `xml:",chardata"`
			} `xml:"failure,omitempty"`
			Error *struct {
				Message string `xml:"message,attr"`
			} `xml:"error,omitempty"`
		} `xml:"testcase"`
	}

	type JUnitResults struct {
		XMLName     xml.Name `xml:"testsuites"`
		TestSuites  []JUnitTestSuite `xml:"testsuite"`
	}

	// Calculate statistics
	totalTests := len(results.Protocols) + len(results.Ciphers) + len(results.Vulnerabilities)
	totalFailures := 0
	totalErrors := len(results.Errors)

	// Count failures (insecure protocols, vulnerabilities, etc.)
	for _, protocol := range results.Protocols {
		if protocol.Enabled && !protocol.Secure {
			totalFailures++
		}
	}
	totalFailures += len(results.Vulnerabilities)

	// Create test suite
	testSuite := JUnitTestSuite{
		Name:     "SSLScan Security Tests",
		Host:     results.Host,
		Port:     results.Port,
		Tests:    totalTests,
		Failures: totalFailures,
		Errors:   totalErrors,
		Time:     results.Duration.String(),
	}

	// Add test cases for protocols
	for _, protocol := range results.Protocols {
		testCase := struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Time      string `xml:"time,attr,omitempty"`
			Failure   *struct {
				Message string `xml:"message,attr"`
				Details string `xml:",chardata"`
			} `xml:"failure,omitempty"`
			Error *struct {
				Message string `xml:"message,attr"`
			} `xml:"error,omitempty"`
		}{
			Name:      fmt.Sprintf("Protocol %s", protocol.Protocol),
			ClassName: "SSLScan.ProtocolTest",
		}

		if protocol.Enabled && !protocol.Secure {
			testCase.Failure = &struct {
				Message string `xml:"message,attr"`
				Details string `xml:",chardata"`
			}{
				Message: "Insecure protocol enabled",
				Details: fmt.Sprintf("Protocol %s is enabled but not secure", protocol.Protocol),
			}
		}

		testSuite.TestCases = append(testSuite.TestCases, testCase)
	}

	// Add test cases for ciphers
	for _, cipher := range results.Ciphers {
		testCase := struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Time      string `xml:"time,attr,omitempty"`
			Failure   *struct {
				Message string `xml:"message,attr"`
				Details string `xml:",chardata"`
			} `xml:"failure,omitempty"`
			Error *struct {
				Message string `xml:"message,attr"`
			} `xml:"error,omitempty"`
		}{
			Name:      fmt.Sprintf("Cipher %s", cipher.Name),
			ClassName: "SSLScan.CipherTest",
			Time:      cipher.Duration.String(),
		}

		if cipher.Accepted {
			testCase.Failure = &struct {
				Message string `xml:"message,attr"`
				Details string `xml:",chardata"`
			}{
				Message: "Weak cipher accepted",
				Details: fmt.Sprintf("Cipher %s is accepted", cipher.Name),
			}
		}

		testSuite.TestCases = append(testSuite.TestCases, testCase)
	}

	// Add test cases for vulnerabilities
	for _, vuln := range results.Vulnerabilities {
		testCase := struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Time      string `xml:"time,attr,omitempty"`
			Failure   *struct {
				Message string `xml:"message,attr"`
				Details string `xml:",chardata"`
			} `xml:"failure,omitempty"`
			Error *struct {
				Message string `xml:"message,attr"`
			} `xml:"error,omitempty"`
		}{
			Name:      fmt.Sprintf("Vulnerability %s", vuln.Name),
			ClassName: "SSLScan.VulnerabilityTest",
		}

		testCase.Failure = &struct {
			Message string `xml:"message,attr"`
			Details string `xml:",chardata"`
		}{
			Message: fmt.Sprintf("%s vulnerability found", vuln.Severity),
			Details: vuln.Description,
		}

		testSuite.TestCases = append(testSuite.TestCases, testCase)
	}

	// Create final results
	junitResults := JUnitResults{
		TestSuites: []JUnitTestSuite{testSuite},
	}

	// Encode to XML
	encoder := xml.NewEncoder(file.Handle)
	encoder.Indent("", "  ")
	if err := encoder.Encode(junitResults); err != nil {
		return utils.NewIOError("failed to encode JUnit XML", err)
	}

	return nil
}
