package main

import (
	"fmt"
	"log"

	"github.com/sslscan/sslscan-go/internal/config"
	"github.com/sslscan/sslscan-go/internal/models"
	"github.com/sslscan/sslscan-go/pkg/output"
	"github.com/sslscan/sslscan-go/pkg/ssl"
)

func main() {
	// Create config
	cfg := config.NewConfig()
	cfg.Options.Host = "google.com"
	cfg.Options.Port = 443
	cfg.Options.Verbose = true
	cfg.Options.ShowCertificate = true
	cfg.Options.TestHeartbleed = true
	cfg.Options.TestCompression = true

	// Configure outputs
	cfg.Options.XMLOutput = &models.OutputWriter{
		File: &models.File{Path: "results.xml"},
	}
	cfg.Options.JUnitOutput = &models.OutputWriter{
		File: &models.File{Path: "results-junit.xml"},
	}

	// Create scanner
	scanner := ssl.NewScanner(cfg.Options)

	// Run scan
	fmt.Println("Starting SSL/TLS scan...")
	results, err := scanner.Scan()
	if err != nil {
		log.Fatalf("Scan error: %v", err)
	}

	// Create output manager
	outputManager := output.NewOutputManager(cfg.Options)

	// Write results
	if err := outputManager.WriteResults(results); err != nil {
		log.Fatalf("Error writing results: %v", err)
	}

	fmt.Println("Scan completed successfully!")
}
