package main

import (
	"fmt"
	"log"

	"github.com/conectabase/sslscan/internal/config"
	"github.com/conectabase/sslscan/internal/models"
	"github.com/conectabase/sslscan/pkg/output"
	"github.com/conectabase/sslscan/pkg/ssl"
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
