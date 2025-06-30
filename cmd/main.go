package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/sslscan/sslscan-go/internal/config"
	"github.com/sslscan/sslscan-go/pkg/output"
	"github.com/sslscan/sslscan-go/pkg/ssl"
	"github.com/sslscan/sslscan-go/pkg/utils"
)

var (
	cfg *config.Config
)

func main() {
	cfg = config.NewConfig()

	rootCmd := &cobra.Command{
		Use:   "sslscan-go [host]",
		Short: "SSL/TLS security scanner written in Go",
		Long: `sslscan-go is a comprehensive SSL/TLS security scanner that tests for:
- Supported protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3)
- Cipher suites and their security
- Certificate analysis and validation
- Known vulnerabilities (Heartbleed, CRIME, etc.)
- Security misconfigurations

Example usage:
  sslscan-go example.com
  sslscan-go --port 8443 --xml results.xml example.com
  sslscan-go --junit results.xml --verbose example.com`,
		Args: cobra.MaximumNArgs(1),
		RunE: runScan,
	}

	// Configurar flags
	config.SetupFlags(rootCmd)

	// Flags de ajuda e versão
	rootCmd.Flags().BoolVarP(&cfg.Help, "help", "h", false, "Show help")
	rootCmd.Flags().BoolVar(&cfg.Version, "version", false, "Show version")

	// Executar comando
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Load config from flags
	if err := cfg.LoadFromFlags(cmd, args); err != nil {
		return err
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %v", err)
	}

	// Show help if requested
	if cfg.Help {
		return cmd.Help()
	}

	// Show version if requested
	if cfg.Version {
		fmt.Printf("sslscan-go version 1.0.0\n")
		return nil
	}

	// Check if host was provided
	if len(args) == 0 {
		return fmt.Errorf("host is required. Use --help for more information")
	}

	// Run scan
	return executeScan()
}

func executeScan() error {
	// Create scanner
	scanner := ssl.NewScanner(cfg.Options)

	// Run scan
	results, err := scanner.Scan()
	if err != nil {
		return utils.NewConnectionError("scan failed", err)
	}

	// Create output manager
	outputManager := output.NewOutputManager(cfg.Options)

	// Write results
	if err := outputManager.WriteResults(results); err != nil {
		return utils.NewIOError("failed to write results", err)
	}

	return nil
}
