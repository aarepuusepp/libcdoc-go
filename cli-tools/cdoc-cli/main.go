package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc"
	"github.com/aarepuusepp/libcdoc-go/v2/cert"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

const (
	version = "2.0.0"
	usage   = `cdoc - CDOC Encryption/Decryption Tool (libcdoc-go)

A command-line tool from libcdoc-go library for encrypting and decrypting
CDOC documents supporting CDOC 1.0, 1.1, and 2.0 formats.

Usage:
  cdoc encrypt [options]
  cdoc decrypt [options]

Commands:
  encrypt    Encrypt file(s) into a CDOC document
  decrypt    Decrypt file(s) from a CDOC document

Examples:
  # Encrypt a file with RSA certificate (CDOC 1.0/1.1)
  cdoc encrypt -f document.pdf -r cert.pem -o document.cdoc

  # Encrypt with CDOC 2.0
  cdoc encrypt -f document.pdf -r cert.pem -c 2.0 -o document.cdoc2

  # Encrypt with password (CDOC 2.0 only)
  cdoc encrypt -f document.pdf -p password -c 2.0 -o document.cdoc2

  # Decrypt a CDOC file with private key
  cdoc decrypt -f document.cdoc -k private_key.pem -o ./decrypted/

  # Decrypt CDOC 2.0 with password
  cdoc decrypt -f document.cdoc2 -p password -o ./decrypted/

Options:
`
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "encrypt", "e":
		runEncrypt(os.Args[2:])
	case "decrypt", "d":
		runDecrypt(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("cdoc version %s (libcdoc-go)\n", version)
		os.Exit(0)
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, usage)
}

func runEncrypt(args []string) {
	flags := flag.NewFlagSet("encrypt", flag.ExitOnError)
	var (
		fileFlag       = flags.String("f", "", "Input file(s) to encrypt (comma-separated or multiple -f flags)")
		recipientFlag  = flags.String("r", "", "Recipient certificate(s) (comma-separated, for CDOC 1.0/1.1/2.0)")
		passwordFlag   = flags.String("p", "", "Password for encryption (CDOC 2.0 only)")
		symmetricFlag  = flags.String("s", "", "Symmetric key file (32 bytes, CDOC 2.0 only)")
		outputFlag     = flags.String("o", "", "Output CDOC file (default: <first-input-file>.cdoc)")
		versionFlag    = flags.String("c", "1.1", "CDOC version (1.0, 1.1, or 2.0, default: 1.1)")
		iterationsFlag = flags.Int("iterations", 100000, "PBKDF2 iterations for password (CDOC 2.0, default: 100000)")
		helpFlag       = flags.Bool("h", false, "Show help")
	)

	flags.Parse(args)

	if *helpFlag {
		flags.Usage()
		return
	}

	if *fileFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: -f (files) is required\n\n")
		flags.Usage()
		os.Exit(1)
	}

	// Validate recipient requirements based on version
	isCDOC2 := *versionFlag == "2.0"
	hasRecipient := *recipientFlag != ""
	hasPassword := *passwordFlag != ""
	hasSymmetric := *symmetricFlag != ""

	if isCDOC2 {
		// CDOC 2.0: need at least one recipient type
		if !hasRecipient && !hasPassword && !hasSymmetric {
			fmt.Fprintf(os.Stderr, "Error: For CDOC 2.0, specify at least one recipient: -r (certificate), -p (password), or -s (symmetric key)\n\n")
			flags.Usage()
			os.Exit(1)
		}
	} else {
		// CDOC 1.0/1.1: require certificate recipient
		if !hasRecipient {
			fmt.Fprintf(os.Stderr, "Error: -r (recipients) is required for CDOC 1.0/1.1\n\n")
			flags.Usage()
			os.Exit(1)
		}
	}

	// Parse files
	files := parseList(*fileFlag, flags.Args())
	for _, arg := range flags.Args() {
		if strings.HasPrefix(arg, "-f") {
			// Already handled
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "Error: At least one input file is required\n")
		os.Exit(1)
	}

	// Parse version
	var cdocVersion cdoc.Version
	switch *versionFlag {
	case "1.0":
		cdocVersion = cdoc.Version10
	case "1.1":
		cdocVersion = cdoc.Version11
	case "2.0":
		cdocVersion = cdoc.Version20
	default:
		fmt.Fprintf(os.Stderr, "Error: Invalid CDOC version %s. Use 1.0, 1.1, or 2.0\n", *versionFlag)
		os.Exit(1)
	}

	// Determine output path
	outputPath := *outputFlag
	if outputPath == "" {
		firstFile := files[0]
		baseName := filepath.Base(firstFile)
		ext := ".cdoc"
		if cdocVersion == cdoc.Version20 {
			ext = ".cdoc2"
		}
		outputPath = strings.TrimSuffix(baseName, filepath.Ext(baseName)) + ext
	}

	// Parse certificate recipients (for CDOC 1.0/1.1 or CDOC 2.0)
	var recipients []string
	if *recipientFlag != "" {
		recipients = parseList(*recipientFlag, flags.Args())
		for _, arg := range flags.Args() {
			if strings.HasPrefix(arg, "-r") {
				continue
			}
		}
	}

	// Create builder
	builder := cdoc.NewBuilder()
	builder.Version(cdocVersion)

	// Load and add certificate recipients (for CDOC 1.0/1.1 or CDOC 2.0)
	if len(recipients) > 0 {
		for _, certPath := range recipients {
			certData, err := os.ReadFile(certPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to read certificate %s: %v\n", certPath, err)
				os.Exit(1)
			}

			certificate, err := cert.ParseCertificatePEM(certData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to parse certificate %s: %v\n", certPath, err)
				os.Exit(1)
			}

			if err := builder.WithRecipientCertificate(certificate); err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to add recipient: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Add password recipient (CDOC 2.0 only)
	if *passwordFlag != "" {
		if cdocVersion != cdoc.Version20 {
			fmt.Fprintf(os.Stderr, "Error: Password recipients are only supported in CDOC 2.0\n")
			os.Exit(1)
		}
		if err := builder.WithPasswordAndIterations(*passwordFlag, int32(*iterationsFlag)); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to add password recipient: %v\n", err)
			os.Exit(1)
		}
	}

	// Add symmetric key recipient (CDOC 2.0 only)
	if *symmetricFlag != "" {
		if cdocVersion != cdoc.Version20 {
			fmt.Fprintf(os.Stderr, "Error: Symmetric key recipients are only supported in CDOC 2.0\n")
			os.Exit(1)
		}
		keyData, err := os.ReadFile(*symmetricFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to read symmetric key file: %v\n", err)
			os.Exit(1)
		}
		if len(keyData) != 32 {
			fmt.Fprintf(os.Stderr, "Error: Symmetric key must be exactly 32 bytes (256 bits), got %d bytes\n", len(keyData))
			os.Exit(1)
		}
		if err := builder.WithSymmetricKey(keyData); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to add symmetric key recipient: %v\n", err)
			os.Exit(1)
		}
	}

	// Add data files
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to open file %s: %v\n", filePath, err)
			os.Exit(1)
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to stat file %s: %v\n", filePath, err)
			os.Exit(1)
		}

		builder.WithDataFile(info.Name(), file, info.Size())
	}

	// Build CDOC
	outputFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to create output file: %v\n", err)
		os.Exit(1)
	}
	defer outputFile.Close()

	if err := builder.BuildToWriter(outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to build CDOC: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully encrypted %d file(s) to %s\n", len(files), outputPath)
}

func runDecrypt(args []string) {
	flags := flag.NewFlagSet("decrypt", flag.ExitOnError)
	var (
		fileFlag      = flags.String("f", "", "CDOC file to decrypt")
		keyFlag       = flags.String("k", "", "Private key file (PEM format, for certificate-based decryption)")
		certFlag      = flags.String("c", "", "Certificate file (optional, for recipient selection)")
		passwordFlag  = flags.String("p", "", "Password (for CDOC 2.0 password-based decryption)")
		symmetricFlag = flags.String("s", "", "Symmetric key file (32 bytes, for CDOC 2.0 symmetric key decryption)")
		outputFlag    = flags.String("o", ".", "Output directory (default: current directory)")
		helpFlag      = flags.Bool("h", false, "Show help")
		// PKCS#12 flags
		pkcs12Flag   = flags.String("pkcs12", "", "PKCS#12 keystore file (.p12 or .pfx)")
		p12PassFlag  = flags.String("p12password", "", "PKCS#12 keystore password")
		p12AliasFlag = flags.String("p12alias", "", "PKCS#12 key alias (optional)")
		// PKCS#11 flags
		pkcs11Flag   = flags.String("pkcs11", "", "Use PKCS#11 token for decryption")
		p11LibFlag   = flags.String("library", "", "Path to PKCS#11 library (required for --pkcs11)")
		p11SlotFlag  = flags.Int("slot", 0, "PKCS#11 slot number (default: 0)")
		p11PinFlag   = flags.String("pin", "", "PKCS#11 token PIN (required for --pkcs11)")
		p11LabelFlag = flags.String("label", "", "PKCS#11 key label (optional)")
	)

	flags.Parse(args)

	if *helpFlag {
		flags.Usage()
		return
	}

	if *fileFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: -f (CDOC file) is required\n\n")
		flags.Usage()
		os.Exit(1)
	}

	// Create decrypter
	decrypter := cdoc.NewDecrypter()
	if err := decrypter.WithCDOCFromFile(*fileFlag); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to open CDOC file: %v\n", err)
		os.Exit(1)
	}

	// Determine decryption method: PKCS#11, PKCS#12, or regular private key
	if *pkcs11Flag != "" {
		// PKCS#11 token decryption
		if *p11LibFlag == "" || *p11PinFlag == "" {
			fmt.Fprintf(os.Stderr, "Error: --library and --pin are required when using --pkcs11\n")
			os.Exit(1)
		}

		config := key.PKCS11Config{
			Library: *p11LibFlag,
			Slot:    *p11SlotFlag,
			PIN:     *p11PinFlag,
			Label:   *p11LabelFlag,
		}

		if err := decrypter.WithPKCS11Token(config); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to initialize PKCS#11 token: %v\n", err)
			os.Exit(1)
		}
	} else if *pkcs12Flag != "" {
		// PKCS#12 keystore decryption
		if *p12PassFlag == "" {
			fmt.Fprintf(os.Stderr, "Error: --p12password is required when using --pkcs12\n")
			os.Exit(1)
		}

		var alias []string
		if *p12AliasFlag != "" {
			alias = []string{*p12AliasFlag}
		}

		if err := decrypter.WithPKCS12Token(*pkcs12Flag, *p12PassFlag, alias...); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to load PKCS#12 keystore: %v\n", err)
			os.Exit(1)
		}
	} else if *passwordFlag != "" {
		// Password-based decryption (CDOC 2.0)
		decrypter.WithPassword(*passwordFlag)
	} else if *symmetricFlag != "" {
		// Symmetric key-based decryption (CDOC 2.0)
		keyData, err := os.ReadFile(*symmetricFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to read symmetric key file: %v\n", err)
			os.Exit(1)
		}
		if len(keyData) != 32 {
			fmt.Fprintf(os.Stderr, "Error: Symmetric key must be exactly 32 bytes (256 bits), got %d bytes\n", len(keyData))
			os.Exit(1)
		}
		decrypter.WithSymmetricKey(keyData)
	} else {
		// Regular private key decryption (CDOC 1.0/1.1 or CDOC 2.0 certificate-based)
		if *keyFlag == "" {
			fmt.Fprintf(os.Stderr, "Error: Specify decryption method: -k (private key), -p (password), -s (symmetric key), --pkcs12, or --pkcs11\n\n")
			flags.Usage()
			os.Exit(1)
		}

		keyData, err := os.ReadFile(*keyFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to read private key: %v\n", err)
			os.Exit(1)
		}

		privateKey, err := key.ParsePrivateKeyPEM(keyData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to parse private key: %v\n", err)
			os.Exit(1)
		}

		decrypter.WithPrivateKey(privateKey)

		// Load certificate if provided
		if *certFlag != "" {
			certData, err := os.ReadFile(*certFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to read certificate: %v\n", err)
				os.Exit(1)
			}

			certificate, err := cert.ParseCertificatePEM(certData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to parse certificate: %v\n", err)
				os.Exit(1)
			}

			decrypter.WithCertificate(certificate)
		}
	}

	// Decrypt
	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to decrypt CDOC: %v\n", err)
		os.Exit(1)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(*outputFlag, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Write decrypted files
	for _, decryptedFile := range decryptedFiles {
		outputPath := filepath.Join(*outputFlag, decryptedFile.Name)

		// Handle file name collisions (like cdoc4j does)
		basePath := outputPath
		counter := 1
		for {
			if _, err := os.Stat(outputPath); os.IsNotExist(err) {
				break
			}
			ext := filepath.Ext(basePath)
			name := strings.TrimSuffix(basePath, ext)
			outputPath = fmt.Sprintf("%s_%d%s", name, counter, ext)
			counter++
		}

		if err := os.WriteFile(outputPath, decryptedFile.Content, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to write file %s: %v\n", outputPath, err)
			continue
		}

		fmt.Printf("Decrypted: %s -> %s\n", decryptedFile.Name, outputPath)
	}

	fmt.Printf("Successfully decrypted %d file(s) to %s\n", len(decryptedFiles), *outputFlag)
}

// parseList parses a comma-separated list or returns the first argument
func parseList(value string, args []string) []string {
	var result []string

	// Check for comma-separated values
	if strings.Contains(value, ",") {
		parts := strings.Split(value, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				result = append(result, part)
			}
		}
	} else if value != "" {
		result = append(result, value)
	}

	return result
}
