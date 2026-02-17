package main

import (
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/crypto/pkcs12"
)

// PFXToPEM converts a PFX/PKCS12 file to PEM-encoded certificate chain and private key.
// Tries the Go pkcs12 library first, falls back to openssl CLI for newer PFX formats.
// Returns (certPEM, keyPEM, error).
func PFXToPEM(pfxData []byte, password string) ([]byte, []byte, error) {
	certPEM, keyPEM, err := pfxToPEMNative(pfxData, password)
	if err != nil {
		// Fall back to openssl for newer PFX formats (SHA-256, AES)
		certPEM, keyPEM, err = pfxToPEMOpenSSL(pfxData, password)
		if err != nil {
			return nil, nil, err
		}
	}
	return certPEM, keyPEM, nil
}

// pfxToPEMNative uses the Go pkcs12 library (supports legacy 3DES/SHA1 formats).
func pfxToPEMNative(pfxData []byte, password string) ([]byte, []byte, error) {
	blocks, err := pkcs12.ToPEM(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PFX: %w", err)
	}

	var certPEM, keyPEM []byte
	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			keyPEM = append(keyPEM, pem.EncodeToMemory(block)...)
		}
	}

	if len(certPEM) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in PFX")
	}
	if len(keyPEM) == 0 {
		return nil, nil, fmt.Errorf("no private key found in PFX")
	}

	return certPEM, keyPEM, nil
}

// pfxToPEMOpenSSL shells out to openssl for PFX formats not supported by the Go library.
func pfxToPEMOpenSSL(pfxData []byte, password string) ([]byte, []byte, error) {
	// Write PFX to temp file
	tmpPFX, err := os.CreateTemp("", "cert-*.pfx")
	if err != nil {
		return nil, nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmpPFX.Name())
	if _, err := tmpPFX.Write(pfxData); err != nil {
		tmpPFX.Close()
		return nil, nil, fmt.Errorf("writing PFX temp file: %w", err)
	}
	tmpPFX.Close()

	// Extract certificates
	certOut, err := exec.Command("openssl", "pkcs12", "-in", tmpPFX.Name(),
		"-clcerts", "-nokeys", "-passin", "pass:"+password).CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("openssl extract certs failed: %s", string(certOut))
	}

	// Also extract CA chain if present
	caOut, _ := exec.Command("openssl", "pkcs12", "-in", tmpPFX.Name(),
		"-cacerts", "-nokeys", "-passin", "pass:"+password).CombinedOutput()

	// Extract private key
	keyOut, err := exec.Command("openssl", "pkcs12", "-in", tmpPFX.Name(),
		"-nocerts", "-nodes", "-passin", "pass:"+password).CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("openssl extract key failed: %s", string(keyOut))
	}

	// Parse out just the PEM blocks from openssl output (it includes extra text)
	certPEM := extractPEMBlocks(certOut)
	certPEM = append(certPEM, extractPEMBlocks(caOut)...)
	keyPEM := extractPEMBlocks(keyOut)

	if len(certPEM) == 0 {
		return nil, nil, fmt.Errorf("openssl: no certificates extracted from PFX")
	}
	if len(keyPEM) == 0 {
		return nil, nil, fmt.Errorf("openssl: no private key extracted from PFX")
	}

	return certPEM, keyPEM, nil
}

// extractPEMBlocks extracts all PEM blocks from openssl output which may contain
// extra text headers/footers.
func extractPEMBlocks(data []byte) []byte {
	var result []byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		result = append(result, pem.EncodeToMemory(block)...)
	}
	return result
}
