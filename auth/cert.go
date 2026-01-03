package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"log"
)

type CertAuthenticator struct {
	caCertPool *x509.CertPool
	clientCerts map[string]*x509.Certificate // username -> certificate
}

func NewCertAuthenticator(caCertPath string) (*CertAuthenticator, error) {
	caCertPool := x509.NewCertPool()
	
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		
		block, _ := pem.Decode(caCert)
		if block == nil {
			return nil, fmt.Errorf("failed to decode CA certificate PEM")
		}
		
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		
		caCertPool.AddCert(cert)
		log.Printf("Certificate authenticator: Loaded CA certificate from %s", caCertPath)
	}
	
	return &CertAuthenticator{
		caCertPool:  caCertPool,
		clientCerts: make(map[string]*x509.Certificate),
	}, nil
}

func (c *CertAuthenticator) VerifyClientCert(conn *tls.Conn) (string, error) {
	state := conn.ConnectionState()
	
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate provided")
	}
	
	clientCert := state.PeerCertificates[0]
	
	opts := x509.VerifyOptions{
		Roots: c.caCertPool,
	}
	
	if _, err := clientCert.Verify(opts); err != nil {
		return "", fmt.Errorf("certificate verification failed: %w", err)
	}
	
	username := clientCert.Subject.CommonName
	if username == "" && len(clientCert.DNSNames) > 0 {
		username = clientCert.DNSNames[0]
	}
	
	if username == "" {
		return "", fmt.Errorf("no username found in certificate")
	}
	
	c.clientCerts[username] = clientCert
	
	log.Printf("Certificate authenticator: Verified certificate for user %s", username)
	return username, nil
}

func (c *CertAuthenticator) GetClientCert(username string) *x509.Certificate {
	return c.clientCerts[username]
}

func (c *CertAuthenticator) LoadClientCert(username, certPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read client certificate: %w", err)
	}
	
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode client certificate PEM")
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %w", err)
	}
	
	c.clientCerts[username] = cert
	log.Printf("Certificate authenticator: Loaded certificate for user %s from %s", username, certPath)
	return nil
}

