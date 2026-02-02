package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func Configure(CAcertFile string, certFile string, keyFile string, clientCertAuth bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading certificate and key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	var CAcert *x509.CertPool

	if CAcertFile != "" {
		caPEM, err := os.ReadFile(CAcertFile)
		if err != nil {
			return nil, fmt.Errorf("loading CA certificate: %w", err)
		}

		CAcert = x509.NewCertPool()
		if !CAcert.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to append CA certificate to pool")
		}
		if clientCertAuth {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = CAcert
		}
		tlsConfig.RootCAs = CAcert
	}

	return tlsConfig, nil
}
