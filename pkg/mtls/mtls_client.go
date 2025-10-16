package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/valyala/fasthttp"
	"os"
)

var (
	mtlsCaCertPath           = flag.String("mtlsCaCertPath", "", "path to CA certificate; either specify this or the mtlsCaCertURL")
	mtlsCaCertURL            = flag.String("mtlsCaCertURL", "", "URL to get the CA certificate from; either specify this or the mtlsCaCertPath")
	mtlsClientCertPath       = flag.String("mtlsClientCertPath", "", "path to client certificate")
	mtlsClientPrivateKeyPath = flag.String("mtlsClientPrivateKeyPath", "", "path to client certificate's corresponding UNENCRYTPTED private key")
)

// NewClient creates an HTTP client with a TLS Config
// Use serverName when the Common Name or Alternative Names of the server's certificate do
// NOT correspond to its FQDN or IP. Set it as the server's CN.
func NewClient(serverName string) (*fasthttp.Client, error) {
	caCertPool, err := createCaPool()
	if err != nil {
		return nil, fmt.Errorf("error creating ca cert pool: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(*mtlsClientCertPath, *mtlsClientPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate pair: %w", err)
	}

	tlsCfg := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
	}

	httpClient := &fasthttp.Client{TLSConfig: tlsCfg}
	return httpClient, nil
}

func GetClientCertCN() (string, error) {
	if *mtlsClientCertPath == "" {
		return "", errors.New("mtlsClientCertPath is required")
	}

	cert, err := tls.LoadX509KeyPair(*mtlsClientCertPath, *mtlsClientPrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to load client certificate pair: %w", err)
	}

	return cert.Leaf.Subject.CommonName, nil
}

func GetClientCertPath() string {
	return *mtlsClientCertPath
}

func GetClientCertKeyPath() string {
	return *mtlsClientPrivateKeyPath
}

func GetCaCertPath() string {
	return *mtlsCaCertPath
}

func GetCaCertURL() string {
	return *mtlsCaCertURL
}

func createCaPool() (*x509.CertPool, error) {
	var caCert []byte
	var err error
	if *mtlsCaCertPath != "" {
		caCert, err = os.ReadFile(*mtlsCaCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from path %s: %w", *mtlsCaCertPath, err)
		}
	} else if *mtlsCaCertURL != "" {
		var code int
		code, caCert, err = fasthttp.Get(caCert, *mtlsCaCertURL)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from URL %s: %w", *mtlsCaCertURL, err)
		}

		if code != fasthttp.StatusOK {
			return nil, fmt.Errorf("failed to read CA certificate from URL %s: got %d, want %d", *mtlsCaCertURL, code, fasthttp.StatusOK)
		}

	} else {
		return nil, fmt.Errorf("must specify either flags mtlsCaCertURL or mtlsCaCertPath")
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return caCertPool, nil
}
