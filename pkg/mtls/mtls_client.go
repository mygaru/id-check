package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/mygaru/id-check/pkg/proxy"
	"github.com/valyala/fasthttp"
	"os"
	"time"
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
// Set proxyEnabled = true if you want the requests that get the CA to though proxy.
func NewClient(serverName string, proxyEnabled bool) (*fasthttp.Client, error) {
	tlsCfg, err := GetMTLSConfig(serverName, proxyEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create tls config: %w", err)
	}

	httpClient := &fasthttp.Client{TLSConfig: tlsCfg}
	return httpClient, nil
}

// GetMTLSConfig builds and returns a reusable *tls.Config for mTLS connections.
func GetMTLSConfig(serverName string, proxyEnabled bool) (*tls.Config, error) {
	caCertPool, err := createCaPool(proxyEnabled)
	if err != nil {
		return nil, fmt.Errorf("error creating CA pool: %w", err)
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

	return tlsCfg, nil
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

func createCaPool(proxyEnabled bool) (*x509.CertPool, error) {
	var caCert []byte
	var err error
	if *mtlsCaCertPath != "" {
		caCert, err = os.ReadFile(*mtlsCaCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from path %s: %w", *mtlsCaCertPath, err)
		}
	} else if *mtlsCaCertURL != "" {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer func() {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}()

		req.SetRequestURI(*mtlsCaCertURL)
		req.Header.SetMethod(fasthttp.MethodGet)

		client, err := proxy.GetClient(req, *mtlsCaCertURL, proxyEnabled)
		if err != nil {
			return nil, fmt.Errorf("failed to get proxy client: %w", err)
		}

		err = client.DoTimeout(req, resp, 30*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to get CA certificate from %s: %w", *mtlsCaCertURL, err)
		}

		if resp.StatusCode() != fasthttp.StatusOK {
			return nil, fmt.Errorf("failed to read CA certificate from URL %s: got %d, want %d", *mtlsCaCertURL, resp.StatusCode(), fasthttp.StatusOK)
		}

		caCert = resp.Body()

	} else {
		return nil, fmt.Errorf("must specify either flags mtlsCaCertURL or mtlsCaCertPath")
	}

	systemPool, err := x509.SystemCertPool()
	if err != nil {
		systemPool = x509.NewCertPool()
	}

	if !systemPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate: %s", caCert)
	}

	return systemPool, nil
}
