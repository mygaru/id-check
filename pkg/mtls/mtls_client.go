package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
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

type Client struct {
	httpClient *fasthttp.Client
	serverName string
}

// SendReqEncrypted will send your request using a TLS Config built from the flags you indicated.
// It returns an error if any and the response is returned back in resp.
func (client *Client) SendReqEncrypted(req *fasthttp.Request, resp *fasthttp.Response, timeout time.Duration) error {
	return client.httpClient.DoTimeout(req, resp, timeout)
}

// InitClient creates an HTTP client with a TLS Config
// Use serverName when the Common Name or Alternative Names of the server's certificate do
// NOT correspond to its FQDN or IP. Set it as the server's CN.
func InitClient(serverName string) (*Client, error) {
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

	// todo add more settings
	httpClient := &fasthttp.Client{TLSConfig: tlsCfg}

	return &Client{httpClient: httpClient}, nil
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
		// todo
	} else {
		return nil, fmt.Errorf("must specify either flags mtlsCaCertURL or mtlsCaCertPath")
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return caCertPool, nil
}
