package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/valyala/fasthttp"
	"gitlab.adtelligent.com/common/shared/log"
	"os"
	"sync"
	"time"
)

var (
	mtlsCaCertPath           = flag.String("mtlsCaCertPath", "", "path to CA certificate; either specify this or the mtlsCaCertURL")
	mtlsCaCertURL            = flag.String("mtlsCaCertURL", "", "URL to get the CA certificate from; either specify this or the mtlsCaCertPath")
	mtlsClientCertPath       = flag.String("mtlsClientCertPath", "", "path to client certificate")
	mtlsClientPrivateKeyPath = flag.String("mtlsClientPrivateKeyPath", "", "path to client certificate's corresponding UNENCRYTPTED private key")
)

var client *fasthttp.Client
var once sync.Once

func InitClient() {
	once.Do(func() {
		cl, err := initClient()
		if err != nil {
			log.Fatalf("Failed to init mTLS client: %v", err)
		}

		client = cl
		log.Infof("Init mTLS client successfully.")
	})
}

// SendReqEncrypted will send your request using a TLS Config built from the flags you indicated.
// It returns an error if any and the response is returned back in resp.
// Recommended to call InitClient() at app initialization to not fatal your app when calling SendReqEncrypted.
//
// Use serverName when the Common Name or Alternative Names of the server's certificate do
// NOT correspond to its FQDN or IP. Set it as the server's CN.
func SendReqEncrypted(req *fasthttp.Request, resp *fasthttp.Response, serverName string, timeout time.Duration) error {
	InitClient()

	if serverName != "" {
		client.TLSConfig.ServerName = serverName
	}

	log.Debugf(req.String())

	return client.DoTimeout(req, resp, timeout)
}

func initClient() (*fasthttp.Client, error) {
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
	}

	// todo add more settings
	return &fasthttp.Client{TLSConfig: tlsCfg}, nil
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
