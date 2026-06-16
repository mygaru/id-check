package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/mygaru/id-check/pkg/provider/mygaru"
	"github.com/mygaru/id-check/pkg/proxy"
	"github.com/mygaru/id-check/pkg/updater"
	"github.com/valyala/fasthttp"
	"log"
	"os"
	"sync/atomic"
	"time"
)

var (
	mtlsCaCertPath             = flag.String("mtlsCaCertPath", "", "path to CA certificate; either specify this or the mtlsCaCertURL")
	mtlsCaCertURL              = flag.String("mtlsCaCertURL", "", "URL to get the CA certificate from; either specify this or the mtlsCaCertPath")
	mtlsClientCertPath         = flag.String("mtlsClientCertPath", "", "path to client certificate")
	mtlsClientPrivateKeyPath   = flag.String("mtlsClientPrivateKeyPath", "", "path to client certificate's corresponding UNENCRYTPTED private key")
	mtlsCertCheckInterval      = flag.Duration("mtlsCertCheckInterval", 24*time.Hour, "how often to check the client certificate for remaining time")
	mtlsCertExpirationInterval = flag.Duration("mtlsCertExpirationInterval", 7*24*time.Hour, "cert expiration threshold")
)

var certStore atomic.Value

// Deprecated
func GetClientCertPath() string {
	return *mtlsClientCertPath
}

// Deprecated
func GetClientCertKeyPath() string {
	return *mtlsClientPrivateKeyPath
}

// Deprecated
func GetCaCertPath() string {
	return *mtlsCaCertPath
}

// Deprecated
func GetCaCertURL() string {
	return *mtlsCaCertURL
}

func Init() {
	_, err := loadCert()
	if err != nil {
		log.Fatal(err)
	}

	// new cert updater that will retrieve certs from myGaru's CA
	cm := updater.NewCertUpdater(*mtlsCertExpirationInterval, &mygaru.CaProvider{})

	target := &updater.CertTarget{
		Name:     "mtlsClientCert",
		CertPath: *mtlsClientCertPath,
		KeyPath:  *mtlsClientPrivateKeyPath}

	newCert, err := cm.UpdateCert(target)
	if err != nil {
		log.Fatalf("Error updating cert name=%s: %v", target.Name, err)
	}

	if newCert != nil {
		certStore.Store(newCert)
		log.Printf("Added cert name=%s to certStore.", target.Name)
	}

	go func() {
		t := time.NewTicker(*mtlsCertCheckInterval)
		for range t.C {
			newCert, err := cm.UpdateCert(target)
			if err != nil {
				log.Printf("Error updating cert name=%s: %v", target.Name, err)
			}

			if newCert != nil {
				certStore.Store(newCert)
				log.Printf("Added cert name=%s to certStore.", target.Name)
			}
		}
	}()

}

// NewClient creates an HTTP client with a TLS Config
// Use serverName when the Common Name or Alternative Names of the server's certificate do
// NOT correspond to its FQDN or IP. Set it as the server's CN.
func NewClient(serverName string) (*fasthttp.Client, error) {
	tlsCfg, err := GetMTLSConfig(serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to create tls config: %w", err)
	}

	httpClient := &fasthttp.Client{TLSConfig: tlsCfg}
	return httpClient, nil
}

// GetMTLSConfig builds and returns a reusable *tls.Config for mTLS connections.
func GetMTLSConfig(serverName string) (*tls.Config, error) {
	caCertPool, err := createCaPool()
	if err != nil {
		return nil, fmt.Errorf("error creating CA pool: %w", err)
	}

	cert, err := loadCert()
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{*cert},
		ServerName:   serverName,
	}

	return tlsCfg, nil
}

func GetClientCertCN() (string, error) {
	if *mtlsClientCertPath == "" {
		return "", errors.New("mtlsClientCertPath is required")
	}

	cert, err := loadCert()
	if err != nil {
		return "", err
	}

	return cert.Leaf.Subject.CommonName, nil
}

func loadCert() (*tls.Certificate, error) {
	cert := certStore.Load()
	if cert != nil {
		return cert.(*tls.Certificate), nil
	}

	log.Println("No certificate found in certStore, reading from disk.")

	c, err := tls.LoadX509KeyPair(*mtlsClientCertPath, *mtlsClientPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate pair: %w", err)
	}

	certStore.Store(&c)
	log.Printf("Loaded cert to certStore CN=%s serial=%v.", c.Leaf.Subject.CommonName, c.Leaf.SerialNumber)

	return &c, nil
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
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer func() {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}()

		req.SetRequestURI(*mtlsCaCertURL)
		req.Header.SetMethod(fasthttp.MethodGet)

		client, err := proxy.GetClient(*mtlsCaCertURL)
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
