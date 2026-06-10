package mygaru

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/mygaru/id-check/pkg/provider"
	"github.com/mygaru/id-check/pkg/proxy"
	"github.com/valyala/fasthttp"
	"net/url"
	"time"
)

var (
	myGaruCaCertUpdateURL = flag.String("myGaruCaCertUpdateURL", "https://ca.mygaru.com/cert", "URL for CA certificates update")
)

type CaProvider struct{}

// GetNewCert requests the new cert from our CA using the old cert
func (p *CaProvider) GetNewCert(certPath, keyPath string, pollEvery, maxWait time.Duration) (*provider.CaResponse, error) {
	if maxWait <= 0 {
		maxWait = 2 * time.Minute
	}

	if pollEvery <= 0 {
		pollEvery = 10 * time.Second
	}

	client, err := newClient(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create MTLS client: %w", err)
	}

	client.ReadTimeout = 30 * time.Second
	client.WriteTimeout = 30 * time.Second

	deadline := time.Now().Add(maxWait)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetRequestURI(*myGaruCaCertUpdateURL)
	req.Header.SetContentType("application/json")
	req.SetBody([]byte(`{}`))

	for {
		if err = client.DoTimeout(req, resp, 10*time.Second); err != nil {
			return nil, err
		}

		code := resp.StatusCode()
		body := append([]byte(nil), resp.Body()...)

		switch code {
		case fasthttp.StatusAccepted:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout waiting for CA issuance")
			}

			time.Sleep(pollEvery)

		case fasthttp.StatusOK:
			var r provider.CaResponse

			if err = json.Unmarshal(body, &r); err != nil {
				return nil, fmt.Errorf("failed to decode CA response: %w", err)
			}

			if r.Chain == "" || r.Key == "" || r.Chain == "null" || r.Key == "null" {
				return nil, fmt.Errorf("empty CHAIN/Key (status=%s reason=%s)", r.Status, r.Reason)
			}

			return &r, nil

		default:
			return nil, fmt.Errorf("invalid status code %d: %s", code, string(body))
		}
	}
}

// newClient returns HTTP client with the TLS config containing the cert from the path
func newClient(certPath, keyPath string) (*fasthttp.Client, error) {
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		systemPool = x509.NewCertPool()
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate pair: %w", err)
	}

	httpClient, err := proxy.GetClient(*myGaruCaCertUpdateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	u, err := url.Parse(*myGaruCaCertUpdateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mtlsCaCertUpdateURL: %w", err)
	}

	httpClient.TLSConfig = &tls.Config{
		RootCAs:      systemPool,
		Certificates: []tls.Certificate{cert},
		ServerName:   u.Hostname(),
	}

	return httpClient, nil
}
