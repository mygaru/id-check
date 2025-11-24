package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/mygaru/id-check/pkg/proxy"
	"github.com/valyala/fasthttp"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// todo add more http flags & metrics
var (
	httpServerListenAddr = flag.String("mtlsServerListenAddr", ":443", "")
)

var (
	mtlsServerCertPath       = flag.String("mtlsServerCertPath", "", "Path to file containing server certificate")
	mtlsServerPrivateKeyPath = flag.String("mtlsServerPrivateKeyPath", "", "Path to file containing private key corresponding to server certificate")
	mtlsServerMaxBodySize    = flag.Int("mtlsServerMaxBodySize", 536870912, "Max request body size")
	mtlsCrlCheckInterval     = flag.Duration("mtlsCrlCheckInterval", 10*time.Second, "How often to refresh myGaru CRL")
)

var (
	// contains Revocation List
	crlAtomic    atomic.Value
	crlLastCheck atomic.Value
)

func RunServer(handler fasthttp.RequestHandler) {
	caCertPool, err := createCaPool()
	if err != nil {
		log.Fatalf("Failed to create CA pool: %s", err)
	}

	cert, err := tls.LoadX509KeyPair(*mtlsServerCertPath, *mtlsServerPrivateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load certificate pair: %s", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			cert := verifiedChains[0][0]
			issuerCert := verifiedChains[0][len(verifiedChains[0])-1]

			log.Printf("Validating server certificate with CRL (serial: %s)", cert.SerialNumber.String())

			err := queryCRL(cert, issuerCert)
			if err != nil {
				log.Printf("CRL query failed: %s", err)
				return err
			}

			log.Printf("Certificate CRL check successful.")
			return nil
		},
	}

	ln, err := net.Listen("tcp", *httpServerListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %s", err)
	}

	lnTls := tls.NewListener(ln, tlsConfig)

	s := &fasthttp.Server{
		Handler:            handler,
		MaxRequestBodySize: *mtlsServerMaxBodySize,
	}

	if err := s.Serve(lnTls); err != nil {
		log.Fatalf("Failed to serve: %s", err)
	}
}

func setCRL(crlURL string) error {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	req.SetRequestURI(crlURL)
	req.Header.SetMethod(fasthttp.MethodGet)

	defer func() {
		fasthttp.ReleaseResponse(resp)
		fasthttp.ReleaseRequest(req)
	}()

	client, err := proxy.GetClient(req, crlURL)
	if err != nil {
		return fmt.Errorf("failed to get proxy client: %w", err)
	}

	log.Printf("\n\n REQUEST: %s \n\n", req.String())

	err = client.DoTimeout(req, resp, 10*time.Second)
	if err != nil {
		return err
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		return fmt.Errorf("got code %d when trying to get CRL from %s: %s", resp.StatusCode(), crlURL, string(resp.Body()))
	}

	crl, err := x509.ParseRevocationList(resp.Body())
	if err != nil {
		return err
	}

	crlAtomic.Store(crl)
	crlLastCheck.Store(time.Now())
	return nil
}

func queryCRL(cert *x509.Certificate, issuerCert *x509.Certificate) error {
	if crlAtomic.Load() == nil || time.Now().Sub(crlLastCheck.Load().(time.Time)) >= *mtlsCrlCheckInterval {

		if len(cert.CRLDistributionPoints) != 1 {
			return fmt.Errorf("expected 1 distribution point in issuer certificate, got: %v", issuerCert.CRLDistributionPoints)
		}

		log.Printf("[*] Trying to renew CRL from %q. Len URL = %d", cert.CRLDistributionPoints[0], len(cert.CRLDistributionPoints[0]))

		err := setCRL(cert.CRLDistributionPoints[0])
		if err != nil {
			return fmt.Errorf("failed to renew CRL: %w", err)
		}
	}

	crl, ok := crlAtomic.Load().(*x509.RevocationList)
	if !ok {
		return errors.New("CRL Atomic Load failed")
	}

	log.Printf("[*] Checking CRL signature.")
	log.Printf("Issuer CN: %s", issuerCert.Subject.CommonName)
	log.Printf("CRL Issuer: %s", crl.Issuer.String())

	err := crl.CheckSignatureFrom(issuerCert)
	if err != nil {
		return err
	}

	log.Printf("[*] Checking CRL validity.")
	if crl.NextUpdate.Before(time.Now()) {
		return fmt.Errorf("CRL is outdated")
	}

	log.Printf("[*] Searching for our certificate...")
	for _, revokedCertificate := range crl.RevokedCertificateEntries {
		log.Printf("[*] Revoked certificate serial: %s.", revokedCertificate.SerialNumber.String())
		if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			log.Printf("[-] Found validated certificate in list of revoked ones.")
			return fmt.Errorf("certificate was revoked")
		}
	}

	log.Printf("[+] Did not find validated certificate among revoked ones.")
	return nil
}
