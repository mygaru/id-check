package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/valyala/fasthttp"
	"gitlab.adtelligent.com/common/shared/log"
	"gitlab.adtelligent.com/common/shared/metric"
	"gitlab.adtelligent.com/common/shared/osexit"
	"net"
	"os"
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
	mtlsCrlURL               = flag.String("mtlsCrlURL", "", "URL of myGaru CRL")
	mtlsCrlCheckInterval     = flag.Duration("mtlsCrlCheckInterval", time.Hour, "How often to refresh myGaru CRL")
)

var (
	errorsFailedCrlRenewal = metric.NewCounter("errorsFailedCrlRenewal")
	errorsFailedCrlQuery   = metric.NewCounter("errorsFailedCrlQuery")
)

// contains Revocation List
var crlAtomic atomic.Value

func RunServer(handler fasthttp.RequestHandler) {
	err := checkCRL()
	if err != nil {
		log.Fatalf("CRL check failed: %s", err)
	}

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
			issuerCert := verifiedChains[0][1]

			log.Debugf("Validating server certificate with CRL (serial: %s)", cert.SerialNumber.String())

			err := queryCRL(cert, issuerCert)
			if err != nil {
				errorsFailedCrlQuery.Inc()
				log.Errorf("CRL query failed: %s", err)
				return err
			}

			log.Debugf("Certificate CRL check successful.")
			return nil
		},
	}

	ln, err := net.Listen("tcp", *httpServerListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %s", err)
	}

	lnTls := tls.NewListener(ln, tlsConfig)

	go func() {
		ticker := time.NewTicker(*mtlsCrlCheckInterval)

		for range ticker.C {
			err = checkCRL()
			if err != nil {
				errorsFailedCrlRenewal.Inc()
				log.Errorf("CRL check failed: %s", err)
			}
		}

		osexit.Before(func(signal os.Signal) {
			ticker.Stop()
		})
	}()

	if err := fasthttp.Serve(lnTls, handler); err != nil {
		log.Fatalf("Failed to serve: %s", err)
	}
}

func checkCRL() error {
	code, resp, err := fasthttp.GetTimeout(nil, *mtlsCrlURL, 10*time.Second)
	if err != nil {
		return err
	}

	if code != fasthttp.StatusOK {
		return fmt.Errorf("got code %d when trying to get CRL from %s: %s", code, *mtlsCrlURL, string(resp))
	}

	crl, err := x509.ParseRevocationList(resp)
	if err != nil {
		return err
	}

	crlAtomic.Store(crl)
	return nil
}

func queryCRL(cert *x509.Certificate, issuerCert *x509.Certificate) error {
	crl := crlAtomic.Load().(*x509.RevocationList)

	log.Debugf("[*] Checking CRL signature.")
	err := crl.CheckSignatureFrom(issuerCert)
	if err != nil {
		return err
	}

	log.Debugf("[*] Checking CRL validity.")
	if crl.NextUpdate.Before(time.Now()) {
		return fmt.Errorf("CRL is outdated")
	}

	log.Debugf("[*] Searching for our certificate...")
	for _, revokedCertificate := range crl.RevokedCertificateEntries {
		log.Debugf("[*] Revoked certificate serial: %s.", revokedCertificate.SerialNumber.String())
		if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			log.Debugf("[-] Found validated certificate in list of revoked ones.")
			return fmt.Errorf("certificate was revoked")
		}
	}

	log.Debugf("[+] Did not find validated certificate among revoked ones.")
	return nil
}
