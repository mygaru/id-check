package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/mygaru/id-check/pkg/proxy"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fastjson"
	"log"
	"net"
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
	mtlsReputationUrl        = flag.String("mtlsReputationUrl", "https://ca.mygaru.com/reputation", "Where to check cert status")
	mtlsServerProxyEnabled   = flag.Bool("mtlsServerProxyEnabled", false, "Whether to enable proxy to get CA certificate")
)

func RunServer(handler fasthttp.RequestHandler) {
	caCertPool, err := createCaPool(*mtlsServerProxyEnabled)
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
			log.Printf("Validating server certificate with CRL (serial: %s)", cert.SerialNumber.String())

			status, reason, err := CheckCertReputation(cert, *mtlsServerProxyEnabled)
			if err != nil {
				return fmt.Errorf("error checking reputation: %s", err)
			}

			log.Printf("Cert %s has status=%s reason=%s", cert.SerialNumber.String(), status, reason)

			switch status {
			case CertStatusRevoked:
				return fmt.Errorf("revoked certificate: %s", reason)
			case CertStatusGood:
				return nil
			case CertStatusUnknown:
				return fmt.Errorf("certificate with unkown status")
			default:
				return fmt.Errorf("unkown status type: %s", status)
			}
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

const (
	CertStatusRevoked = "revoked"
	CertStatusGood    = "good"
	CertStatusUnknown = "unknown"
)

// CheckCertReputation checks reputation of cert, and returns status, reason, and error
func CheckCertReputation(cert *x509.Certificate, proxyEnabled bool) (string, string, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	defer func() {
		fasthttp.ReleaseResponse(resp)
		fasthttp.ReleaseRequest(req)
	}()

	url := *mtlsReputationUrl + "/" + cert.SerialNumber.String()

	log.Printf("Checking reputation of %s", url)

	client, err := proxy.GetClient(req, url, proxyEnabled)
	if err != nil {
		return "", "", fmt.Errorf("failed to get proxy client: %w", err)
	}

	req.SetRequestURI(url)
	req.Header.SetMethod(fasthttp.MethodGet)

	err = client.DoTimeout(req, resp, 10*time.Second)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		return "", "", fmt.Errorf("wanted 200 OK, got %d: %s", resp.StatusCode(), resp.Body())
	}

	v, err := fastjson.ParseBytes(resp.Body())
	if err != nil {
		return "", "", fmt.Errorf("failed to parse bytes: %w", err)
	}

	v = v.Get("0")

	status := v.GetStringBytes("status")
	if len(status) == 0 {
		return "", "", fmt.Errorf("no status in json body: %s", resp.Body())
	}

	return string(status), string(v.GetStringBytes("reason")), nil

}
