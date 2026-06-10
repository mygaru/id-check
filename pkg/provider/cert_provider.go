package provider

import "time"

// CertProvider must implement a single function - getNewCert, which performs a HTTP request
// to get an updated version of a certificate and its key from some CA
type CertProvider interface {
	GetNewCert(certPath, keyPath string, pollEvery, maxWait time.Duration) (*CaResponse, error)
}

type CaResponse struct {
	CommonName string `json:"COMMON_NAME"`
	Serial     string `json:"SERIAL"`
	// Certificate
	Chain string `json:"CHAIN"`
	// Private key
	Key    string `json:"Key"`
	Status string `json:"Status"`
	Reason string `json:"reason"`
}
