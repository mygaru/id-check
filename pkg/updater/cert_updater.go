package updater

import (
	"crypto/tls"
	"fmt"
	"github.com/mygaru/id-check/pkg/provider"
	"log"
	"os"
	"time"
)

type CertUpdater struct {
	ExpirationThreshold time.Duration
	Provider            provider.CertProvider
}

func NewCertUpdater(expirationThreshold time.Duration, p provider.CertProvider) *CertUpdater {
	return &CertUpdater{
		ExpirationThreshold: expirationThreshold,
		Provider:            p,
	}
}

type CertTarget struct {
	Name     string
	CertPath string
	KeyPath  string
}

type certInfo struct {
	path      string
	subjectCN string
	notBefore time.Time
	notAfter  time.Time
	remaining time.Duration
}

// UpdateCert replaces the cert & key path with an updated version from myGaru's CA
func (cm *CertUpdater) UpdateCert(ct *CertTarget) (*tls.Certificate, error) {
	_, oldCinfo, err := inspectCert(ct.CertPath, ct.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("inspect cert failed: %v", err)
	}

	if oldCinfo.remaining > cm.ExpirationThreshold {
		log.Printf("No need to update cert name=%s remaining=%v", ct.Name, oldCinfo.remaining)
		return nil, nil
	}

	log.Printf("Attempting to update cert name=%s remaining=%v path=%s", ct.Name, oldCinfo.remaining, ct.CertPath)

	poll := 5 * time.Second
	maxW := 1 * time.Minute

	caResp, err := cm.Provider.GetNewCert(ct.CertPath, ct.KeyPath, poll, maxW)
	if err != nil {
		return nil, fmt.Errorf("get cert failed: %v", err)
	}

	if err = write(ct.CertPath, []byte(caResp.Chain), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write cert: %w", err)
	}

	if err = write(ct.KeyPath, []byte(caResp.Key), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write key: %w", err)
	}

	cert, newCinfo, err := inspectCert(ct.CertPath, ct.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("inspect cert after update failed: %v", err)
	}

	if newCinfo.subjectCN != oldCinfo.subjectCN {
		return nil, fmt.Errorf("new cert CN does not match old cert CN (%s vs %s)", newCinfo.subjectCN, oldCinfo.subjectCN)
	}

	log.Printf("Updated cert name=%s serial=%s remaining=%v", ct.Name, cert.Leaf.SerialNumber, newCinfo.remaining)

	return cert, nil
}

func write(path string, data []byte, mode os.FileMode) error {
	backupPath := path + ".bak"

	err := os.Rename(path, backupPath)
	if err != nil {
		return fmt.Errorf("failed to backup old file: %w", err)
	}

	if err := os.WriteFile(path, data, mode); err != nil {
		renameErr := os.Rename(backupPath, path)
		if renameErr != nil {
			return fmt.Errorf("failed roll back old file %s", err)
		}

		return fmt.Errorf("failed to write new file, using old file: %w", err)
	}

	err = os.Remove(backupPath)
	if err != nil {
		log.Printf("Failed to remove backup binary %s: %v", backupPath, err)
	}

	return nil
}

// inspectCert returns detailed certificate information.
func inspectCert(certPath, keyPath string) (*tls.Certificate, *certInfo, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client certificate pair: %w", err)
	}

	now := time.Now()
	remaining := cert.Leaf.NotAfter.Sub(now)

	info := &certInfo{
		path:      certPath,
		subjectCN: cert.Leaf.Subject.CommonName,
		notBefore: cert.Leaf.NotBefore,
		notAfter:  cert.Leaf.NotAfter,
		remaining: remaining,
	}

	return &cert, info, nil
}
