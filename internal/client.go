package internal

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"time"
)

func CreateClient(subject string, keyType KeyType, keySize, days int, caCert *x509.Certificate, caKey crypto.PrivateKey) (privateKey crypto.PrivateKey, cert []byte, err error) {
	privateKey, publicKey, err := generateKeyPair(keyType, keySize)
	if err != nil {
		log.Fatalf("error generating private key: %v", err)
	}
	name, err := parseSubject(subject)
	if err != nil {
		log.Fatalf("error parsing the subject: %v", err)
	}
	template := x509.CertificateRequest{
		Subject: *name,
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      template.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * time.Duration(days)),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	cert, err = signCert(&certTemplate, caCert, publicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %s", err)
	}
	return privateKey, cert, nil
}
