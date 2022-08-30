package internal

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

func CreateCA(subject string, keyType KeyType, keySize, days int) (privateKey crypto.PrivateKey, publicKey crypto.PublicKey, cert []byte, err error) {
	privateKey, publicKey, err = generateKeyPair(keyType, keySize)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error generating private key: %v", err)
	}

	name, err := parseSubject(subject)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error parsing the subject: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      *name,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * time.Duration(days)),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err = signCert(&template, &template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	return privateKey, publicKey, cert, nil
}
