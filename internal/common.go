package internal

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

type KeyType int

const (
	RSA KeyType = iota
	Ed25519
	ECDSA
)

func generateKeyPair(keyType KeyType, size int) (crypto.PrivateKey, crypto.PublicKey, error) {
	var (
		privateKey, publicKey interface{}
		err                   error
	)
	reader := rand.Reader
	switch keyType {
	case RSA:
		rsaPrivateKey, perr := rsa.GenerateKey(reader, size)
		privateKey = rsaPrivateKey
		err = perr
		publicKey = rsaPrivateKey.Public()
	case Ed25519:
		publicKey, privateKey, err = ed25519.GenerateKey(reader)
	case ECDSA:
		curve := elliptic.P256()
		ecdsaPrivateKey, perr := ecdsa.GenerateKey(curve, reader)
		privateKey = ecdsaPrivateKey
		err = perr
		publicKey = ecdsaPrivateKey.Public()
	default:
		return nil, nil, fmt.Errorf("unknown key type: %v", keyType)
	}

	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func PrivateKeyToPEM(privateKey interface{}) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	privateKeyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, privateKeyPem); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func CertificateToPEM(b []byte) ([]byte, error) {
	return CertificatesToPEM([][]byte{b})
}

func CertificatesToPEM(bs [][]byte) ([]byte, error) {
	var buf bytes.Buffer
	for _, b := range bs {
		certPem := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		err := pem.Encode(&buf, certPem)
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// unfortunately, the golang library does not make it easy to parse DN
func parseSubject(subject string) (*pkix.Name, error) {
	var (
		err  error
		name pkix.Name
	)
	// the separator character could be escaped, so we cannot just blindly split on it
	separator := ','
	if len(subject) > 0 && subject[0] == '/' {
		separator = '/'
		subject = subject[1:]
	}
	// hold the current string
	current := make([]rune, 0)
	for _, c := range subject {
		if c != separator || (len(current) > 0 && current[len(current)-1] == '\\') {
			current = append(current, c)
			continue
		}
		// we are at a separator
		if err = populateName(&name, current); err != nil {
			return nil, err
		}
		// reset our current
		current = make([]rune, 0)
	}
	// do not miss anything at the end
	if len(current) > 0 {
		if err = populateName(&name, current); err != nil {
			return nil, err
		}
	}
	return &name, nil
}

func populateName(name *pkix.Name, rdn []rune) error {
	// split on the first =
	parts := strings.SplitN(string(rdn), "=", 2)
	switch parts[0] {
	case "C":
		name.Country = []string{parts[1]}
	case "O":
		name.Organization = []string{parts[1]}
	case "OU":
		name.OrganizationalUnit = []string{parts[1]}
	case "ST":
		name.Province = []string{parts[1]}
	case "L":
		name.Locality = []string{parts[1]}
	case "CN":
		name.CommonName = parts[1]
	default:
		return fmt.Errorf("unknown RDN: %s", string(rdn))
	}
	return nil
}

func signCert(template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.PrivateKey) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
}

func randomString(length int) (string, error) {
	charset := "abcdefghijklmnopqrstuvwxyz0123456789"
	size := int64(len(charset))
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(size))
		if err != nil {
			return "", err
		}
		ret[i] = charset[num.Int64()]
	}
	return string(ret), nil

}

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func PublicPEMToDER(pubKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKeyPEM)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return keyDER, nil
}

func RandomHex(size int) (string, error) {
	b, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
