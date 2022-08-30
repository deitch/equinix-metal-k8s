package internal

import "fmt"

func GenerateCertsEncryptionKey() (string, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
