package internal

import "fmt"

func GenerateBootstrapToken() (string, error) {
	firstHalf, err := randomString(6)
	if err != nil {
		return "", err
	}
	secondHalf, err := randomString(16)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s", firstHalf, secondHalf), nil
}
