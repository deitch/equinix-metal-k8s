package internal

func GenerateCertsEncryptionKey() (string, error) {
	return RandomHex(32)
}
