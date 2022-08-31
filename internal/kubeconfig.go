package internal

import (
	"encoding/base64"

	// use this yaml provider, otherwise it gets messed up
	"sigs.k8s.io/yaml"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func GenerateKubeconfig(caCertPEM, clientCertPEM, clientKeyPEM []byte, address string) ([]byte, error) {

	caCertB64 := make([]byte, base64.StdEncoding.EncodedLen(len(caCertPEM)))
	base64.StdEncoding.Encode(caCertB64, caCertPEM)

	clientCertB64 := make([]byte, base64.StdEncoding.EncodedLen(len(clientCertPEM)))
	base64.StdEncoding.Encode(clientCertB64, clientCertPEM)

	clientKeyB64 := make([]byte, base64.StdEncoding.EncodedLen(len(clientKeyPEM)))
	base64.StdEncoding.Encode(clientKeyB64, clientKeyPEM)

	clusters := make(map[string]*clientcmdapi.Cluster)
	clusters["default-cluster"] = &clientcmdapi.Cluster{
		Server:                   address,
		CertificateAuthorityData: caCertB64,
	}

	contexts := make(map[string]*clientcmdapi.Context)
	contexts["default-context"] = &clientcmdapi.Context{
		Cluster:  "default-cluster",
		AuthInfo: "default-user",
	}

	authinfos := make(map[string]*clientcmdapi.AuthInfo)
	authinfos["default-user"] = &clientcmdapi.AuthInfo{
		ClientKeyData:         clientKeyB64,
		ClientCertificateData: clientCertB64,
	}

	clientConfig := clientcmdapi.Config{
		Kind:           "Config",
		APIVersion:     "v1",
		Clusters:       clusters,
		Contexts:       contexts,
		CurrentContext: "default-context",
		AuthInfos:      authinfos,
	}
	return yaml.Marshal(&clientConfig)
}
