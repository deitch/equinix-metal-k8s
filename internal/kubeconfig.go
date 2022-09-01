package internal

import (

	// use this yaml provider, otherwise it gets messed up
	"sigs.k8s.io/yaml"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func GenerateKubeconfig(caCertPEM, clientCertPEM, clientKeyPEM []byte, address string) ([]byte, error) {

	clusters := make(map[string]*clientcmdapi.Cluster)
	clusters["default-cluster"] = &clientcmdapi.Cluster{
		Server:                   address,
		CertificateAuthorityData: caCertPEM,
	}

	contexts := make(map[string]*clientcmdapi.Context)
	contexts["default-context"] = &clientcmdapi.Context{
		Cluster:  "default-cluster",
		AuthInfo: "default-user",
	}

	authinfos := make(map[string]*clientcmdapi.AuthInfo)
	authinfos["default-user"] = &clientcmdapi.AuthInfo{
		ClientKeyData:         clientKeyPEM,
		ClientCertificateData: clientCertPEM,
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
