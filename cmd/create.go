package cmd

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/deitch/equinix-metal-k8s/internal"
	"github.com/packethost/packngo"
	"github.com/spf13/cobra"
)

const (
	defaultWaitDeviceReady = 300
	defaultWaitKubeReady   = 300
	defaultWaitInterval    = 15
)

var (
	controlPlaneCount, workerCount               int
	controlPlanePlan, workerPlan                 string
	metro, operatingSystem                       string
	port                                         int
	waitDeviceReady, waitKubeReady, waitInterval int
)

type node struct {
	purpose  string
	hostname string
	id       string
	ip       string
}

var createCmd = &cobra.Command{
	Use:   "init",
	Short: "initialize a Kubernetes cluster",
	Long:  `Initialize a Kubernetes cluster on Equinix Metal.`,
	Run: func(cmd *cobra.Command, args []string) {
		// get EQXM client
		client := packngo.NewClientWithAuth("equinix-metal-k8s", token, nil)
		client.UserAgent = fmt.Sprintf("equinix-metal-k8s/%s %s", version, client.UserAgent)

		// create CA: private key (RSA 2048), public key, self-signed cert, get its cert hash
		caPrivateKey, caPublicKey, caCert, err := internal.CreateCA("/CN=kubernetes", internal.RSA, 2048, 365*10)
		if err != nil {
			log.Fatal(err)
		}
		caCertificate, err := x509.ParseCertificate(caCert)
		if err != nil {
			log.Fatal(err)
		}
		caKeyDER, err := x509.MarshalPKIXPublicKey(caPublicKey)
		if err != nil {
			log.Fatal(err)
		}
		caCertHash := fmt.Sprintf("sha256:%x", sha256.Sum256(caKeyDER))

		// generate certs encryption key, equivalent to `kubeadm certs certificate-key`, which should be 32 byte = 64 chars in hex
		certsEncryptionKey, err := internal.GenerateCertsEncryptionKey()
		if err != nil {
			log.Fatal(err)
		}

		// create client: private key (RSA 2048), CSR, sign it via CA
		clientKey, clientCert, err := internal.CreateClient("/CN=kubernetes-admin/O=system:masters", internal.RSA, 2048, 365, caCertificate, caPrivateKey)
		if err != nil {
			log.Fatal(err)
		}

		// we need them in PEM in various places
		caKeyPEM, err := internal.PrivateKeyToPEM(caPrivateKey)
		if err != nil {
			log.Fatal(err)
		}
		caCertPEM, err := internal.CertificateToPEM(caCert)
		if err != nil {
			log.Fatal(err)
		}
		clientKeyPEM, err := internal.PrivateKeyToPEM(clientKey)
		if err != nil {
			log.Fatal(err)
		}
		clientCertPEM, err := internal.CertificateToPEM(clientCert)
		if err != nil {
			log.Fatal(err)
		}

		// generate bootstrap token, equivalent to `kubeadm token create`, which should give [a-z0-9]{6}.[a-z0-9]{16}
		token, err := internal.GenerateBootstrapToken()
		if err != nil {
			log.Fatal(err)
		}

		// request EIP
		res, _, err := client.ProjectIPs.Create(project, &packngo.IPReservationCreateRequest{
			Type:     packngo.PublicIPv4,
			Quantity: 1,
			Metro:    &metro,
		})
		if err != nil {
			log.Fatal(err)
		}
		eipAddress := res.Address
		eipCidr := res.CIDR

		// create kubeconfig using CA cert, client key, client cert, EIP endpoint
		kubeconfig, err := internal.GenerateKubeconfig(caCertPEM, clientCertPEM, clientKeyPEM, eipAddress)
		if err != nil {
			log.Fatal(err)
		}

		// to track all of our nodes
		var nodes []node
		// deploy init control plane node
		userdata := fmt.Sprintf(`
#!/bin/sh
curl https://raw.githubusercontent.com/deitch/kubeadm-install/master/install.sh | sh -s init -r containerd -a "%s:%d" -b "%s" -k "%s" -c "%s" -e "%s"
`, eipAddress, port, token, base64.StdEncoding.EncodeToString(caKeyPEM), base64.StdEncoding.EncodeToString(caCertPEM), certsEncryptionKey)
		hostname := fmt.Sprintf("k8s-master-%02d", 1)
		dev, _, err := client.Devices.Create(&packngo.DeviceCreateRequest{
			Hostname:  hostname,
			Plan:      controlPlanePlan,
			Metro:     metro,
			OS:        operatingSystem,
			ProjectID: project,
			UserData:  userdata,
		})
		if err != nil {
			log.Fatal(err)
		}
		nodes = append(nodes, node{
			hostname: hostname,
			id:       dev.ID,
			purpose:  "control plane",
		})
		devID := dev.ID

		// wait for init control plane device to be ready
		ticker := time.NewTicker(time.Duration(waitInterval) * time.Second)
	waitForDevice:
		for {
			select {
			case <-ticker.C:
				dev, _, err := client.Devices.Get(devID, nil)
				if err != nil {
					log.Printf("error getting device, but still waiting: %v", err)
				}
				if dev.State == "active" {
					log.Printf("device ready")
					break waitForDevice
				}
			case <-time.After(time.Duration(waitDeviceReady) * time.Second):
				ticker.Stop()
				log.Fatalf("device failed to report ready after %d seconds", waitDeviceReady)
			}
		}
		// if we made it here, the device is ready
		ticker.Stop()

		// assign EIP to init control plane node
		if _, _, err := client.DeviceIPs.Assign(devID, &packngo.AddressStruct{
			Address: fmt.Sprintf("%s/%d", eipAddress, eipCidr),
		}); err != nil {
			log.Fatal(err)
		}

		// wait for kube-apiserver to be ready
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient := &http.Client{Transport: tr}
		healthAddress := fmt.Sprintf("https://%s:%d/healthz", eipAddress, port)

		ticker = time.NewTicker(time.Duration(waitInterval) * time.Second)
	waitForKubernetes:
		for {
			select {
			case <-ticker.C:
				res, err := httpClient.Get(healthAddress)
				switch {
				case err != nil:
					log.Printf("error getting kubernetes health, still waiting: %v", err)
				case res.StatusCode == http.StatusOK:
					log.Print("Kubernetes ready")
					break waitForKubernetes
				default:
					log.Printf("Kubernetes API server responding, but did not return health %d, waiting", res.StatusCode)
				}
				continue
			case <-time.After(time.Duration(waitKubeReady) * time.Second):
				ticker.Stop()
				log.Fatalf("kubernetes failed to report ready after %d seconds", waitKubeReady)
			}
		}
		// if we made it here, the device is ready
		ticker.Stop()

		// apply CNI

		// create other control plane nodes
		for i := 2; i <= controlPlaneCount; i++ {
			userdata := fmt.Sprintf(`
#!/bin/sh
curl https://raw.githubusercontent.com/deitch/kubeadm-install/master/install.sh | sh -s join -r containerd -a "%s:%d" -b "%s" -h "%s" -e "%s"
`, eipAddress, port, token, caCertHash, certsEncryptionKey)
			hostname := fmt.Sprintf("k8s-master-%02d", i)
			dev, _, err := client.Devices.Create(&packngo.DeviceCreateRequest{
				Hostname:  hostname,
				Plan:      controlPlanePlan,
				Metro:     metro,
				OS:        operatingSystem,
				ProjectID: project,
				UserData:  userdata,
			})
			if err != nil {
				log.Fatal(err)
			}
			nodes = append(nodes, node{
				hostname: hostname,
				id:       dev.ID,
				purpose:  "control plane",
			})
		}

		// create worker nodes
		for i := 1; i <= workerCount; i++ {
			userdata := fmt.Sprintf(`
#!/bin/sh
curl https://raw.githubusercontent.com/deitch/kubeadm-install/master/install.sh | sh -s worker -r containerd -a "%s:%d" -b "%s" -h "%s"
`, eipAddress, port, token, caCertHash)
			hostname := fmt.Sprintf("k8s-worker-%02d", i)
			dev, _, err := client.Devices.Create(&packngo.DeviceCreateRequest{
				Hostname:  hostname,
				Plan:      workerPlan,
				Metro:     metro,
				OS:        operatingSystem,
				ProjectID: project,
				UserData:  userdata,
			})
			if err != nil {
				log.Fatal(err)
			}
			nodes = append(nodes, node{
				hostname: hostname,
				id:       dev.ID,
				purpose:  "worker",
			})
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", "Purpose", "Hostname", "ID", "IP")
		for _, node := range nodes {
			fmt.Printf("%s\t%s\t%s\t%s\n", node.purpose, node.hostname, node.id, node.ip)
		}
		// output kubeconfig
		fmt.Printf("%s\n", kubeconfig)
	},
}

func createInit() {
	createCmd.Flags().IntVar(&controlPlaneCount, "control-plane-count", 1, "number of control plane nodes")
	createCmd.Flags().IntVar(&workerCount, "worker-count", 0, "number of worker nodes")
	createCmd.Flags().StringVar(&metro, "metro", "da", "metro in which to create cluster")
	createCmd.Flags().StringVar(&operatingSystem, "os", "ubuntu_16_04", "slug of OS to use to create cluster")
	createCmd.Flags().StringVar(&controlPlanePlan, "control-plane-plan", "c3.small.x86", "device type to use for control plane nodes")
	createCmd.Flags().StringVar(&workerPlan, "worker-plan", "c3.small.x86", "device type to use for worker nodes")
	createCmd.Flags().IntVar(&port, "port", 6443, "port on which kube-apiserver should listen")
	createCmd.Flags().IntVar(&waitDeviceReady, "wait-device", defaultWaitDeviceReady, "how long to wait for device to be ready from Equinix Metal, in seconds")
	createCmd.Flags().IntVar(&waitKubeReady, "wait-kubernetes", defaultWaitKubeReady, "how long to wait for kubernetes to be ready after the device is ready, in seconds")
	createCmd.Flags().IntVar(&waitInterval, "wait-interval", defaultWaitInterval, "how often to check for device or kubernetes ready, in seconds")
}
