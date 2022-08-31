# equinix-metal-k8s

Single command-line to launch single-node or multi-node Kubernetes clusters on [Equinix Metal](https://metal.equinix.com).

Sets up your CA keys and certs, client keys and certs, gets an Elastic IP for the API, launches the nodes with
userdata set to use [kube-install](https://github.com/deitch/kube-install), and gives you the node IDs and kubeconfig.

The original version of this was in `sh`, and depended upon the installation of multiple tools. The original
script is [packet-k8s-cluster.sh](./packet-k8s-cluster.sh).