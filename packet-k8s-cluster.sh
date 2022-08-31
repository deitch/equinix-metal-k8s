#!/bin/bash
set -ex

if [ $# -lt 2 ]; then
  echo "Usage: packet-k8s-cluster <count> <projectID>" >&2
  exit
fi

count="$1"
project="$2"
# default project should be 2a5da360-5749-41a9-8c40-8a2ef7dc3d1e
metro="da"
os="ubuntu_16_04"
plan="c3.small.x86"
port="6443"

# generate CA key and cert, so we can share them around
caPrivateKey=$(openssl genrsa 2048 2>/dev/null)
caPrivateKeyB64=$(echo -n "${caPrivateKey}" | base64)
caPubKey=$(echo -n "${caPrivateKey}" | openssl rsa -outform PEM -pubout 2>/dev/null)
caCertHash="sha256:$(echo -n "${caPubKey}" | openssl rsa -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"

# generate certs key, equivalent to `kubeadm certs certificate-key`, which should be 32 byte = 64 chars in hex
certsKey=$(cat /dev/urandom | hexdump -e '/1 "%x"' | head -c 64)

# generate CA cert
# this needs CN and SAN
#   - SubjectAlternateName: DNS:kubernetes
#   - KeyUsage: Digital Signature, Key Encipherment, Certificate Sign
#   - CN=kubernetes
TMPDIR="/tmp/k8s-cluster-$$/"
CACONF=${TMPDIR}/ca-$$.cnf
CAKEY=${TMPDIR}/ca-$$.key
CACERT=${TMPDIR}/ca-$$.crt
CLIENTKEY=${TMPDIR}/client-$$.key
CLIENTCONF=${TMPDIR}/client-$$.cnf
CLIENTCSR=${TMPDIR}/client-$$.csr
CLIENTCERT=${TMPDIR}/client-$$.crt
export KUBECONFIG=${TMPDIR}/kubeconfig-$$

echo ${caPrivateKey} > ${CAKEY}
cat > ${CACONF} <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions     = v3_req
x509_extensions    = v3_req

[req_distinguished_name]
commonName       = {{ common_name }}
emailAddress     = {{ ssl_certs_email }}
organizationName = {{ ssl_certs_organization }}
localityName     = {{ ssl_certs_locality }}
countryName      = {{ ssl_certs_country }}

[v3_req]
# The extentions to add to a self-signed cert
subjectKeyIdentifier = hash
basicConstraints     = critical,CA:true
subjectAltName       = DNS:kubernetes
keyUsage             = critical,digitalSignature,keyEncipherment,keyCertSign
EOF
        openssl req -new -x509 -nodes -days 365000 -key ${CAKEY} -out ${CACERT} -subj '/CN=kubernetes' -config ${CACONF}
caCert=$(cat ${CACERT})
caCertB64=$(echo -n "${caCert}" | base64)

clientPrivateKey=$(openssl genrsa 2048 2>/dev/null)

cat > ${CLIENTCONFIG} <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions     = v3_req
x509_extensions    = v3_req

[req_distinguished_name]
commonName       = {{ common_name }}
emailAddress     = {{ ssl_certs_email }}
organizationName = {{ ssl_certs_organization }}
localityName     = {{ ssl_certs_locality }}
countryName      = {{ ssl_certs_country }}

[v3_req]
subjectKeyIdentifier = hash
basicConstraints     = critical,CA:false
keyUsage             = critical,digitalSignature,keyEncipherment
EOF

openssl req -new -nodes -days 365 -key ${CLIENTKEY} -out ${CLIENTCSR} -subj '/CN=kubernetes-admin/O=system:masters' -config ${CLIENTCONF}
openssl x509 -extensions v3_req -extfile ${CLIENTCONF} -req -days 365 -in ${CLIENTCSR} -out ${CLIENTCERT} -CAkey ${CAKEY} -CA ${CACERT} -set_serial 01
clientCert=$(cat ${CLIENTCERT})

# generate kubeconfig
kubectl config set clusters.my-cluster.server https://${eipAddress}:${eipPort}
kubectl config set clusters.my-cluster.certificate-authority-data ${caCert} --set-raw-bytes=true
kubectl config set users.cluster-admin.client-key-data ${clientPrivateKey} --set-raw-bytes=true
kubectl config set users.cluster-admin.client-certificate-data ${clientCert} --set-raw-bytes=true
kubeconfig=$(cat ${KUBECONFIG})

# generate bootstrap token, equivalent to `kubeadm token create`, which should give [a-z0-9]{6}.[a-z0-9]{16}
tokenFirst=$(cat /dev/urandom| LC_ALL=C tr -dc 'a-z0-9' | head -c 6)
tokenSecond=$(cat /dev/urandom| LC_ALL=C tr -dc 'a-z0-9' | head -c 16)
token="${tokenFirst}.${tokenSecond}"

# get the IP to use for the API server
eipData=$(metal -p ${project} ip request -t public_ipv4 -m ${metro} -q 1 -o json)
eipAddress=$(echo ${eipData} | jq -r '.address')
eipCidr=$(echo ${eipData} | jq -r '.cidr')

# deploy initial device
userdata="$(printf '%s\n' '#!/bin/sh' "curl https://raw.githubusercontent.com/deitch/kubeadm-install/master/install.sh | sh -s init -r containerd -a ${eipAddress}:${port} -b ${token} -k ${caPrivateKeyB64} -c ${caCertB64} -e ${certsKey}")"
masterID=$(metal -p ${project} device create -P ${plan} -m ${metro} -O ${os} -H $(printf "k8s-master-%02d" ${i}) --userdata "$userdata" -o json | jq -r '.id')

# wait for it to be ready to start other devices
total=0
waitDeviceReady=300
waitKubeReady=300
waitInternal=15
echo "waiting for initial device to be ready up to ${waitDeviceReady} seconds"
while true; do
    sleep $waitInterval
    total=$(( $total + $waitInterval ))
    state=$(metal device get --id ${masterID} -ojson | jq -r '.state')
    if [ "$state" = "active" ]; then
       break
    fi
    if [ $total -gt $waitDeviceReady ]; then
       echo "device $masterID not ready in $total seconds; failure" >&2
       exit 1
    fi
done

# if we made it here, the device is ready, but kubernetes may not be
# assign the EIP to the initial master
metal ip assign -d ${masterID} -a ${eipAddress}/${eipCidr}

total=0
echo "waiting for initial Kubernetes control plane node to be ready up to ${waitKubeReady} seconds"
while true; do
    sleep $waitInterval
    total=$(( $total + $waitInterval ))
    set +e
    curl -k -s -I -f https://${eipAddress}:${eipPort}/healthz
    exitCode=$1
    set -e
    if [ "$exitCode" = "0" ]; then
       break
    fi
    if [ $total -gt $waitKubeReady ]; then
       echo "node $masterID not ready in $total seconds; failure" >&2
       exit 1
    fi
done

# add CNI
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')&env.IPALLOC_RANGE=192.168.0.0/16"

# create other devices
if [ $count -gt 1 ]; then
    userdata="$(printf '%s\n' '#!/bin/sh' "curl https://raw.githubusercontent.com/deitch/kubeadm-install/master/install.sh | sh -s join -r containerd -a ${eipAddress}:${port} -b ${token} -h ${caCertHash} -e ${certsKey}")"
    for i in $(seq 2 ${count}); do
        metal -p ${project} device create -P c3.small.x86 -m ${metro} -O ubuntu_16_04 -H $(printf "k8s-master-%02d" ${i} --userdata "$userdata")
    done
fi

rm -rf ${TMPDIR}

echo kubeconfig:
echo
echo "${kubeconfig}"
