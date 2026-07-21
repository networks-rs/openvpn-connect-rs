#!/bin/sh
set -eu

if [ -s /vpn/client.ovpn ]; then
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj /CN=openvpn-connect-rs-test-ca \
    -keyout /vpn/ca.key -out /vpn/ca.crt

openssl req -newkey rsa:2048 -nodes -subj /CN=server \
    -keyout /vpn/server.key -out /vpn/server.csr
printf '%s\n' \
    'basicConstraints=CA:FALSE' \
    'keyUsage=digitalSignature,keyEncipherment' \
    'subjectAltName=DNS:server' \
    'extendedKeyUsage=serverAuth' >/vpn/server.ext
openssl x509 -req -days 2 -sha256 -CA /vpn/ca.crt -CAkey /vpn/ca.key \
    -CAcreateserial -in /vpn/server.csr -out /vpn/server.crt -extfile /vpn/server.ext

openssl req -newkey rsa:2048 -nodes -subj /CN=e2e-client \
    -keyout /vpn/client.key -out /vpn/client.csr
printf '%s\n' \
    'basicConstraints=CA:FALSE' \
    'keyUsage=digitalSignature' \
    'extendedKeyUsage=clientAuth' >/vpn/client.ext
openssl x509 -req -days 2 -sha256 -CA /vpn/ca.crt -CAkey /vpn/ca.key \
    -CAcreateserial -in /vpn/client.csr -out /vpn/client.crt -extfile /vpn/client.ext

cat >/vpn/server.conf <<'EOF'
port 1194
proto udp
dev tun
topology subnet
server 10.8.0.0 255.255.255.0
ca /vpn/ca.crt
cert /vpn/server.crt
key /vpn/server.key
dh none
tls-version-min 1.2
remote-cert-tls client
data-ciphers AES-256-GCM
cipher AES-256-GCM
auth SHA256
keepalive 2 10
persist-key
persist-tun
verb 4
EOF

{
    cat <<'EOF'
client
dev tun
proto udp
remote server 1194
nobind
remote-cert-tls server
tls-version-min 1.2
cipher AES-256-GCM
auth SHA256
verb 4
<ca>
EOF
    cat /vpn/ca.crt
    printf '%s\n' '</ca>' '<cert>'
    cat /vpn/client.crt
    printf '%s\n' '</cert>' '<key>'
    cat /vpn/client.key
    printf '%s\n' '</key>'
} >/vpn/client.ovpn

chmod 600 /vpn/*.key
chmod 644 /vpn/client.ovpn /vpn/*.crt /vpn/server.conf
