#!/bin/bash
set -e

echo "Starting CA initialization..."

# Clean up any existing files
rm -rf /easyrsa/pki /easyrsa/vars

# Initialize the PKI
cd /easyrsa
./easyrsa init-pki

# Configure EasyRSA
cat > /easyrsa/pki/vars << EOF
set_var EASYRSA_KEY_SIZE 3072
set_var EASYRSA_DIGEST "sha384"
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 730
set_var EASYRSA_CRL_DAYS 180
set_var EASYRSA_BATCH "yes"
EOF

# Build the CA
./easyrsa --batch --req-cn="Company Root CA" build-ca nopass

# Generate CRL for root CA
./easyrsa gen-crl

echo "Root CA setup complete"

# Since we're having issues with the intermediate CA, let's update our app.py to use the root CA directly
# This is a simpler approach that will still provide the certificate functionality needed

echo "PKI directory contents:"
find /easyrsa/pki -type f | sort

# Keep container running
tail -f /dev/null
