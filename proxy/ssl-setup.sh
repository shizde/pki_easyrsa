#!/bin/sh
set -e

# Wait for CA to be ready
echo "Waiting for CA to be ready..."
while [ ! -f /ca/pki/ca.crt ]; do
    sleep 2
done

# Copy CA certificates
echo "Copying CA certificates..."
cp /ca/pki/ca.crt /etc/nginx/certs/ca.crt
cp /ca/pki/crl.pem /etc/nginx/certs/crl.pem

# Generate a self-signed certificate for the proxy
if [ ! -f /etc/nginx/certs/server.crt ]; then
    echo "Generating self-signed certificate..."
    
    # Generate server key
    openssl genrsa -out /etc/nginx/certs/server.key 3072
    
    # Generate CSR
    openssl req -new -key /etc/nginx/certs/server.key \
        -out /etc/nginx/certs/server.csr \
        -subj "/C=US/ST=State/L=City/O=Company/CN=pki.company.local"
    
    # Self-sign the certificate (instead of using CA to sign it)
    openssl x509 -req -days 365 \
        -in /etc/nginx/certs/server.csr \
        -signkey /etc/nginx/certs/server.key \
        -out /etc/nginx/certs/server.crt
    
    # Remove the CSR as it's no longer needed
    rm /etc/nginx/certs/server.csr
fi

# Generate DH parameters if they don't exist
if [ ! -f /etc/nginx/certs/dhparam.pem ]; then
    echo "Generating DH parameters (this may take a while)..."
    openssl dhparam -out /etc/nginx/certs/dhparam.pem 2048
fi

echo "SSL setup complete!"
