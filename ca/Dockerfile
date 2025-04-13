FROM alpine:latest

RUN apk add --no-cache openssl bash

# Install EasyRSA
WORKDIR /tmp
RUN wget -q https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz && \
    tar -xzf EasyRSA-3.1.0.tgz && \
    mv EasyRSA-3.1.0 /easyrsa && \
    rm -f EasyRSA-3.1.0.tgz

WORKDIR /easyrsa

# Copy initialization script
COPY init-ca.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-ca.sh

# Default command
CMD ["/usr/local/bin/init-ca.sh"]
