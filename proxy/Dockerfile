FROM nginx:alpine

# Install necessary tools
RUN apk add --no-cache openssl

# Copy configuration files
COPY nginx.conf /etc/nginx/nginx.conf
COPY ssl-setup.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/ssl-setup.sh

# Create directory for certificates
RUN mkdir -p /etc/nginx/certs

# Expose ports
EXPOSE 443

# Start Nginx after SSL setup
CMD ["/bin/sh", "-c", "/usr/local/bin/ssl-setup.sh && nginx -g 'daemon off;'"]
