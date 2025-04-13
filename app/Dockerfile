FROM python:3.9-slim

WORKDIR /app

# Install required packages including PostgreSQL client
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openssl \
    curl \
    postgresql-client \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Make the scripts executable
RUN chmod +x /app/docker-inspect.sh

# Expose port for Flask application
EXPOSE 5000

# Use the new script to ensure database is ready
CMD ["/app/docker-inspect.sh", "gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
