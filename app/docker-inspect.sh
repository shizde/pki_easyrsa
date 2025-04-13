#!/bin/bash
# docker-inspect.sh

set -e

echo "Waiting for database to be available..."

# Get the DB container's IP address (this works because docker provides a DNS resolver)
# Try several approaches to connect to postgres

# Try to connect for 60 seconds (30 attempts, 2 seconds apart)
for i in {1..30}; do
  # Try direct connection to postgres container
  if PGPASSWORD=$DB_PASSWORD psql -h db -U "$DB_USER" -d "$DB_NAME" -c '\q' 2>/dev/null; then
    echo "Successfully connected to Postgres!"
    break
  fi
  
  if [ $i -eq 30 ]; then
    echo "Could not connect to Postgres after 30 attempts. Exiting."
    exit 1
  fi
  
  echo "Attempt $i: Cannot connect to database yet - waiting 2 seconds..."
  sleep 2
done

# Execute the command passed to this script
echo "Database is available - executing: $@"
exec "$@"
