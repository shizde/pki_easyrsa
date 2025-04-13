#!/bin/bash
# wait-for-db.sh

set -e

host="$1"
shift
cmd="$@"

echo "Waiting for postgres to become available..."
# Try to ping the host first to ensure DNS resolution
until ping -c 1 "$host" > /dev/null 2>&1; do
  >&2 echo "Cannot resolve hostname $host - waiting for DNS"
  sleep 2
done

# Now wait for PostgreSQL to accept connections
until PGPASSWORD=$DB_PASSWORD psql -h "$host" -U "$DB_USER" -d "$DB_NAME" -c '\q'; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 2
done

>&2 echo "Postgres is up - executing command"
exec $cmd
