#!/usr/bin/env bash
set -euo pipefail

DB_CONTAINER="${DB_CONTAINER:-aivuln-postgres}"
DB_VOLUME="${DB_VOLUME:-aivuln_postgres_data}"
DOCKER_NETWORK="${DOCKER_NETWORK:-aivuln-net}"
POSTGRES_DB="${POSTGRES_DB:-aivuln}"
POSTGRES_USER="${POSTGRES_USER:-aivuln}"
POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-5432}"
SECRET_DIR="${SECRET_DIR:-/root/aivuln-secrets}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root or with sudo."
  exit 1
fi

mkdir -p "${SECRET_DIR}"
chmod 700 "${SECRET_DIR}"

if [[ ! -f "${SECRET_DIR}/postgres_password" ]]; then
  openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 32 > "${SECRET_DIR}/postgres_password"
fi

POSTGRES_PASSWORD="$(cat "${SECRET_DIR}/postgres_password")"

docker volume inspect "${DB_VOLUME}" >/dev/null 2>&1 || docker volume create "${DB_VOLUME}"
docker network inspect "${DOCKER_NETWORK}" >/dev/null 2>&1 || docker network create "${DOCKER_NETWORK}"

if docker ps -a --format '{{.Names}}' | grep -qx "${DB_CONTAINER}"; then
  docker start "${DB_CONTAINER}" >/dev/null || true
  docker network connect "${DOCKER_NETWORK}" "${DB_CONTAINER}" 2>/dev/null || true
else
  docker run -d \
    --name "${DB_CONTAINER}" \
    --network "${DOCKER_NETWORK}" \
    --network-alias "${DB_CONTAINER}" \
    -e POSTGRES_DB="${POSTGRES_DB}" \
    -e POSTGRES_USER="${POSTGRES_USER}" \
    -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
    -v "${DB_VOLUME}:/var/lib/postgresql/data" \
    -p "127.0.0.1:${POSTGRES_HOST_PORT}:5432" \
    --restart unless-stopped \
    postgres:16
fi

for i in {1..60}; do
  if docker exec "${DB_CONTAINER}" pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; then
    echo "[+] PostgreSQL is ready."
    break
  fi
  sleep 2
done

if ! docker exec "${DB_CONTAINER}" pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; then
  docker logs "${DB_CONTAINER}" --tail=100
  exit 1
fi

docker exec -i "${DB_CONTAINER}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" <<SQL
ALTER USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';
SQL

echo "[+] PostgreSQL container ready."
