#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ENGINE=${CONTAINER_ENGINE:-podman}
NAME=${SOCA_DEMO_NAME:-soca-matomo-demo}
PORT=${SOCA_DEMO_PORT:-8093}
SECRETS=${SOCA_DEMO_SECRETS:-$(mktemp -d "${TMPDIR:-/tmp}/soca-matomo-XXXXXX")}
HOST=analytics.soca.localhost
python3 "$ROOT/demo/init.py" matomo "$SECRETS" "https://$HOST:$PORT"
"$ENGINE" build --network host -f "$ROOT/demo/Dockerfile" -t "$NAME:local" "$ROOT"
MOUNTS=()
for file in config.json client.pem state.key admin-password server.crt server.key; do
  MOUNTS+=(-v "$SECRETS/$file:/run/soca/$file:ro")
done
NETWORK="$NAME-net"
"$ENGINE" network create "$NETWORK"
"$ENGINE" run -d --name "$NAME-db" --network "$NETWORK" --network-alias db   -e MARIADB_DATABASE=matomo -e MARIADB_USER=matomo   -e MARIADB_PASSWORD_FILE=/run/soca/db-password -e MARIADB_ROOT_PASSWORD_FILE=/run/soca/db-root   -v "$SECRETS/db-password:/run/soca/db-password:ro" -v "$SECRETS/db-root:/run/soca/db-root:ro"   docker.io/library/mariadb:11.4@sha256:1292844148b311e4ed4300022a996d39083f415a963e970cf47cad1b3b18e3a6
"$ENGINE" run -d --name "$NAME" --network "$NETWORK" -p "127.0.0.1:$PORT:80"   -e SOCA_CONFIG_FILE=/run/soca/config.json "${MOUNTS[@]}"   -v "$SECRETS/db-password:/run/soca/db-password:ro" "$NAME:local"
for attempt in {1..60}; do
  if "$ENGINE" exec "$NAME-db" healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1; then break; fi
  sleep 1
done
"$ENGINE" exec -u www-data -e SOCA_NATIVE_TESTS=1 "$NAME" php /opt/soca-demo-install.php
printf 'Open https://%s:%s. Local account: localadmin. Password file: %s/admin-password
' "$HOST" "$PORT" "$SECRETS"
printf 'Trust the generated development certificate explicitly. CA/certificate: %s/server.crt
' "$SECRETS"
printf 'SSO starts disabled. See demo/README.md for candidate checks, recovery and cleanup.
'
