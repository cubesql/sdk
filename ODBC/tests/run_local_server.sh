#!/bin/sh
set -eu

server_bin=${CUBESQL_SERVER_BIN:-/Users/marco/SQLabs/cubesql/Installers/PackageBuilder/exec/cubesql}
server_port=${CUBESQL_ODBC_PORT:-4540}
server_root=${CUBESQL_ODBC_SERVER_ROOT:-$(mktemp -d /tmp/cubesql-odbc.XXXXXX)}
server_log="$server_root/server.log"
integration_log="$server_root/integration.log"

if [ ! -x "$server_bin" ]; then
    echo "CubeSQL executable not found: $server_bin" >&2
    exit 1
fi

mkdir -p "$server_root"
"$server_bin" -p "$server_port" -i 127.0.0.1 -x "$server_root" \
    -s "$server_root/cubesql.settings" -f CONSOLE -v SQL_ERRORS \
    >"$server_log" 2>&1 &
server_pid=$!

stop_server() {
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    echo "CubeSQL test data and log: $server_root"
}
trap stop_server EXIT HUP INT TERM

attempt=0
while ! nc -z 127.0.0.1 "$server_port" 2>/dev/null; do
    attempt=$((attempt + 1))
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo "CubeSQL exited before accepting connections:" >&2
        sed -n '1,160p' "$server_log" >&2
        exit 1
    fi
    if [ "$attempt" -ge 50 ]; then
        echo "CubeSQL did not listen on port $server_port:" >&2
        sed -n '1,160p' "$server_log" >&2
        exit 1
    fi
    sleep 0.1
done

set +e
CUBESQL_ODBC_HOST=127.0.0.1 \
CUBESQL_ODBC_PORT="$server_port" \
CUBESQL_ODBC_USER=admin \
CUBESQL_ODBC_PASSWORD=admin \
CUBESQL_ODBC_REGISTER_TEST_SERVER=1 \
    ./test_odbc_integration >"$integration_log" 2>&1
test_status=$?
set -e

cat "$integration_log"
if [ "$test_status" -ne 0 ]; then
    echo "CubeSQL ODBC integration: FAILED (exit $test_status)" >&2
    exit "$test_status"
fi
echo "CubeSQL ODBC live integration suite completed successfully."
