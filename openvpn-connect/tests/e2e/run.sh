#!/bin/sh
set -eu

cd "$(dirname "$0")"

cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [ "$status" -ne 0 ]; then
        docker compose logs --no-color server || true
    fi
    docker compose down --volumes --remove-orphans
    exit "$status"
}

trap cleanup EXIT INT TERM
docker compose up --build --abort-on-container-exit --exit-code-from test test
