#!/bin/bash

(
    set -eu

    echo "Stopping the test server..."

    CONTAINER_NAME="swiftsmb-test-server"

    CONTAINERS="$(docker ps -a --format '{{.Names}}')"
    if printf '%s\n' "$CONTAINERS" | grep -qx "$CONTAINER_NAME"; then
        docker rm -f "$CONTAINER_NAME" >/dev/null
        echo "Container '${CONTAINER_NAME}' stopped and removed."
    else
        echo "Container '${CONTAINER_NAME}' is not running."
    fi
)
