#!/bin/bash

echo "Stopping the test server..."

CONTAINER_NAME="swiftsmb-test-server"

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
    echo "Container '${CONTAINER_NAME}' stopped and removed."
else
    echo "Container '${CONTAINER_NAME}' is not running."
fi