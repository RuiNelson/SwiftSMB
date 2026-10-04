#!/bin/bash

(
    set -eu

    echo "Bringing up the test server..."

    if [ -n "${BASH_VERSION:-}" ]; then
        SCRIPT_PATH="${BASH_SOURCE[0]}"
    elif [ -n "${ZSH_VERSION:-}" ]; then
        SCRIPT_PATH="${(%):-%x}"
    else
        SCRIPT_PATH="$0"
    fi
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
    IMAGE_NAME="swiftsmb-test-server"
    CONTAINER_NAME="swiftsmb-test-server"

    CONTAINERS="$(docker ps -a --format '{{.Names}}')"
    if printf '%s\n' "$CONTAINERS" | grep -qx "$CONTAINER_NAME"; then
        echo "Stopping existing container..."
        docker rm -f "$CONTAINER_NAME" >/dev/null
    fi

    echo "Building Docker image..."
    docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

    echo "Starting container..."
    docker run -d \
        --name "$CONTAINER_NAME" \
        -p 44445:445 \
        "$IMAGE_NAME"

    echo "Test server is running on port 44445"
    echo ""
    echo "Available shares:"
    echo "  smb2://localhost/public   - guest access, read-write"
    echo "  smb2://localhost/private  - auth required (smbuser:smbpass123)"
    echo "  smb2://localhost/readonly - guest access, read-only"
    echo "  smb2://localhost/hidden\$  - hidden, auth required (smbadmin:smbadmin123)"
)
