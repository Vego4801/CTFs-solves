#!/bin/bash

IMAGE_NAME="web_magical_palindrome_release"
CONTAINER_NAME="magical_palindrome_container"
PORT=12349

echo "[*] Stopping and removing existing container..."
docker stop $CONTAINER_NAME 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true

echo "[*] Removing existing image..."
docker rmi $IMAGE_NAME 2>/dev/null || true

echo "[*] Building Docker image: $IMAGE_NAME"
docker build -t $IMAGE_NAME .

if [ $? -eq 0 ]; then
    echo "[+] Build successful!"
    docker run -d --name $CONTAINER_NAME -p $PORT:80 $IMAGE_NAME

    if [ $? -eq 0 ]; then
        echo "[+] Container started successfully!"
        echo "[+] Access the application at: http://127.0.0.1:$PORT"
    else
        echo "[-] Failed to start container"
        exit 1
    fi
else
    echo "[-] Build failed"
    exit 1
fi
