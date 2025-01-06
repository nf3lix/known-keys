#!/bin/bash
path=""

read -p "Please choose the crypto system for the public keys (RSA/EC) : " crypto

# Validate user input
if [[ "$crypto" != "RSA" && "$crypto" != "EC" ]]; then
    echo "Invalid crypto system. Please enter 'RSA' or 'EC'."
    exit 1
fi

if [[ "$crypto" == "RSA" ]]; then
    endpoint="http://localhost:8080/public-keys/rsa"
else
    endpoint="http://localhost:8080/public-keys/ec"
fi

read -p "Enter the local path to Public Keys in PEM format: " path

perform_curl_request() {
    local file=$1
    local endpoint=$2
    echo "Post PEM file: $file to $endpoint"
    curl -X POST -F "file=@${file}" "$endpoint"
}

export -f perform_curl_request

# Find .pem and .key files recursively and perform post request
find "$path" -type f \( -iname "*.pem" -o -iname "*.key" \) -exec bash -c 'perform_curl_request "$0" "$1"' {} "$endpoint" \;

echo "Completed processing all files."
