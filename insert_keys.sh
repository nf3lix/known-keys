#!/bin/bash
path=""

read -p "Please choose the crypto system for inserting public keys (RSA/EC) : " crypto
if [[ "$crypto" != "RSA" && "$crypto" != "EC" ]]; then
    echo "Invalid crypto system. Please enter 'RSA' or 'EC'."
    exit 1
fi

read -p "Do you want to add or test a public key? (add/test): " action
if [[ "$action" != "add" && "$action" != "test" ]]; then
    echo "Invalid action. Please enter 'add' or 'test'."
    exit 1
fi

if [[ "$action" == "add" ]]; then
    action_endpoint=""
else
    action_endpoint="/exists"
fi

crypto_lower=$(echo "$crypto" | tr '[:upper:]' '[:lower:]')
endpoint="http://localhost:8080/public-keys/${crypto_lower}${action_endpoint}"

read -p "Enter the local path to Public Keys in PEM format: " path

read -p "Enter the maximum number of files to process (press Enter to process all files): " max_files

perform_curl_request() {
    local file=$1
    local endpoint=$2
    # echo "Post PEM file: $file to $endpoint"
    curl -X POST -F "file=@${file}" "$endpoint" > /dev/null 2>&1
}

export -f perform_curl_request

echo "#################"
start_time=$(date +%s.%N)
# Find .pem and .key files recursively and perform post request
if [[ -z "$max_files" ]]; then
    find "$path" -type f \( -iname "*.pem" -o -iname "*.key" \) -exec bash -c 'perform_curl_request "$0" "$1"' {} "$endpoint" \;
    echo "Completed processing all files from the directory."
else
    start_time=$(date +%s.%N)
    find "$path" -type f \( -iname "*.pem" -o -iname "*.key" \) | head -n "$max_files" | xargs -I {} bash -c 'perform_curl_request "$0" "$1"' {} "$endpoint"
    end_time=$(date +%s.%N)
    elapsed=$(echo "$end_time - $start_time" | bc)
    echo "Completed processing $max_files files from the directory."
fi

end_time=$(date +%s.%N)
elapsed=$(echo "$end_time - $start_time" | bc)
echo "Time taken: ${elapsed} seconds."

new_memory_consumption=$(curl -s "http://localhost:8080/public-keys/${crypto_lower}/redis-memory-consumption")
echo "Memory consumption (bytes) of the redis key after this operation: $new_memory_consumption"
