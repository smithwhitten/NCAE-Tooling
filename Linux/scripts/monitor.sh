#!/bin/bash

FILE="/etc/passwd"
HASH_FILE="/var/tmp/passwd.hash"
LOG_FILE="/var/log/passwd_changes.log"

# Create initial hash if it doesn't exist
if [ ! -f "$HASH_FILE" ]; then
    sha256sum "$FILE" > "$HASH_FILE"
    exit 0
fi

# Compute current hash
CURRENT_HASH=$(sha256sum "$FILE")

# Read previous hash
OLD_HASH=$(cat "$HASH_FILE")

# Compare hashes
if [ "$CURRENT_HASH" != "$OLD_HASH" ]; then
    echo "$(date): /"$FILE" has been modified!" >> "$LOG_FILE"
    
    # Update stored hash
    echo "$CURRENT_HASH" > "$HASH_FILE"
fi