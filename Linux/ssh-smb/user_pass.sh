#!/bin/bash
# NCAE - CosmicGrace
# Author - Claude (Anthropic) / CosmicGrace

# Prompt for password (hidden input)
read -s -p "Enter new password: " PASSWORD
echo
read -s -p "Confirm new password: " CONFIRM
echo

# Check if passwords match
if [[ "$PASSWORD" != "$CONFIRM" ]]; then
    echo "Passwords do not match!"
    exit 1
fi

# Check if users file exists
if [[ ! -f users.txt ]]; then
    echo "users.txt not found!"
    exit 1
fi

# Loop through users and update password
while IFS= read -r USER; do
    if id "$USER" &>/dev/null; then
        echo "$USER:$PASSWORD" | chpasswd
        echo "Password updated for $USER"
    else
        echo "User $USER does not exist, skipping..."
    fi
done < users.txt

echo "Done."