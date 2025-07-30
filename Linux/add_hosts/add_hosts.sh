#!/bin/bash

# Backup the original hosts file
cp /etc/hosts /etc/hosts.bak
echo "📦 Backup created: /etc/hosts.bak"

# Define PLURA-XDR related host entries (with a comment header)
entries=(
  "# PLURA-XDR hosts entries"
  "10.10.10.1    repo.plura.io"
  "10.10.10.1    apis.plura.io"
  "10.10.10.4    uploadsys.plura.io"
  "10.10.10.7    uploadweb.plura.io"
  "10.10.10.7    uploadnet.plura.io"
  "10.10.10.7    uploadapp.plura.io"
  "10.10.10.7    uploadres.plura.io"
)

# Track whether any changes were made
changes_made=false

# Loop through each entry and add it if not already present
for entry in "${entries[@]}"; do
  if ! grep -Fxq "$entry" /etc/hosts; then
    echo "$entry" >> /etc/hosts
    echo "✔️ Added: $entry"
    changes_made=true
  else
    echo "ℹ️ Already exists: $entry"
  fi
done

# Summary
if [ "$changes_made" = true ]; then
  echo "✅ Hosts file updated successfully."
else
  echo "✅ No changes made. All entries already exist."
fi
