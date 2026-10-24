#!/bin/sh
set -e

# Generate signing keys if none exist
if [ -z "$(ls -A /app/certs/*.pem 2>/dev/null)" ]; then
  echo "No signing keys found — generating RSA key pair..."
  bun run scripts/gen-secrets.ts
  echo "Keys generated in /app/certs/"
else
  echo "Signing keys found — skipping generation."
fi

exec bun run index.ts
