#!/usr/bin/env bash
# setup.sh — Run ONCE to inject the Kaspa mnemonic into the IronClaw vault.
#
# The mnemonic is stored with AES-256-GCM encryption inside the TEE.
# After this script runs, the raw value is never accessible to the LLM
# or tool runtime — IronClaw injects it as {{KASPA_MNEMONIC}} at the
# WASM call boundary only.
#
# Usage:
#   chmod +x secrets/setup.sh
#   KASPA_MNEMONIC="your twelve word mnemonic phrase here" ./secrets/setup.sh
#
# Or interactively (recommended — avoids mnemonic in shell history):
#   ./secrets/setup.sh

set -euo pipefail

if [ -z "${KASPA_MNEMONIC:-}" ]; then
  echo "Enter your Kaspa BIP39 mnemonic (input hidden):"
  read -rs KASPA_MNEMONIC
  echo
fi

if [ -z "$KASPA_MNEMONIC" ]; then
  echo "Error: mnemonic is empty." >&2
  exit 1
fi

# Inject into IronClaw vault
ironclaw secret set KASPA_MNEMONIC "$KASPA_MNEMONIC"

echo "Vault injection complete. Verifying (value not shown):"
ironclaw secret list

# Clear from shell variable immediately
unset KASPA_MNEMONIC
