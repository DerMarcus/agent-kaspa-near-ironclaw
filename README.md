# IronClaw × Kaspa — Send KAS Tokens (PoC)

A WASM tool for sending KAS tokens from an IronClaw TEE-encrypted vault.
The private key (BIP39 mnemonic) is stored with AES-256-GCM inside the enclave
and injected only at the WASM call boundary — it never touches the LLM context.

---

## Repository structure

```
ironclaw-kaspa-poc/
├── kaspa-send-tool/          # WASM tool (Rust)
│   ├── Cargo.toml
│   └── src/lib.rs
├── ironclaw-config/
│   ├── tool_manifest.toml    # Tool registration + permissions
│   └── allowlist.toml        # Approved HTTP endpoints
├── secrets/
│   └── setup.sh              # Vault injection script (run once)
└── README.md
```

---

## Prerequisites

| Requirement | Install |
|---|---|
| Rust toolchain | `curl https://sh.rustup.rs -sSf \| sh` |
| wasm-pack | `cargo install wasm-pack` |
| IronClaw CLI | see IronClaw docs |
| Funded Kaspa wallet | BIP39 mnemonic for a mainnet address |

---

## Step 1 — Store the mnemonic in the vault

```bash
chmod +x secrets/setup.sh
./secrets/setup.sh        # prompts for mnemonic with hidden input
```

Verify (shows placeholder only — raw value never printed):

```bash
ironclaw secret list
```

---

## Step 2 — Register the Kaspa API allowlist

```bash
ironclaw allowlist apply ironclaw-config/allowlist.toml
```

---

## Step 3 — Build the WASM tool

```bash
cd kaspa-send-tool
wasm-pack build --target web --release
# Output: pkg/kaspa_send_tool_bg.wasm
```

---

## Step 4 — Register the tool with IronClaw

```bash
ironclaw tool register ironclaw-config/tool_manifest.toml
ironclaw tool verify kaspa_send
```

---

## Step 5 — Invoke

### Natural language (REPL)

```
> Send 5 KAS to kaspa:qrrzeucwfetuty3qserqydw4z4ax9unxd23zwp7tndvg7cs3ls8dvwldeayv5
```

### Direct CLI

```bash
ironclaw tool call kaspa_send '{
  "recipient": "kaspa:qrrzeucwfetuty3qserqydw4z4ax9unxd23zwp7tndvg7cs3ls8dvwldeayv5",
  "amount_kas": 5.0,
  "priority_fee_sompi": 1000
}'
```

---

## Step 6 — Validate

1. Check the txid on the explorer: `https://explorer.kaspa.org/txs/<txid>`
2. Confirm no secret leakage:
   ```bash
   ironclaw logs kaspa_send --last 1 | grep "leak_scan"
   # Expected: leak_scan: PASS
   ```
3. Verify balance:
   ```bash
   curl https://api.kaspa.org/addresses/<your_address>/balance
   ```

---

## Kaspa technical reference

| Concept | Value |
|---|---|
| Base unit | sompi (1 KAS = 100 000 000 sompi) |
| Signature scheme | Schnorr (secp256k1) |
| Hash function | Blake2b-256 |
| HD derivation path | `m/44'/111111'/0'/0/0` |
| Address prefix | `kaspa:` (mainnet) / `kaspatest:` (testnet) |
| REST API | `https://api.kaspa.org` |
| UTXO maturity | 100 block confirmations |
| Block rate | ~1 block/sec (blockDAG) |

---

## Security notes

- The mnemonic is stored with AES-256-GCM inside the TEE — IronClaw infrastructure
  cannot access the raw key.
- All transaction signing occurs inside the sandboxed WASM; the private key is never
  passed to or visible in the LLM context.
- Only `api.kaspa.org` paths required for the PoC are allowlisted.
- For production: replace mnemonic injection with TEE-native key generation (generate
  keypair *inside* the enclave; export only the public address).

---

## Next steps

- [ ] Add testnet support (`network = "kaspatest"`, point to testnet node)
- [ ] Add UTXO compounding for wallets with many small UTXOs
- [ ] Integrate with SolStream / agentic finance PoC for cross-chain treasury management
- [ ] Consider MPC key splitting across multiple IronClaw instances for institutional custody
