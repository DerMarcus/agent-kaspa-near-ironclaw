#[allow(warnings)]
mod bindings;

use bindings::exports::near::agent::tool::{Guest, Request, Response};
use bindings::near::agent::host;

use serde::{Deserialize, Serialize};
use blake2::{Blake2b256, Digest};
use k256::{
    Scalar, FieldBytes,
    elliptic_curve::{PrimeField, ops::Reduce},
    schnorr::{SigningKey, Signature},
    schnorr::signature::Signer,
};
use bip39::Mnemonic;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Tool input/output types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SendParams {
    recipient: String,
    amount_kas: f64,
    #[serde(default)]
    priority_fee_sompi: u64,
}

#[derive(Serialize)]
struct TxResult {
    txid: String,
    status: String,
}

// ---------------------------------------------------------------------------
// Kaspa REST API types
// ---------------------------------------------------------------------------

#[derive(Deserialize, Clone)]
struct UtxoEntry {
    outpoint: Outpoint,
    #[serde(rename = "utxoEntry")]
    entry: UtxoData,
}

#[derive(Deserialize, Clone)]
struct Outpoint {
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u32,
}

#[derive(Deserialize, Clone)]
struct UtxoData {
    amount: String,
    #[serde(rename = "scriptPublicKey")]
    script_public_key: ScriptPublicKey,
}

#[derive(Deserialize, Clone)]
struct ScriptPublicKey {
    #[serde(rename = "scriptPublicKey")]
    script: String,
    version: u16,
}

#[derive(Serialize)]
struct SubmitTxRequest {
    transaction: KaspaTx,
    #[serde(rename = "allowOrphan")]
    allow_orphan: bool,
}

#[derive(Serialize, Clone)]
struct KaspaTx {
    version: u16,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    #[serde(rename = "lockTime")]
    lock_time: u64,
    #[serde(rename = "subnetworkId")]
    subnetwork_id: String,
}

#[derive(Serialize, Clone)]
struct TxInput {
    #[serde(rename = "previousOutpoint")]
    previous_outpoint: PreviousOutpoint,
    #[serde(rename = "signatureScript")]
    signature_script: String,
    sequence: u64,
    #[serde(rename = "sigOpCount")]
    sig_op_count: u8,
}

#[derive(Serialize, Clone)]
struct PreviousOutpoint {
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u32,
}

#[derive(Serialize, Clone)]
struct TxOutput {
    amount: u64,
    #[serde(rename = "scriptPublicKey")]
    script_public_key: ScriptPublicKeyOut,
}

#[derive(Serialize, Clone)]
struct ScriptPublicKeyOut {
    version: u16,
    #[serde(rename = "scriptPublicKey")]
    script: String,
}

#[derive(Deserialize)]
struct SubmitTxResponse {
    #[serde(rename = "transactionId")]
    transaction_id: String,
}

// ---------------------------------------------------------------------------
// Keypair — we carry the 32-byte secret (x-only compatible) and the Schnorr key
// ---------------------------------------------------------------------------

struct KaspaKeypair {
    signing_key: SigningKey,
    address: String,
}

// ---------------------------------------------------------------------------
// Kaspa address encoding (bech32-like, version 0 = P2PK Schnorr)
// ---------------------------------------------------------------------------

const CHARSET: [char; 32] = [
    'q','p','z','r','y','9','x','8','g','f','2','t','v','d','w','0',
    's','3','j','n','5','4','k','h','c','e','6','m','u','a','7','l',
];

fn encode_kaspa_address(xonly_pubkey: &[u8; 32]) -> String {
    let mut payload = vec![0u8]; // version 0 = P2PK Schnorr
    payload.extend_from_slice(xonly_pubkey);
    let b32 = to_base32(&payload);
    let checksum = kaspa_checksum("kaspa", &b32);
    let mut chars: Vec<char> = b32.iter().map(|b| CHARSET[*b as usize]).collect();
    for i in 0..8 {
        chars.push(CHARSET[((checksum >> (5 * (7 - i))) & 0x1f) as usize]);
    }
    format!("kaspa:{}", chars.iter().collect::<String>())
}

fn to_base32(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        result.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    result
}

fn kaspa_checksum(hrp: &str, data: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for ch in hrp.bytes() {
        c = polymod_step(c) ^ (ch as u64 & 0x1f);
    }
    c = polymod_step(c);
    for &d in data {
        c = polymod_step(c) ^ (d as u64);
    }
    for _ in 0..8 {
        c = polymod_step(c);
    }
    c ^ 1
}

fn polymod_step(pre: u64) -> u64 {
    let b = pre >> 35;
    ((pre & 0x07_ffff_ffff) << 5)
        ^ if (b >> 0) & 1 != 0 { 0x98_f2bc_8e61 } else { 0 }
        ^ if (b >> 1) & 1 != 0 { 0x79_b76d_99e2 } else { 0 }
        ^ if (b >> 2) & 1 != 0 { 0xf3_3e5f_b3c4 } else { 0 }
        ^ if (b >> 3) & 1 != 0 { 0xae_2eab_e2a8 } else { 0 }
        ^ if (b >> 4) & 1 != 0 { 0x1e_4f43_e470 } else { 0 }
}

// ---------------------------------------------------------------------------
// P2PK script helpers
// ---------------------------------------------------------------------------

fn p2pk_script(xonly: &[u8; 32]) -> String {
    // 0x20 <32-byte xonly> 0xac
    let mut script = vec![0x20u8];
    script.extend_from_slice(xonly);
    script.push(0xac);
    hex::encode(script)
}

fn address_to_script(address: &str) -> Result<(u16, String), String> {
    let addr = address
        .strip_prefix("kaspa:")
        .ok_or("invalid address: missing kaspa: prefix")?;

    let b32: Result<Vec<u8>, String> = addr
        .chars()
        .map(|c| {
            CHARSET.iter().position(|&x| x == c)
                .map(|p| p as u8)
                .ok_or_else(|| format!("invalid char '{}'", c))
        })
        .collect();
    let b32 = b32?;

    if b32.len() < 9 {
        return Err("address too short".into());
    }
    let payload_b32 = &b32[..b32.len() - 8];

    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in payload_b32 {
        acc = (acc << 5) | b as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push(((acc >> bits) & 0xff) as u8);
        }
    }

    if result.is_empty() {
        return Err("empty address payload".into());
    }

    let version = result[0] as u16;
    let pubkey_bytes = &result[1..];
    let mut script = vec![0x20u8];
    script.extend_from_slice(pubkey_bytes);
    script.push(0xac);
    Ok((version, hex::encode(script)))
}

// ---------------------------------------------------------------------------
// BIP32 key derivation  (m/44'/111111'/0'/0/0  — Kaspa coin type 111111)
// Uses k256 scalars — pure Rust, no C dependency.
// ---------------------------------------------------------------------------

fn derive_kaspa_keypair(mnemonic_phrase: &str) -> Result<KaspaKeypair, String> {
    let mnemonic = Mnemonic::from_str(mnemonic_phrase)
        .map_err(|e| format!("invalid mnemonic: {}", e))?;
    let seed = mnemonic.to_seed("");
    let key_bytes = derive_bip32_key(&seed)?;

    // k256 schnorr SigningKey uses the raw 32-byte secret
    let signing_key = SigningKey::from_bytes(&key_bytes)
        .map_err(|e| format!("invalid derived key: {}", e))?;

    // X-only public key (32 bytes)
    let xonly: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    let address = encode_kaspa_address(&xonly);

    Ok(KaspaKeypair { signing_key, address })
}

/// BIP32 child key derivation — returns raw 32-byte secret scalar for path
/// m/44'/111111'/0'/0/0
fn derive_bip32_key(seed: &[u8]) -> Result<[u8; 32], String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    // Master key from seed
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
        .map_err(|e| e.to_string())?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    let mut key_bytes: [u8; 32] = result[..32].try_into().unwrap();
    let mut chain_code: [u8; 32] = result[32..].try_into().unwrap();

    // m/44'/111111'/0'/0/0
    let path: &[u32] = &[0x8000_002C, 0x8001_B207, 0x8000_0000, 0, 0];

    for &index in path {
        let mut data = Vec::with_capacity(37);
        if index >= 0x8000_0000 {
            // Hardened: 0x00 || private_key
            data.push(0x00u8);
            data.extend_from_slice(&key_bytes);
        } else {
            // Normal: compressed public key
            let sk = SigningKey::from_bytes(&key_bytes)
                .map_err(|e| format!("bip32 key error: {}", e))?;
            // Uncompressed pubkey from schnorr verifying key = 02 || xonly
            let xonly: [u8; 32] = sk.verifying_key().to_bytes().into();
            data.push(0x02); // even parity (Schnorr convention)
            data.extend_from_slice(&xonly);
        }
        data.extend_from_slice(&index.to_be_bytes());

        let mut child_mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|e| e.to_string())?;
        child_mac.update(&data);
        let child_result = child_mac.finalize().into_bytes();

        let il: [u8; 32] = child_result[..32].try_into().unwrap();
        chain_code = child_result[32..].try_into().unwrap();

        // child_key = parse256(IL) + parent_key  (mod n)
        // Use k256 Scalar arithmetic (pure Rust)
        let il_scalar = Scalar::from_repr(*FieldBytes::from_slice(&il))
            .into_option()
            .ok_or("BIP32: IL >= order")?;
        let parent_scalar = Scalar::from_repr(*FieldBytes::from_slice(&key_bytes))
            .into_option()
            .ok_or("BIP32: parent key invalid")?;

        let child_scalar = il_scalar + parent_scalar;

        // Check child is not zero
        if child_scalar.is_zero().into() {
            return Err("BIP32: derived zero key (astronomically unlikely, retry with next index)".into());
        }

        key_bytes = child_scalar.to_bytes().into();
    }

    Ok(key_bytes)
}

// ---------------------------------------------------------------------------
// Kaspa sighash (SIGHASH_ALL, Blake2b-256)
// ---------------------------------------------------------------------------

fn kaspa_sighash(tx: &KaspaTx, input_index: usize, utxo: &UtxoEntry) -> [u8; 32] {
    let mut h = Blake2b256::new();

    h.update(tx.version.to_le_bytes());

    let mut ph = Blake2b256::new();
    for inp in &tx.inputs {
        let txid = hex::decode(&inp.previous_outpoint.transaction_id).unwrap_or_default();
        ph.update(&txid);
        ph.update(inp.previous_outpoint.index.to_le_bytes());
    }
    h.update(ph.finalize());

    let mut sh = Blake2b256::new();
    for inp in &tx.inputs {
        sh.update(inp.sequence.to_le_bytes());
    }
    h.update(sh.finalize());

    let mut soph = Blake2b256::new();
    for inp in &tx.inputs {
        soph.update([inp.sig_op_count]);
    }
    h.update(soph.finalize());

    let txid = hex::decode(&tx.inputs[input_index].previous_outpoint.transaction_id)
        .unwrap_or_default();
    h.update(&txid);
    h.update(tx.inputs[input_index].previous_outpoint.index.to_le_bytes());

    let script = hex::decode(&utxo.entry.script_public_key.script).unwrap_or_default();
    h.update((script.len() as u64).to_le_bytes());
    h.update(&script);

    let amount: u64 = utxo.entry.amount.parse().unwrap_or(0);
    h.update(amount.to_le_bytes());
    h.update(utxo.entry.script_public_key.version.to_le_bytes());
    h.update(tx.inputs[input_index].sequence.to_le_bytes());
    h.update([tx.inputs[input_index].sig_op_count]);

    let mut oh = Blake2b256::new();
    for out in &tx.outputs {
        oh.update(out.amount.to_le_bytes());
        oh.update(out.script_public_key.version.to_le_bytes());
        let sc = hex::decode(&out.script_public_key.script).unwrap_or_default();
        oh.update((sc.len() as u64).to_le_bytes());
        oh.update(&sc);
    }
    h.update(oh.finalize());

    h.update(tx.lock_time.to_le_bytes());

    let subnet = hex::decode(&tx.subnetwork_id).unwrap_or_default();
    h.update(&subnet);
    h.update(0u64.to_le_bytes());

    let mut payh = Blake2b256::new();
    payh.update([]);
    h.update(payh.finalize());

    h.update(1u8.to_le_bytes()); // SIGHASH_ALL

    h.finalize().into()
}

// ---------------------------------------------------------------------------
// HTTP helpers (via IronClaw host)
// ---------------------------------------------------------------------------

fn http_get(url: &str) -> Result<Vec<u8>, String> {
    host::log(host::LogLevel::Debug, &format!("GET {}", url));
    let resp = host::http_request("GET", url, "{}", None, Some(30_000))
        .map_err(|e| format!("http error: {}", e))?;
    if resp.status < 200 || resp.status >= 300 {
        return Err(format!("HTTP {} from {}", resp.status, url));
    }
    Ok(resp.body)
}

fn http_post_json(url: &str, body: &str) -> Result<Vec<u8>, String> {
    host::log(host::LogLevel::Debug, &format!("POST {}", url));
    let headers = r#"{"Content-Type":"application/json"}"#;
    let resp = host::http_request(
        "POST",
        url,
        headers,
        Some(body.as_bytes().to_vec()),
        Some(30_000),
    ).map_err(|e| format!("http error: {}", e))?;
    if resp.status < 200 || resp.status >= 300 {
        let body_str = String::from_utf8_lossy(&resp.body).to_string();
        return Err(format!("HTTP {} from {}: {}", resp.status, url, body_str));
    }
    Ok(resp.body)
}

// ---------------------------------------------------------------------------
// Core send logic
// ---------------------------------------------------------------------------

fn send_kas(params: &SendParams, mnemonic: &str) -> Result<TxResult, String> {
    let keypair = derive_kaspa_keypair(mnemonic)?;
    let xonly: [u8; 32] = keypair.signing_key.verifying_key().to_bytes().into();

    host::log(host::LogLevel::Info, &format!("sender: {}", keypair.address));

    // Fetch UTXOs
    let url = format!("https://api.kaspa.org/addresses/{}/utxos", keypair.address);
    let body = http_get(&url)?;
    let utxos: Vec<UtxoEntry> = serde_json::from_slice(&body)
        .map_err(|e| format!("parse utxos: {}", e))?;

    if utxos.is_empty() {
        return Err("no UTXOs found for address".into());
    }

    let amount_sompi = (params.amount_kas * 100_000_000.0) as u64;
    let required = amount_sompi + params.priority_fee_sompi;
    let selected = select_utxos(&utxos, required)?;

    let total_input: u64 = selected.iter()
        .map(|u| u.entry.amount.parse::<u64>().unwrap_or(0))
        .sum();
    let change = total_input.checked_sub(required)
        .ok_or("arithmetic overflow calculating change")?;

    let (_, recipient_script) = address_to_script(&params.recipient)?;

    let mut outputs = vec![TxOutput {
        amount: amount_sompi,
        script_public_key: ScriptPublicKeyOut { version: 0, script: recipient_script },
    }];
    if change >= 1_000 {
        outputs.push(TxOutput {
            amount: change,
            script_public_key: ScriptPublicKeyOut {
                version: 0,
                script: p2pk_script(&xonly),
            },
        });
    }

    let inputs: Vec<TxInput> = selected.iter().map(|u| TxInput {
        previous_outpoint: PreviousOutpoint {
            transaction_id: u.outpoint.transaction_id.clone(),
            index: u.outpoint.index,
        },
        signature_script: String::new(),
        sequence: 0,
        sig_op_count: 1,
    }).collect();

    let mut tx = KaspaTx {
        version: 0,
        inputs,
        outputs,
        lock_time: 0,
        subnetwork_id: "0000000000000000000000000000000000000000".into(),
    };

    // Sign each input with BIP340 Schnorr over the Blake2b-256 sighash
    for i in 0..selected.len() {
        let sighash = kaspa_sighash(&tx, i, &selected[i]);
        let sig: Signature = keypair.signing_key.sign(&sighash);
        let sig_bytes = sig.to_bytes();
        // signature_script: <sig_len(1 byte)> <sig(64 bytes)>
        let mut script = vec![sig_bytes.len() as u8];
        script.extend_from_slice(&sig_bytes);
        tx.inputs[i].signature_script = hex::encode(script);
    }

    // Broadcast
    let req = SubmitTxRequest { transaction: tx, allow_orphan: false };
    let payload = serde_json::to_string(&req).map_err(|e| e.to_string())?;
    let resp_body = http_post_json("https://api.kaspa.org/transactions", &payload)?;
    let resp: SubmitTxResponse = serde_json::from_slice(&resp_body)
        .map_err(|e| format!("parse broadcast response: {}", e))?;

    Ok(TxResult { txid: resp.transaction_id, status: "submitted".into() })
}

fn select_utxos(utxos: &[UtxoEntry], required: u64) -> Result<Vec<UtxoEntry>, String> {
    let mut sorted = utxos.to_vec();
    sorted.sort_by(|a, b| {
        let va: u64 = a.entry.amount.parse().unwrap_or(0);
        let vb: u64 = b.entry.amount.parse().unwrap_or(0);
        vb.cmp(&va)
    });
    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for utxo in sorted {
        let amount: u64 = utxo.entry.amount.parse()
            .map_err(|_| "invalid utxo amount")?;
        total += amount;
        selected.push(utxo);
        if total >= required {
            return Ok(selected);
        }
    }
    Err(format!("insufficient funds: have {} sompi, need {} sompi", total, required))
}

// ---------------------------------------------------------------------------
// IronClaw tool interface
// ---------------------------------------------------------------------------

struct Component;

impl Guest for Component {
    fn execute(req: Request) -> Response {
        let mnemonic = match std::env::var("KASPA_MNEMONIC") {
            Ok(v) if !v.is_empty() => v,
            _ => return Response {
                output: None,
                error: Some("KASPA_MNEMONIC not set — run: ironclaw tool setup kaspa_send".into()),
            },
        };

        let params: SendParams = match serde_json::from_str(&req.params) {
            Ok(p) => p,
            Err(e) => return Response {
                output: None,
                error: Some(format!("invalid params: {}", e)),
            },
        };

        match send_kas(&params, &mnemonic) {
            Ok(result) => Response {
                output: Some(serde_json::to_string(&result).unwrap()),
                error: None,
            },
            Err(e) => Response {
                output: None,
                error: Some(e),
            },
        }
    }

    fn schema() -> String {
        r#"{
  "type": "object",
  "required": ["recipient", "amount_kas"],
  "properties": {
    "recipient": {
      "type": "string",
      "description": "Kaspa recipient address (kaspa:q...)"
    },
    "amount_kas": {
      "type": "number",
      "description": "Amount to send in KAS (1 KAS = 100000000 sompi)"
    },
    "priority_fee_sompi": {
      "type": "integer",
      "description": "Optional miner tip in sompi (default 0)",
      "default": 0
    }
  }
}"#.into()
    }

    fn description() -> String {
        "Send KAS tokens on the Kaspa blockchain. Requires KASPA_MNEMONIC secret.".into()
    }
}

bindings::export!(Component with_types_in bindings);
