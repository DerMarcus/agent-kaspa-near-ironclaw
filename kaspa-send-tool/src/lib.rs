use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use serde::{Deserialize, Serialize};
use blake2::{Blake2b, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use bip39::Mnemonic;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Public API types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct SendParams {
    pub recipient: String,
    pub amount_kas: f64,
    pub priority_fee_sompi: u64,
}

#[derive(Serialize, Deserialize)]
pub struct TxResult {
    pub txid: String,
    pub status: String,
}

// ---------------------------------------------------------------------------
// Internal types mirroring Kaspa REST API shapes
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UtxoEntry {
    #[serde(rename = "outpoint")]
    pub outpoint: Outpoint,
    #[serde(rename = "utxoEntry")]
    pub entry: UtxoData,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Outpoint {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    pub index: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UtxoData {
    pub amount: String, // sompi as string in API response
    #[serde(rename = "scriptPublicKey")]
    pub script_public_key: ScriptPublicKey,
    #[serde(rename = "blockDaaScore")]
    pub block_daa_score: String,
    #[serde(rename = "isCoinbase")]
    pub is_coinbase: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScriptPublicKey {
    #[serde(rename = "scriptPublicKey")]
    pub script: String, // hex-encoded script
    pub version: u16,
}

// Kaspa REST API transaction submission structures
#[derive(Serialize, Deserialize)]
struct KaspaTransactionInput {
    #[serde(rename = "previousOutpoint")]
    previous_outpoint: PreviousOutpoint,
    #[serde(rename = "signatureScript")]
    signature_script: String, // hex
    sequence: u64,
    #[serde(rename = "sigOpCount")]
    sig_op_count: u8,
}

#[derive(Serialize, Deserialize)]
struct PreviousOutpoint {
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u32,
}

#[derive(Serialize, Deserialize)]
struct KaspaTransactionOutput {
    amount: u64,
    #[serde(rename = "scriptPublicKey")]
    script_public_key: ScriptPublicKeyOut,
}

#[derive(Serialize, Deserialize)]
struct ScriptPublicKeyOut {
    version: u16,
    #[serde(rename = "scriptPublicKey")]
    script: String, // hex
}

#[derive(Serialize, Deserialize)]
struct KaspaTransaction {
    version: u16,
    inputs: Vec<KaspaTransactionInput>,
    outputs: Vec<KaspaTransactionOutput>,
    #[serde(rename = "lockTime")]
    lock_time: u64,
    #[serde(rename = "subnetworkId")]
    subnetwork_id: String,
}

#[derive(Serialize, Deserialize)]
struct SubmitTxRequest {
    transaction: KaspaTransaction,
    #[serde(rename = "allowOrphan")]
    allow_orphan: bool,
}

#[derive(Serialize, Deserialize)]
struct SubmitTxResponse {
    #[serde(rename = "transactionId")]
    transaction_id: String,
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

struct KaspaKeypair {
    secret_key: SecretKey,
    public_key: PublicKey,
    address: String,
}

// ---------------------------------------------------------------------------
// Kaspa address encoding
//
// Kaspa uses a custom bech32-like encoding:
//   - HRP: "kaspa" (mainnet)
//   - Payload: version_byte (0x00 for P2PK Schnorr) + 32-byte x-only pubkey
// ---------------------------------------------------------------------------

fn encode_kaspa_address(pubkey: &PublicKey) -> String {
    let xonly = &pubkey.serialize()[1..]; // drop 02/03 prefix → 32 bytes
    // version byte 0 = P2PK (Schnorr)
    let mut payload = vec![0u8];
    payload.extend_from_slice(xonly);
    // 5-bit base32 conversion
    let b32 = to_base32(&payload);
    let checksum = kaspa_checksum("kaspa", &b32);
    let mut chars: Vec<char> = b32.iter().map(|b| CHARSET[*b as usize]).collect();
    for i in 0..8 {
        chars.push(CHARSET[((checksum >> (5 * (7 - i))) & 0x1f) as usize]);
    }
    format!("kaspa:{}", chars.iter().collect::<String>())
}

const CHARSET: [char; 32] = [
    'q','p','z','r','y','9','x','8','g','f','2','t','v','d','w','0',
    's','3','j','n','5','4','k','h','c','e','6','m','u','a','7','l',
];

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
// p2pk script helpers
// ---------------------------------------------------------------------------

fn p2pk_script(pubkey: &PublicKey) -> String {
    // OP_DATA_32 <xonly_pubkey_32_bytes> OP_CHECKSIG
    // Kaspa P2PK: 0x20 <32-byte xonly pubkey> 0xac
    let xonly = &pubkey.serialize()[1..];
    let mut script = vec![0x20u8];
    script.extend_from_slice(xonly);
    script.push(0xac);
    hex::encode(script)
}

fn address_to_script(address: &str) -> Result<(u16, String), JsValue> {
    // Strip "kaspa:" prefix and decode
    let addr = address
        .strip_prefix("kaspa:")
        .ok_or_else(|| JsValue::from_str("invalid address: missing kaspa: prefix"))?;

    // Decode bech32 chars to 5-bit values
    let b32: Result<Vec<u8>, _> = addr.chars().map(|c| {
        CHARSET.iter().position(|&x| x == c)
            .map(|p| p as u8)
            .ok_or_else(|| JsValue::from_str("invalid address char"))
    }).collect();
    let b32 = b32?;

    // Last 8 values are checksum — strip them
    if b32.len() < 9 {
        return Err(JsValue::from_str("address too short"));
    }
    let payload_b32 = &b32[..b32.len() - 8];

    // Convert 5-bit to 8-bit
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
        return Err(JsValue::from_str("empty address payload"));
    }

    let version = result[0] as u16;
    let pubkey_bytes = &result[1..];

    // Build P2PK script: 0x20 <32 bytes> 0xac
    let mut script = vec![0x20u8];
    script.extend_from_slice(pubkey_bytes);
    script.push(0xac);
    Ok((version, hex::encode(script)))
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

fn derive_kaspa_keypair(mnemonic_phrase: &str) -> Result<KaspaKeypair, JsValue> {
    let mnemonic = Mnemonic::from_str(mnemonic_phrase)
        .map_err(|e| JsValue::from_str(&format!("invalid mnemonic: {}", e)))?;

    let seed = mnemonic.to_seed("");

    // BIP44 derivation: m/44'/111111'/0'/0/0
    // Manually derive using HMAC-SHA512 (BIP32)
    let secret_key = derive_bip32_key(&seed)?;

    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let address = encode_kaspa_address(&public_key);

    Ok(KaspaKeypair { secret_key, public_key, address })
}

/// Minimal BIP32 derivation for path m/44'/111111'/0'/0/0
fn derive_bip32_key(seed: &[u8]) -> Result<SecretKey, JsValue> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    // Master key
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    let (mut key_bytes, mut chain_code): ([u8; 32], [u8; 32]) = (
        result[..32].try_into().unwrap(),
        result[32..].try_into().unwrap(),
    );

    // Path: 44' = 0x8000002C, 111111' = 0x8001B207, 0' = 0x80000000, 0, 0
    let path: &[u32] = &[
        0x8000_002C,
        0x8001_B207,
        0x8000_0000,
        0,
        0,
    ];

    let secp = Secp256k1::new();

    for &index in path {
        let mut data = Vec::with_capacity(37);
        if index >= 0x8000_0000 {
            // Hardened: 0x00 || key
            data.push(0x00);
            data.extend_from_slice(&key_bytes);
        } else {
            // Normal: serialized compressed pubkey
            let sk = SecretKey::from_slice(&key_bytes)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let pk = PublicKey::from_secret_key(&secp, &sk);
            data.extend_from_slice(&pk.serialize());
        }
        data.extend_from_slice(&index.to_be_bytes());

        let mut child_mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        child_mac.update(&data);
        let child_result = child_mac.finalize().into_bytes();

        // child_key = parse256(IL) + parent_key (mod n)
        let il: [u8; 32] = child_result[..32].try_into().unwrap();
        chain_code = child_result[32..].try_into().unwrap();

        let mut child_sk = SecretKey::from_slice(&il)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        child_sk = child_sk.add_tweak(&secp256k1::Scalar::from_be_bytes(key_bytes).unwrap())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        key_bytes = *child_sk.as_ref();
    }

    SecretKey::from_slice(&key_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ---------------------------------------------------------------------------
// UTXO fetching
// ---------------------------------------------------------------------------

async fn fetch_utxos(address: &str) -> Result<Vec<UtxoEntry>, JsValue> {
    use web_sys::{Request, RequestInit, RequestMode, Response};
    use wasm_bindgen::JsCast;

    let url = format!("https://api.kaspa.org/addresses/{}/utxos", address);

    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&url, &opts)?;

    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp_value.dyn_into()?;

    if !resp.ok() {
        return Err(JsValue::from_str(&format!(
            "fetch_utxos: HTTP {}", resp.status()
        )));
    }

    let json = JsFuture::from(resp.json()?).await?;
    let utxos: Vec<UtxoEntry> = serde_wasm_bindgen::from_value(json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(utxos)
}

// ---------------------------------------------------------------------------
// UTXO selection (largest-first)
// ---------------------------------------------------------------------------

fn select_utxos(utxos: &[UtxoEntry], required_sompi: u64) -> Result<Vec<UtxoEntry>, JsValue> {
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
            .map_err(|_| JsValue::from_str("invalid utxo amount"))?;
        total += amount;
        selected.push(utxo);
        if total >= required_sompi {
            return Ok(selected);
        }
    }

    Err(JsValue::from_str(&format!(
        "insufficient funds: have {} sompi, need {} sompi",
        total, required_sompi
    )))
}

// ---------------------------------------------------------------------------
// Transaction building + signing
// ---------------------------------------------------------------------------

/// Kaspa sighash (SIGHASH_ALL):
///   Blake2b-256 of the serialised transaction components
///   Reference: https://github.com/kaspanet/kaspad/blob/master/domain/consensus/utils/transactionhelper/transaction_sighash.go
fn kaspa_sighash(
    tx: &KaspaTransaction,
    input_index: usize,
    utxo: &UtxoEntry,
) -> [u8; 32] {
    let mut hasher = blake2::Blake2b256::new();

    // 1. version (2 bytes LE)
    hasher.update(tx.version.to_le_bytes());

    // 2. hash of all previous outpoints
    let mut prev_hasher = blake2::Blake2b256::new();
    for inp in &tx.inputs {
        let txid_bytes = hex::decode(&inp.previous_outpoint.transaction_id).unwrap_or_default();
        prev_hasher.update(&txid_bytes);
        prev_hasher.update(inp.previous_outpoint.index.to_le_bytes());
    }
    hasher.update(prev_hasher.finalize());

    // 3. hash of all sequences
    let mut seq_hasher = blake2::Blake2b256::new();
    for inp in &tx.inputs {
        seq_hasher.update(inp.sequence.to_le_bytes());
    }
    hasher.update(seq_hasher.finalize());

    // 4. hash of all sigop counts
    let mut sop_hasher = blake2::Blake2b256::new();
    for inp in &tx.inputs {
        sop_hasher.update([inp.sig_op_count]);
    }
    hasher.update(sop_hasher.finalize());

    // 5. this input's outpoint
    let txid_bytes = hex::decode(&tx.inputs[input_index].previous_outpoint.transaction_id)
        .unwrap_or_default();
    hasher.update(&txid_bytes);
    hasher.update(tx.inputs[input_index].previous_outpoint.index.to_le_bytes());

    // 6. this input's utxo script
    let script_bytes = hex::decode(&utxo.entry.script_public_key.script).unwrap_or_default();
    hasher.update((script_bytes.len() as u64).to_le_bytes());
    hasher.update(&script_bytes);

    // 7. this input's utxo amount
    let amount: u64 = utxo.entry.amount.parse().unwrap_or(0);
    hasher.update(amount.to_le_bytes());

    // 8. this input's utxo script version
    hasher.update(utxo.entry.script_public_key.version.to_le_bytes());

    // 9. this input's sequence
    hasher.update(tx.inputs[input_index].sequence.to_le_bytes());

    // 10. this input's sig op count
    hasher.update([tx.inputs[input_index].sig_op_count]);

    // 11. hash of all outputs
    let mut out_hasher = blake2::Blake2b256::new();
    for out in &tx.outputs {
        out_hasher.update(out.amount.to_le_bytes());
        out_hasher.update(out.script_public_key.version.to_le_bytes());
        let sc = hex::decode(&out.script_public_key.script).unwrap_or_default();
        out_hasher.update((sc.len() as u64).to_le_bytes());
        out_hasher.update(&sc);
    }
    hasher.update(out_hasher.finalize());

    // 12. lock time (8 bytes LE)
    hasher.update(tx.lock_time.to_le_bytes());

    // 13. subnetwork ID (20 bytes)
    let subnet_bytes = hex::decode(&tx.subnetwork_id).unwrap_or_default();
    hasher.update(&subnet_bytes);

    // 14. gas (8 bytes LE, 0 for native subnetwork)
    hasher.update(0u64.to_le_bytes());

    // 15. payload hash
    let mut pay_hasher = blake2::Blake2b256::new();
    pay_hasher.update([]); // empty payload for native subnetwork
    hasher.update(pay_hasher.finalize());

    // 16. sighash type (1 = SIGHASH_ALL)
    hasher.update(1u8.to_le_bytes());

    hasher.finalize().into()
}

fn build_and_sign_transaction(
    keypair: &KaspaKeypair,
    selected_utxos: &[UtxoEntry],
    params: &SendParams,
) -> Result<KaspaTransaction, JsValue> {
    let amount_sompi = (params.amount_kas * 100_000_000.0) as u64;
    let fee = params.priority_fee_sompi;
    let total_input: u64 = selected_utxos.iter()
        .map(|u| u.entry.amount.parse::<u64>().unwrap_or(0))
        .sum();
    let change = total_input
        .checked_sub(amount_sompi + fee)
        .ok_or_else(|| JsValue::from_str("arithmetic overflow on change calculation"))?;

    // Build inputs (signature scripts filled in after signing)
    let inputs: Vec<KaspaTransactionInput> = selected_utxos.iter().map(|u| {
        KaspaTransactionInput {
            previous_outpoint: PreviousOutpoint {
                transaction_id: u.outpoint.transaction_id.clone(),
                index: u.outpoint.index,
            },
            signature_script: String::new(), // filled after signing
            sequence: 0,
            sig_op_count: 1,
        }
    }).collect();

    // Build outputs
    let (_, recipient_script) = address_to_script(&params.recipient)?;
    let mut outputs = vec![
        KaspaTransactionOutput {
            amount: amount_sompi,
            script_public_key: ScriptPublicKeyOut {
                version: 0,
                script: recipient_script,
            },
        },
    ];

    // Only add change output if it covers minimum dust threshold (1000 sompi)
    if change >= 1000 {
        outputs.push(KaspaTransactionOutput {
            amount: change,
            script_public_key: ScriptPublicKeyOut {
                version: 0,
                script: p2pk_script(&keypair.public_key),
            },
        });
    }

    // Native subnetwork ID = 20 zero bytes
    let subnetwork_id = "0000000000000000000000000000000000000000".to_string();

    let mut tx = KaspaTransaction {
        version: 0,
        inputs,
        outputs,
        lock_time: 0,
        subnetwork_id,
    };

    // Sign each input
    let secp = Secp256k1::new();
    for i in 0..selected_utxos.len() {
        let sighash = kaspa_sighash(&tx, i, &selected_utxos[i]);
        let msg = Message::from_digest(sighash);
        // Schnorr signature
        let keypair_obj = secp256k1::Keypair::from_secret_key(&secp, &keypair.secret_key);
        let sig = secp.sign_schnorr(&msg, &keypair_obj);
        // signature_script: <sig_len> <sig_bytes> (64 bytes Schnorr)
        let sig_bytes = sig.as_ref();
        let mut script = vec![sig_bytes.len() as u8];
        script.extend_from_slice(sig_bytes);
        tx.inputs[i].signature_script = hex::encode(script);
    }

    Ok(tx)
}

// ---------------------------------------------------------------------------
// Broadcast
// ---------------------------------------------------------------------------

async fn broadcast_transaction(tx: KaspaTransaction) -> Result<String, JsValue> {
    use web_sys::{Request, RequestInit, RequestMode, Response};
    use wasm_bindgen::JsCast;

    let body = serde_json::to_string(&SubmitTxRequest {
        transaction: tx,
        allow_orphan: false,
    }).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.body(Some(&JsValue::from_str(&body)));

    let request = Request::new_with_str_and_init("https://api.kaspa.org/transactions", &opts)?;
    request.headers().set("Content-Type", "application/json")?;

    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp_value.dyn_into()?;

    if !resp.ok() {
        let text = JsFuture::from(resp.text()?).await?;
        return Err(JsValue::from_str(&format!(
            "broadcast failed (HTTP {}): {}",
            resp.status(),
            text.as_string().unwrap_or_default()
        )));
    }

    let json = JsFuture::from(resp.json()?).await?;
    let result: SubmitTxResponse = serde_wasm_bindgen::from_value(json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(result.transaction_id)
}

// ---------------------------------------------------------------------------
// Main entry point (called by IronClaw host)
// ---------------------------------------------------------------------------

/// Send KAS tokens.
///
/// # Arguments
/// * `params_json` — JSON-serialised `SendParams`
/// * `mnemonic`    — BIP39 mnemonic injected by IronClaw from the encrypted vault;
///                   this value never leaves the WASM sandbox.
#[wasm_bindgen]
pub async fn kaspa_send(params_json: &str, mnemonic: &str) -> Result<String, JsValue> {
    let params: SendParams = serde_json::from_str(params_json)
        .map_err(|e| JsValue::from_str(&format!("invalid params: {}", e)))?;

    // 1. Derive keypair
    let keypair = derive_kaspa_keypair(mnemonic)?;

    // 2. Fetch UTXOs
    let utxos = fetch_utxos(&keypair.address).await?;

    if utxos.is_empty() {
        return Err(JsValue::from_str("no UTXOs found for address"));
    }

    // 3. Select UTXOs
    let amount_sompi = (params.amount_kas * 100_000_000.0) as u64;
    let required = amount_sompi + params.priority_fee_sompi;
    let selected = select_utxos(&utxos, required)?;

    // 4. Build + sign transaction
    let signed_tx = build_and_sign_transaction(&keypair, &selected, &params)?;

    // 5. Broadcast
    let txid = broadcast_transaction(signed_tx).await?;

    let result = TxResult { txid, status: "submitted".into() };
    Ok(serde_json::to_string(&result).unwrap())
}
