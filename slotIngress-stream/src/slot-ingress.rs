//! slot — connects to quic-sol-server, receives gossip slots, calls getBlock for each

use std::{net::SocketAddr, sync::Arc};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ── Wire protocol ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientHandshake {
    service: ServiceKind,
    api_key: Option<String>,
    params: ServiceParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ServiceKind { Slot }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ServiceParams {
    Slot {
        rpc_url: String,
        #[serde(default)]
        filter_programs: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
struct ServerAck {
    ok: bool,
    message: String,
    session_id: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
enum ServerFrame {
    SlotTransaction(SlotTransaction),
    SlotConfirmed(SlotConfirmed),
    Heartbeat,
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct UiTokenAmount {
    amount: String,
    decimals: u8,
    ui_amount: Option<f64>,
    ui_amount_string: String,
}

#[derive(Debug, Deserialize)]
struct TransactionTokenBalance {
    account_index: u8,
    mint: String,
    ui_token_amount: UiTokenAmount,
    owner: String,
    program_id: String,
}

#[derive(Debug, Deserialize)]
struct InnerInstruction {
    program_id_index: u8,
    accounts: Vec<u8>,
    data: String,
    stack_height: u32,
}

#[derive(Debug, Deserialize)]
struct InnerInstructions {
    index: u8,
    instructions: Vec<InnerInstruction>,
}

#[derive(Debug, Deserialize)]
struct LoadedAddresses {
    writable: Vec<String>,
    readonly: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TransactionReturnData {
    program_id: String,
    data: String,
}

#[derive(Debug, Deserialize)]
struct TransactionStatusMeta {
    err: Option<serde_json::Value>,
    fee: u64,
    pre_balances: Vec<u64>,
    post_balances: Vec<u64>,
    #[serde(default)]
    inner_instructions: Vec<InnerInstructions>,
    log_messages: Option<Vec<String>>,
    pre_token_balances: Option<Vec<TransactionTokenBalance>>,
    post_token_balances: Option<Vec<TransactionTokenBalance>>,
    loaded_addresses: Option<LoadedAddresses>,
    return_data: Option<TransactionReturnData>,
    compute_units_consumed: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SlotTransaction {
    slot: u64,
    block_time: Option<i64>,
    signature: String,
    program_ids: Vec<String>,
    fee: u64,
    compute_units_consumed: Option<u64>,
    priority_fee_micro_lamports: Option<u64>,
    meta: TransactionStatusMeta,
    received_at_ms: u64,
}

#[derive(Debug, Deserialize)]
struct SlotConfirmed {
    slot: u64,
    tx_count: u32,
    tx_emitted: u32,
    received_at_ms: u64,
}

// ── TLS: skip verify ──────────────────────────────────────────────────────────

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer, _: &[rustls::pki_types::CertificateDer], _: &rustls::pki_types::ServerName, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

// ── Framing ───────────────────────────────────────────────────────────────────

fn encode(value: &impl Serialize) -> Vec<u8> {
    let body = serde_json::to_vec(value).unwrap();
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

async fn read_frame<T: for<'de> serde::Deserialize<'de>>(
    recv: &mut quinn::RecvStream,
) -> Result<T> {
    let mut hdr = [0u8; 4];
    recv.read_exact(&mut hdr).await.context("read header")?;
    let len = u32::from_be_bytes(hdr) as usize;
    anyhow::ensure!(len <= 4 * 1024 * 1024, "frame too large");
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.context("read body")?;
    serde_json::from_slice(&body).context("deserialize")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sig_short(sig: &str) -> String {
    if sig.len() >= 16 {
        format!("{}..{}", &sig[..8], &sig[sig.len()-8..])
    } else {
        sig.to_string()
    }
}

fn shorten_program(id: &str) -> &str {
    match id {
        "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"  => "Pump.fun",
        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4" => "Jupiter",
        "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8" => "Raydium",
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"  => "Orca",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"  => "Token",
        "11111111111111111111111111111111"               => "System",
        "ComputeBudget111111111111111111111111111111"    => "ComputeBudget",
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" => "ATA",
        other => other,
    }
}

fn rpc_health(latency_ms: u64) -> &'static str {
    match latency_ms {
        0..=1500        => "🟢 LOW",
        1501..=5000     => "🟡 MID",
        5001..=20000    => "🔴 HIGH",
        20001..=30000   => "⚫ LIMIT",
        _               => "💀 OFFLINE",
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let server = std::env::args().nth(1)
        .unwrap_or_else(|| "216.128.152.28:4433".to_string());

    let rpc_url = std::env::args().nth(2)
        .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());

    rustls::crypto::ring::default_provider().install_default().ok();

    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut ep = quinn::Endpoint::client("[::]:0".parse::<SocketAddr>()?)?;
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_cfg)));

    let addr: SocketAddr = server.parse().context("invalid address")?;
    println!("Connecting to {} ...", addr);
    println!("RPC: {}", rpc_url.split('?').next().unwrap_or(&rpc_url));

    let conn = ep.connect(addr, "localhost")?.await.context("connect")?;
    let (mut send, mut recv) = conn.open_bi().await?;

    let hs = encode(&ClientHandshake {
        service: ServiceKind::Slot,
        api_key: None,
        params: ServiceParams::Slot {
            rpc_url,
            filter_programs: vec![],
        },
    });
    send.write_all(&hs).await?;
    send.finish()?;

    let ack: ServerAck = read_frame(&mut recv).await?;
    anyhow::ensure!(ack.ok, "server rejected: {}", ack.message);
    println!("✓ session {} — {}\n", ack.session_id, ack.message);

    let mut tx_count = 0u64;
    let mut slot_count = 0u64;

    loop {
        match read_frame::<ServerFrame>(&mut recv).await? {
            ServerFrame::SlotTransaction(tx) => {
               println!("{:#?}", tx);
            }

            ServerFrame::SlotConfirmed(sc) => {
                slot_count += 1;
                let latency = now_ms().saturating_sub(sc.received_at_ms);
                println!(
                    "\n  ✅ slot {} — {}/{} txs  rpc-health={}  [slot #{} total]\n",
                    sc.slot, sc.tx_emitted, sc.tx_count, rpc_health(latency), slot_count
                );
            }

            ServerFrame::Heartbeat => {
                println!("  💓 heartbeat  ({tx_count} txs, {slot_count} slots so far)");
            }

            ServerFrame::Other => {}
        }
    }
}
