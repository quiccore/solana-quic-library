use std::{net::SocketAddr, sync::Arc};
use anyhow::Result;
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct AccountMeta {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecodedInstruction {
    program_id: String,
    accounts: Vec<String>,
    data: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecodedTransaction {
    slot: u64,
    signatures: Vec<String>,
    signature: String,
    program_ids: Vec<String>,
    accounts: Vec<AccountMeta>,
    instructions: Vec<DecodedInstruction>,
    recent_blockhash: String,
    timestamp_us: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubscriptionFilter {
    program_ids: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth();

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
    ));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let server_addr: SocketAddr = "35.234.100.129:9000".parse()?;
    println!("Connecting to {server_addr}...");

    let conn = endpoint.connect(server_addr, "localhost")?.await?;
    println!("Connected! Waiting for transactions...\n");
    let filter = SubscriptionFilter { program_ids: vec![] };
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&serde_json::to_vec(&filter)?).await?;
    send.finish()?;
    drop(recv);

    let mut count = 0u64;
    let mut total_latency_us: u64 = 0;
    let mut min_latency_us: u64 = u64::MAX;
    let mut max_latency_us: u64 = 0;

    loop {
        match conn.accept_uni().await {
            Ok(mut stream) => {
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).await.is_err() { continue; }
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                if stream.read_exact(&mut buf).await.is_err() { continue; }

                if let Ok(tx) = serde_json::from_slice::<DecodedTransaction>(&buf) {
                    println!("{:#?}", tx);                  
                }
            }
            Err(e) => { eprintln!("Connection closed: {e}"); break; }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
