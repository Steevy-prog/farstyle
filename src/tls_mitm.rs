/// TLS MITM engine for FARSTYLE proxy.
///
/// On first use this module generates a self-signed CA keypair that is stored
/// in ~/.config/farstyle/ca.pem / ca.key.pem.  Per-host leaf certificates are
/// generated on-the-fly and signed by that CA.
///
/// The browser / curl / tool under test must trust the CA certificate.  The
/// path to the CA cert is exposed via `ca_cert_path()` so the UI can show it.
///
/// Threading model
/// ---------------
/// `mitm_connect()` is called from a proxy handler thread.  It:
///  1. Completes the CONNECT handshake with the client.
///  2. Wraps the client TCP stream in a server-side TLS session (presenting the
///     per-host cert).
///  3. Opens a plain TLS connection to the real upstream.
///  4. Reads the decrypted HTTP/1.1 request from the client TLS stream.
///  5. Returns the decrypted bytes to the caller (proxy handler) so the normal
///     intercept / capture logic can run on them as if it were plain HTTP.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};

// ── CA storage ────────────────────────────────────────────────────────────────

fn farstyle_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("farstyle")
}

pub fn ca_cert_path() -> PathBuf {
    farstyle_dir().join("ca.pem")
}

fn ca_key_path() -> PathBuf {
    farstyle_dir().join("ca.key.pem")
}

// ── In-process CA singleton ───────────────────────────────────────────────────

struct CaState {
    #[allow(dead_code)] // retained PEM for export/inspection; signing uses key_pem
    cert_pem: String,
    key_pem: String,
    /// DER bytes of the self-signed CA cert, kept for signing leaf certs
    cert_der: Vec<u8>,
}

static CA: OnceLock<Arc<Mutex<CaState>>> = OnceLock::new();

/// Load or generate the CA.  Returns `Err` if the CA cannot be created.
pub fn ensure_ca() -> Result<(), String> {
    CA.get_or_init(|| {
        let state = load_or_create_ca()
            .unwrap_or_else(|e| panic!("Failed to init CA: {}", e));
        Arc::new(Mutex::new(state))
    });
    Ok(())
}

fn load_or_create_ca() -> Result<CaState, String> {
    let cert_path = ca_cert_path();
    let key_path  = ca_key_path();

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| format!("read CA cert: {}", e))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .map_err(|e| format!("read CA key: {}", e))?;
        // Re-generate in-memory to get the DER for signing
        let key = KeyPair::from_pem(&key_pem).map_err(|e| e.to_string())?;
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
        let cert_der = cert.der().to_vec();
        return Ok(CaState { cert_pem, key_pem, cert_der });
    }

    // Generate new CA
    let key = KeyPair::generate().map_err(|e| e.to_string())?;

    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "FARSTYLE Proxy CA");
    dn.push(DnType::OrganizationName, "FARSTYLE");
    params.distinguished_name = dn;

    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    let cert_pem = cert.pem();
    let cert_der = cert.der().to_vec();
    let key_pem  = key.serialize_pem();

    std::fs::create_dir_all(farstyle_dir())
        .map_err(|e| format!("mkdir: {}", e))?;
    std::fs::write(&cert_path, &cert_pem)
        .map_err(|e| format!("write CA cert: {}", e))?;
    std::fs::write(&key_path, &key_pem)
        .map_err(|e| format!("write CA key: {}", e))?;

    Ok(CaState { cert_pem, key_pem, cert_der })
}

// ── Per-host certificate generation ──────────────────────────────────────────

fn make_leaf_cert(hostname: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let ca_state = CA.get().ok_or("CA not initialised")?;
    let ca_state = ca_state.lock().unwrap();

    // Reconstruct CA keypair + cert for signing
    let ca_key = KeyPair::from_pem(&ca_state.key_pem).map_err(|e| e.to_string())?;
    let ca_cert_der = CertificateDer::from(ca_state.cert_der.clone());
    let ca_cert = rcgen::CertificateParams::default()
        .self_signed(&ca_key)
        .map_err(|e| e.to_string())?;

    // Build leaf cert signed by CA
    let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::default();
    let san = rcgen::SanType::DnsName(
        hostname.to_string().try_into().map_err(|e: rcgen::Error| e.to_string())?
    );
    params.subject_alt_names = vec![san];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    params.distinguished_name = dn;

    let _ = ca_cert_der; // stored in CaState; signing uses the in-memory cert
    let leaf_cert = params.signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|e| e.to_string())?;

    Ok((leaf_cert.der().to_vec(), leaf_key.serialize_der()))
}

// ── Main MITM entry point ─────────────────────────────────────────────────────

/// Called by the proxy handler after it has read the CONNECT line but before
/// sending `200 Connection Established`.
///
/// Returns the decrypted HTTP/1.1 request bytes (headers + body) that the
/// proxy's normal capture path can handle, plus the upstream TLS stream
/// wrapped in a Box so the caller can pipe the response back.
pub struct MitmSession {
    pub request_bytes: Vec<u8>,
    pub client_tls:    Box<dyn ReadWrite>,
    pub upstream_tls:  Box<dyn ReadWrite>,
}

pub trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

pub fn mitm_connect(
    mut client: TcpStream,
    host: &str,
    port: u16,
) -> Result<MitmSession, String> {
    ensure_ca()?;

    // 1. Tell the client "tunnel established"
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| e.to_string())?;

    // 2. Build server-side TLS config with per-host leaf cert
    let hostname = host.trim_matches(|c: char| c == '[' || c == ']'); // strip IPv6 brackets
    let (leaf_cert_der, leaf_key_der) = make_leaf_cert(hostname)?;

    let cert_chain = vec![CertificateDer::from(leaf_cert_der)];
    let priv_key   = PrivateKeyDer::try_from(leaf_key_der)
        .map_err(|e| e.to_string())?;

    let server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)
        .map_err(|e| e.to_string())?;

    let mut server_conn = rustls::ServerConnection::new(Arc::new(server_cfg))
        .map_err(|e| e.to_string())?;

    // 3. Perform TLS handshake with client (blocking, 10s timeout)
    client.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut tls_client = rustls::Stream::new(&mut server_conn, &mut client);

    // 4. Connect upstream with TLS
    let upstream_addr = format!("{}:{}", host, port);
    let upstream_tcp = TcpStream::connect(&upstream_addr)
        .map_err(|e| format!("upstream connect {}: {}", upstream_addr, e))?;
    upstream_tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();

    // Build client config that accepts any cert (for internal / self-signed upstreams)
    // For strict validation, swap in a proper RootCertStore.
    let client_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|e| format!("invalid server name: {}", e))?;
    let client_conn = rustls::ClientConnection::new(Arc::new(client_cfg), server_name)
        .map_err(|e| e.to_string())?;

    // 5. Read the decrypted HTTP request from the client TLS stream
    let mut req_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = tls_client.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 { break; }
        req_buf.extend_from_slice(&tmp[..n]);
        if req_buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if req_buf.len() > 4 * 1024 * 1024 { break; }
    }

    // Read body based on Content-Length if present
    let body_bytes = extract_body_from_request(&req_buf, &mut tls_client);
    req_buf.extend_from_slice(&body_bytes);

    // We need to store the streams for the caller to forward the response.
    // Since we used references above we need to reconstruct them.
    // Re-wrap as owned objects using a wrapper struct.
    let client_owned = TlsServerStream {
        conn: server_conn,
        tcp:  client,
    };
    let upstream_owned = TlsClientStream {
        conn: client_conn,
        tcp:  upstream_tcp,
    };

    Ok(MitmSession {
        request_bytes: req_buf,
        client_tls:    Box::new(client_owned),
        upstream_tls:  Box::new(upstream_owned),
    })
}

/// Read the body from the TLS client stream given the already-parsed header
/// block.  Handles `Content-Length`.  Returns body bytes (may be empty).
fn extract_body_from_request(headers_buf: &[u8], stream: &mut impl Read) -> Vec<u8> {
    let header_text = std::str::from_utf8(headers_buf).unwrap_or("");
    let content_length: usize = header_text
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split_once(':'))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);

    if content_length == 0 { return Vec::new(); }

    let mut body = vec![0u8; content_length];
    let mut read = 0;
    while read < content_length {
        match stream.read(&mut body[read..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => read += n,
        }
    }
    body.truncate(read);
    body
}

// ── Owned TLS stream wrappers ─────────────────────────────────────────────────

struct TlsServerStream {
    conn: rustls::ServerConnection,
    tcp:  TcpStream,
}

impl Read for TlsServerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        rustls::Stream::new(&mut self.conn, &mut self.tcp).read(buf)
    }
}
impl Write for TlsServerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        rustls::Stream::new(&mut self.conn, &mut self.tcp).write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        rustls::Stream::new(&mut self.conn, &mut self.tcp).flush()
    }
}

struct TlsClientStream {
    conn: rustls::ClientConnection,
    tcp:  TcpStream,
}

impl Read for TlsClientStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        rustls::Stream::new(&mut self.conn, &mut self.tcp).read(buf)
    }
}
impl Write for TlsClientStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        rustls::Stream::new(&mut self.conn, &mut self.tcp).write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        rustls::Stream::new(&mut self.conn, &mut self.tcp).flush()
    }
}

// ── Dangerous: accept-all certificate verifier for upstream ──────────────────

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
