use base64::Engine;
use md5::Digest as Md5Digest;
#[allow(unused_imports)] use sha1::Digest as Sha1Digest;
#[allow(unused_imports)] use sha2::Digest as Sha2Digest;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Base64Encode,
    Base64Decode,
    HexEncode,
    HexDecode,
    UrlEncode,
    UrlDecode,
    HtmlEncode,
    HtmlDecode,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Rot13,
    Reverse,
}

impl Op {
    pub fn label(&self) -> &'static str {
        match self {
            Op::Base64Encode => "Base64 Encode",
            Op::Base64Decode => "Base64 Decode",
            Op::HexEncode => "Hex Encode",
            Op::HexDecode => "Hex Decode",
            Op::UrlEncode => "URL Encode",
            Op::UrlDecode => "URL Decode",
            Op::HtmlEncode => "HTML Encode",
            Op::HtmlDecode => "HTML Decode",
            Op::Md5 => "MD5 Hash",
            Op::Sha1 => "SHA-1 Hash",
            Op::Sha256 => "SHA-256 Hash",
            Op::Sha512 => "SHA-512 Hash",
            Op::Rot13 => "ROT13",
            Op::Reverse => "Reverse",
        }
    }

    pub fn all() -> &'static [Op] {
        &[
            Op::Base64Encode,
            Op::Base64Decode,
            Op::HexEncode,
            Op::HexDecode,
            Op::UrlEncode,
            Op::UrlDecode,
            Op::HtmlEncode,
            Op::HtmlDecode,
            Op::Md5,
            Op::Sha1,
            Op::Sha256,
            Op::Sha512,
            Op::Rot13,
            Op::Reverse,
        ]
    }
}

pub fn apply(op: Op, input: &str) -> Result<String, String> {
    match op {
        Op::Base64Encode => Ok(base64::engine::general_purpose::STANDARD.encode(input.as_bytes())),
        Op::Base64Decode => base64::engine::general_purpose::STANDARD
            .decode(input.trim().as_bytes())
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .map_err(|e| e.to_string()),
        Op::HexEncode => Ok(hex::encode(input.as_bytes())),
        Op::HexDecode => hex::decode(input.trim())
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .map_err(|e| e.to_string()),
        Op::UrlEncode => Ok(urlencoding::encode(input).to_string()),
        Op::UrlDecode => urlencoding::decode(input)
            .map(|s| s.to_string())
            .map_err(|e| e.to_string()),
        Op::HtmlEncode => Ok(html_encode(input)),
        Op::HtmlDecode => Ok(html_decode(input)),
        Op::Md5 => {
            let mut h = md5::Md5::new();
            h.update(input.as_bytes());
            Ok(hex::encode(h.finalize()))
        }
        Op::Sha1 => {
            let mut h = sha1::Sha1::new();
            h.update(input.as_bytes());
            Ok(hex::encode(h.finalize()))
        }
        Op::Sha256 => {
            let mut h = sha2::Sha256::new();
            h.update(input.as_bytes());
            Ok(hex::encode(h.finalize()))
        }
        Op::Sha512 => {
            let mut h = sha2::Sha512::new();
            h.update(input.as_bytes());
            Ok(hex::encode(h.finalize()))
        }
        Op::Rot13 => Ok(rot13(input)),
        Op::Reverse => Ok(input.chars().rev().collect()),
    }
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn html_decode(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

/// Decode standard base64 (used by JWT header/payload decoding).
pub fn b64_decode_std(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| e.to_string())
}

/// Encode bytes as base64url (no padding) — used for JWT construction.
pub fn b64_encode_url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// HMAC-SHA256 — used for JWT HS256 re-sign attack.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    // RFC 2104: if key > block size (64), hash it first
    let block_size = 64usize;
    let key_block: Vec<u8> = {
        let k = if key.len() > block_size {
            let mut h = sha2::Sha256::new();
            h.update(key);
            h.finalize().to_vec()
        } else {
            key.to_vec()
        };
        let mut b = vec![0u8; block_size];
        b[..k.len()].copy_from_slice(&k);
        b
    };
    let i_pad: Vec<u8> = key_block.iter().map(|b| b ^ 0x36).collect();
    let o_pad: Vec<u8> = key_block.iter().map(|b| b ^ 0x5c).collect();
    // inner = SHA256(ipad || msg)
    let inner = {
        let mut h = sha2::Sha256::new();
        h.update(&i_pad);
        h.update(msg);
        h.finalize().to_vec()
    };
    // outer = SHA256(opad || inner)
    let mut h = sha2::Sha256::new();
    h.update(&o_pad);
    h.update(&inner);
    h.finalize().to_vec()
}
