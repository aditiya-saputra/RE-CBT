//! Pekerjaan token agent: ganti antar-muka `urlgetagent` klien lama.
//!
//! Klien lama (temuan #23) memanggil endpoint generator token **2× per
//! launch**, memakai passphrase hardcoded, lalu menyuntik token sebagai UA
//! via `argv[1]`. RE-CBT: endpoint dari config ditandatangani, dipanggil
//! tepat satu kali, ekstraksi token fleksibel (JSON `token`/`user_agent`/
//! `data.token` atau teks polos), dan token dipakai sebagai User-Agent
//! untuk request TLS selanjutnya.

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("jaringan: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("endpoint mengembalikan HTTP {status}")]
    BadStatus { status: u16 },
    #[error("respons tidak memuat token (JSON keys: {keys})")]
    TokenMissing { keys: String },
    #[error("respons bukan teks/JSON token")]
    Unreadable,
}

/// GET `getagent_url` (+ header config) → token agent (string).
/// Tanpa penyimpanan disk.
pub async fn fetch(
    client: &reqwest::Client,
    url: &reqwest::Url,
    headers: &std::collections::HashMap<String, String>,
) -> Result<String, AgentError> {
    let mut req = client.get(url.clone());
    for (name, value) in headers {
        req = req.header(name, value);
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    if !(200..=299).contains(&status) {
        return Err(AgentError::BadStatus { status });
    }
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_lowercase();

    if ct.contains("json") {
        let value: Value = resp.json().await?;
        return extract_from_json(&value);
    }
    let text = resp.text().await?;
    let trimmed = text.trim().to_string();
    if trimmed.is_empty() || trimmed.len() > 512 {
        return Err(AgentError::Unreadable);
    }
    // Beberapa endpoint mengembalikan token langsung sebagai teks polos;
    // bila sebetulnya JSON tanpa header, coba ekstraksi JSON juga.
    if trimmed.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<Value>(&trimmed) {
            if let Ok(t) = extract_from_json(&value) {
                return Ok(t);
            }
        }
    }
    Ok(trimmed)
}

fn extract_from_json(value: &Value) -> Result<String, AgentError> {
    let keys = match value.as_object() {
        Some(map) => map.keys().cloned().collect::<Vec<_>>().join(","),
        None => String::new(),
    };
    let candidates = [
        value.get("token"),
        value.get("user_agent"),
        value.get("userAgent"),
        value.get("ua"),
        value.get("data").and_then(|d| d.get("token")),
        value.get("data").and_then(|d| d.get("user_agent")),
        value.get("payload").and_then(|d| d.get("token")),
        value.get("payload").and_then(|d| d.get("user_agent")),
        value.get("payload").and_then(|d| d.get("userAgent")),
    ];
    for c in candidates.into_iter().flatten() {
        if let Some(s) = c.as_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() && trimmed.len() <= 512 {
                return Ok(trimmed.to_string());
            }
        }
    }
    Err(AgentError::TokenMissing { keys })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_token_field() {
        let v: Value = serde_json::json!({"status": true, "token": "abc123-x"});
        assert_eq!(extract_from_json(&v).unwrap(), "abc123-x");
    }

    #[test]
    fn extracts_user_agent_alias() {
        let v: Value = serde_json::json!({"ok": 1, "user_agent": " ua-9 "});
        assert_eq!(extract_from_json(&v).unwrap(), "ua-9");
    }

    #[test]
    fn extracts_nested_data_token() {
        let v: Value = serde_json::json!({"data": {"token": "tok-77"}});
        assert_eq!(extract_from_json(&v).unwrap(), "tok-77");
    }

    #[test]
    fn reports_missing_with_keys() {
        let v: Value = serde_json::json!({"hello": 1});
        let err = extract_from_json(&v).unwrap_err();
        assert!(matches!(err, AgentError::TokenMissing { ref keys } if keys == "hello"));
    }

    #[test]
    fn rejects_empty_token_string() {
        let v: Value = serde_json::json!({"token": "   "});
        assert!(matches!(
            extract_from_json(&v),
            Err(AgentError::TokenMissing { .. })
        ));
    }
}
