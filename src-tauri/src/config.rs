//! Konfigurasi RE-CBT.
//!
//! Perbaikan utama vs klien lama (`setting_exambro.json` AES-256-CBC dengan
//! kunci + IV hardcoded di `main.js`, temuan teardown-CBT `#4`-related):
//! konfigurasi berupa JSON **dengan tanda tangan Ed25519**, kunci publik
//! disimpan terpisah di `ed25519.pub`, kunci privat tidak pernah ada di klien.
//!
//! Struktur file konfigurasi (`config/re-cbt.json`):
//!
//! ```json
//! {
//!   "payload_b64": "<base64 dari JSON Config (kanonik)>",
//!   "signature_hex": "<hex 64 byte Ed25519>"
//! }
//! ```

use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Interval polling minimum (ms). Klien lama bisa jatuh ke
/// `setInterval(fn, 1)` dan menghujani server (temuan #5); RE-CBT memaksa
/// hiatus minimum ini.
pub const MIN_POLL_MILLIS: u64 = 5_000;

fn d_message_interval() -> u64 {
    300_000
}

fn d_status_interval() -> u64 {
    60_000
}

fn d_kick_grace() -> u64 {
    15_000
}

fn d_fullscreen() -> bool {
    true
}

/// Konfigurasi runtime RE-CBT, dibaca dari payload yang bertanda tangan valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// URL halaman/paket ujian untuk jendela utama. Wajib HTTPS.
    pub exam_url: reqwest::Url,
    /// Base URL API pengawas; `message_endpoint`/`status_endpoint` di-join ke sini.
    pub supervisor_api_base: reqwest::Url,
    /// Template endpoint pesan pengawas, memuat `{username}` dan `{activity}`,
    /// tanpa `/` awal (contoh: `api/task-get-pesan/{username}/{activity}`).
    pub message_endpoint: String,
    /// Template endpoint status peserta (kick), memuat `{username}` dan `{activity}`.
    pub status_endpoint: String,
    /// User-Agent yang dikirim semua request (pengganti injeksi `argv[1]`).
    pub user_agent: String,
    /// Kegiatan/ujian, dipakai di template endpoint.
    pub activity: String,
    /// Username peserta (identitas eksplisit, bukan scraping DOM).
    pub participant_username: String,
    /// Interval polling pesan pengawas (ms); di-clamp ke [MIN_POLL_MILLIS, ..).
    #[serde(default = "d_message_interval")]
    pub message_interval_ms: u64,
    /// Interval polling status peserta (ms); di-clamp ke [MIN_POLL_MILLIS, ..).
    #[serde(default = "d_status_interval")]
    pub status_interval_ms: u64,
    /// Grace period (ms) sebelum aplikasi keluar setelah perintah kick
    /// (default 15.000 ms, seperti `setTimeout 15000` klien lama).
    #[serde(default = "d_kick_grace")]
    pub kick_grace_ms: u64,
    /// Jendela ujian fullscreen kiosk.
    #[serde(default = "d_fullscreen")]
    pub fullscreen: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("format JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 tidak sah: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("hex tidak sah: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("kripto: {0}")]
    Crypto(String),
    #[error("tanda tangan Ed25519 TIDAK VALID - konfigurasi mungkin disusupi atau kunci berbeda")]
    SignatureInvalid,
    #[error("field '{field}' wajib HTTPS, dapat '{url}'")]
    SchemeNotHttps { field: &'static str, url: String },
    #[error("field '{0}' tidak boleh kosong")]
    Empty(&'static str),
    #[error("template '{field}' tidak memuat {token}")]
    TemplateMissing { field: &'static str, token: &'static str },
}

impl Config {
    /// Validasi penuh + penyelarasan aman (clamp) yang mencegah semua mode
    /// "hammering" (temuan #5). Panggil setelah deserialisasi, sebelum dipakai.
    pub fn validate_and_adjust(&mut self) -> Result<(), ConfigError> {
        let check_https = |field: &'static str, url: &reqwest::Url| -> Result<(), ConfigError> {
            if url.scheme() != "https" {
                return Err(ConfigError::SchemeNotHttps {
                    field,
                    url: url.to_string(),
                });
            }
            Ok(())
        };
        check_https("exam_url", &self.exam_url)?;
        check_https("supervisor_api_base", &self.supervisor_api_base)?;

        for (field, value) in [
            ("user_agent", &self.user_agent),
            ("activity", &self.activity),
            ("participant_username", &self.participant_username),
        ] {
            if value.trim().is_empty() {
                return Err(ConfigError::Empty(field));
            }
        }

        for (field, template) in [
            ("message_endpoint", &self.message_endpoint),
            ("status_endpoint", &self.status_endpoint),
        ] {
            if template.trim().is_empty() {
                return Err(ConfigError::Empty(field));
            }
            for token in ["{username}", "{activity}"] {
                if !template.contains(token) {
                    return Err(ConfigError::TemplateMissing { field, token });
                }
            }
        }

        for (field, value) in [
            ("message_interval_ms", &mut self.message_interval_ms),
            ("status_interval_ms", &mut self.status_interval_ms),
        ] {
            if *value < MIN_POLL_MILLIS {
                eprintln!(
                    "RE-CBT: {}={} < {} ms di-clamp ke minimum (anti-hammering)",
                    field, *value, MIN_POLL_MILLIS
                );
                *value = MIN_POLL_MILLIS;
            }
        }
        if self.kick_grace_ms < 1_000 {
            self.kick_grace_ms = 1_000;
        }
        Ok(())
    }

    /// Bentuk URL penuh dari sebuah template endpoint.
    pub fn expand_endpoint(&self, template: &str) -> Option<reqwest::Url> {
        let path = template
            .replace("{username}", &self.participant_username)
            .replace("{activity}", &self.activity);
        self.supervisor_api_base.join(&path).ok()
    }
}

#[derive(Debug, Deserialize)]
struct Envelope {
    payload_b64: String,
    signature_hex: String,
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey, ConfigError> {
    let hex_str = fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| ConfigError::Crypto(format!(
        "kunci publik harus 32 byte, dapat {} byte",
        v.len()
    )))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| ConfigError::Crypto(format!("kunci publik: {e}")))
}

fn load_signing_key(path: &Path) -> Result<SigningKey, ConfigError> {
    let hex_str = fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| ConfigError::Crypto(format!(
        "kunci privat harus 32 byte, dapat {} byte",
        v.len()
    )))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Muat konfigurasi bertanda tangan: verifikasi Ed25519 dulu (strict),
/// baru parse + validasi. Gagal tanda tangan = tuntas ditolak.
pub fn load_verified(config_path: &Path) -> Result<Config, ConfigError> {
    let env: Envelope = serde_json::from_str(&fs::read_to_string(config_path)?)?;

    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    let vk = load_verifying_key(&parent.join("ed25519.pub"))?;

    let payload = B64.decode(&env.payload_b64)?;
    let sig_bytes = hex::decode(&env.signature_hex)?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| ConfigError::Crypto(format!("signature: {e}")))?;
    vk.verify_strict(&payload, &sig).map_err(|_| ConfigError::SignatureInvalid)?;

    let mut cfg: Config = serde_json::from_slice(&payload)?;
    cfg.validate_and_adjust()?;
    Ok(cfg)
}

/// Buat pasangan kunci Ed25519 ke `<dir>/ed25519.priv` + `ed25519.pub` (hex).
pub fn genkey(out_dir: &Path) -> Result<(), ConfigError> {
    fs::create_dir_all(out_dir)?;
    let mut secret = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut secret);
    let sk = SigningKey::from_bytes(&secret);
    fs::write(out_dir.join("ed25519.priv"), hex::encode(sk.to_bytes()))?;
    fs::write(out_dir.join("ed25519.pub"), hex::encode(sk.verifying_key().to_bytes()))?;
    Ok(())
}

/// Validasi + tanda tangani payload konfigurasi menjadi recengkapan siap pakai.
pub fn sign(payload_path: &Path, key_path: &Path, out_path: &PathBuf) -> Result<(), ConfigError> {
    let sk = load_signing_key(key_path)?;
    let payload_bytes = fs::read(payload_path)?;

    // Gagal parse/validasi = tidak akan menghasilkan konfigurasi rusak.
    let mut cfg: Config = serde_json::from_slice(&payload_bytes)?;
    cfg.validate_and_adjust()?;
    let canonical = serde_json::to_vec_pretty(&cfg)?;

    let signature = sk.sign(&canonical);
    let env = serde_json::json!({
        "payload_b64": B64.encode(&canonical),
        "signature_hex": hex::encode(signature.to_bytes()),
    });
    fs::write(out_path, serde_json::to_vec_pretty(&env)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "exam_url": "https://cbt.sekolah-saya.sch.id/ujian",
        "supervisor_api_base": "https://cbt.sekolah-saya.sch.id/",
        "message_endpoint": "api/task-get-pesan/{username}/{activity}",
        "status_endpoint": "api/task-get-status-peserta/{username}/{activity}",
        "user_agent": "RE-CBT (sekolah-saya)",
        "activity": "Ujian-Matematika-01",
        "participant_username": "peserta01",
        "message_interval_ms": 300000,
        "status_interval_ms": 60000,
        "kick_grace_ms": 15000,
        "fullscreen": true
    }"#;

    fn sample_config() -> Config {
        serde_json::from_str(SAMPLE).unwrap()
    }

    #[test]
    fn sample_valid() {
        let mut cfg = sample_config();
        cfg.validate_and_adjust().expect("contoh config harus valid");
    }

    #[test]
    fn rejects_http() {
        let mut cfg = sample_config();
        cfg.exam_url = reqwest::Url::parse("http://cbt.sekolah-saya.sch.id/ujian").unwrap();
        let err = cfg.validate_and_adjust().unwrap_err();
        assert!(matches!(err, ConfigError::SchemeNotHttps { field: "exam_url", .. }));
    }

    #[test]
    fn clamps_hammering_intervals() {
        let mut cfg = sample_config();
        cfg.message_interval_ms = 1;
        cfg.status_interval_ms = 0;
        cfg.validate_and_adjust().unwrap();
        assert_eq!(cfg.message_interval_ms, MIN_POLL_MILLIS);
        assert_eq!(cfg.status_interval_ms, MIN_POLL_MILLIS);
    }

    #[test]
    fn template_must_have_tokens() {
        let mut cfg = sample_config();
        cfg.message_endpoint = "api/no-tokens".into();
        assert!(cfg.validate_and_adjust().is_err());
    }

    #[test]
    fn expand_endpoint_resolves() {
        let mut cfg = sample_config();
        cfg.validate_and_adjust().unwrap();
        let url = cfg.expand_endpoint(&cfg.message_endpoint).unwrap();
        assert_eq!(
            url.as_str(),
            "https://cbt.sekolah-saya.sch.id/api/task-get-pesan/peserta01/Ujian-Matematika-01"
        );
    }
}
