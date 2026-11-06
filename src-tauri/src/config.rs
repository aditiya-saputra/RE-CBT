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

fn d_semi_subnet_prefix() -> u8 {
    24
}

/// Mode ujian, setara `ModeUjian` klien lama (temuan paritas semi/online
/// di REVERSE_ENGINEERING.md) — tanpa mewarisi URL/kunci rahasianya.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Daring: internet penuh, setara `ModeUjian=2` klien lama (tanpa
    /// pre-check jaringan tambahan; tetap preflight TLS ke `exam_url`).
    #[default]
    Online,
    /// Semi-daring: LAN terisolasi, setara `ModeUjian=1` — mesin wajib satu
    /// subnet dengan host ujian dan internet **tidak boleh** terdeteksi.
    Semi,
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
    /// Mode ujian: `online` (default) atau `semi` (LAN terisolasi).
    #[serde(default)]
    pub mode: Mode,
    /// Hanya `mode=semi`: URL HTTPS untuk probe kehadiran internet. Probe
    /// **berhasil** = internet hidup = konfigurasi ditolak. Wajib diset
    /// eksplisit — tidak ada URL deteksi yang di-hardcode di binary.
    #[serde(default)]
    pub offline_probe_url: Option<reqwest::Url>,
    /// Hanya `mode=semi`: panjang prefix subnet `exam_url` yang dipakai
    /// memverifikasi mesin berada di LAN ujian (default 24, maks 32).
    #[serde(default = "d_semi_subnet_prefix")]
    pub semi_subnet_prefix: u8,
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
    TemplateMissing {
        field: &'static str,
        token: &'static str,
    },
    #[error("prefix subnet tidak valid: {value} (harus <= 32)")]
    InvalidSubnetPrefix { value: u8 },
    #[error("mode semi: field '{field}' harus host IPv4 literal (LAN tanpa DNS), dapat '{host}'")]
    NotIpv4 { field: &'static str, host: String },
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

        if self.semi_subnet_prefix > 32 {
            return Err(ConfigError::InvalidSubnetPrefix {
                value: self.semi_subnet_prefix,
            });
        }
        if self.mode == Mode::Semi {
            // LAN terisolasi sering tanpa DNS: host uji + API pengawas harus
            // IPv4 literal (paritas `https://192.168.x.x` klien lama).
            for (field, url) in [
                ("exam_url", &self.exam_url),
                ("supervisor_api_base", &self.supervisor_api_base),
            ] {
                let host = url.host_str().unwrap_or_default();
                let parsed = host.parse::<std::net::Ipv4Addr>();
                if parsed.is_err() {
                    return Err(ConfigError::NotIpv4 {
                        field,
                        host: host.to_string(),
                    });
                }
            }
            match &self.offline_probe_url {
                None => return Err(ConfigError::Empty("offline_probe_url")),
                Some(url) => check_https("offline_probe_url", url)?,
            }
        }

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
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        ConfigError::Crypto(format!(
            "kunci publik harus 32 byte, dapat {} byte",
            v.len()
        ))
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| ConfigError::Crypto(format!("kunci publik: {e}")))
}

fn load_signing_key(path: &Path) -> Result<SigningKey, ConfigError> {
    let hex_str = fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        ConfigError::Crypto(format!(
            "kunci privat harus 32 byte, dapat {} byte",
            v.len()
        ))
    })?;
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
    vk.verify_strict(&payload, &sig)
        .map_err(|_| ConfigError::SignatureInvalid)?;

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
    fs::write(
        out_dir.join("ed25519.pub"),
        hex::encode(sk.verifying_key().to_bytes()),
    )?;
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
        cfg.validate_and_adjust()
            .expect("contoh config harus valid");
    }

    #[test]
    fn rejects_http() {
        let mut cfg = sample_config();
        cfg.exam_url = reqwest::Url::parse("http://cbt.sekolah-saya.sch.id/ujian").unwrap();
        let err = cfg.validate_and_adjust().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::SchemeNotHttps {
                field: "exam_url",
                ..
            }
        ));
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

    const SEMI_SAMPLE: &str = r#"{
        "mode": "semi",
        "exam_url": "https://192.168.10.10/unbk",
        "supervisor_api_base": "https://192.168.10.10/",
        "offline_probe_url": "https://cek-konektivitas.example/check",
        "message_endpoint": "api/task-get-pesan/{username}/{activity}",
        "status_endpoint": "api/task-get-status-peserta/{username}/{activity}",
        "user_agent": "RE-CBT (sekolah-saya)",
        "activity": "Ujian-Matematika-01",
        "participant_username": "peserta01",
        "semi_subnet_prefix": 24
    }"#;

    fn semi_config() -> Config {
        serde_json::from_str(SEMI_SAMPLE).unwrap()
    }

    #[test]
    fn mode_defaults_online_when_absent() {
        let cfg = sample_config();
        assert_eq!(cfg.mode, Mode::Online);
    }

    #[test]
    fn mode_semi_valid() {
        let mut cfg = semi_config();
        assert_eq!(cfg.mode, Mode::Semi);
        assert!(cfg.validate_and_adjust().is_ok());
    }

    #[test]
    fn mode_rejects_unknown_variant() {
        assert!(serde_json::from_str::<Mode>("\"wifi\"").is_err());
        assert!(serde_json::from_str::<Mode>("1").is_err());
    }

    #[test]
    fn semi_requires_ipv4_exam_host() {
        let mut cfg = semi_config();
        cfg.exam_url = reqwest::Url::parse("https://cbt.sekolah-saya.sch.id/unbk").unwrap();
        assert!(matches!(
            cfg.validate_and_adjust(),
            Err(ConfigError::NotIpv4 {
                field: "exam_url",
                ..
            })
        ));
    }

    #[test]
    fn semi_requires_ipv4_supervisor_host() {
        let mut cfg = semi_config();
        cfg.supervisor_api_base =
            reqwest::Url::parse("https://api-lan.sekolah-saya.sch.id/").unwrap();
        assert!(matches!(
            cfg.validate_and_adjust(),
            Err(ConfigError::NotIpv4 {
                field: "supervisor_api_base",
                ..
            })
        ));
    }

    #[test]
    fn semi_requires_probe_url() {
        let mut cfg = semi_config();
        cfg.offline_probe_url = None;
        assert!(matches!(
            cfg.validate_and_adjust(),
            Err(ConfigError::Empty("offline_probe_url"))
        ));
    }

    #[test]
    fn semi_probe_must_be_https() {
        let mut cfg = semi_config();
        cfg.offline_probe_url =
            Some(reqwest::Url::parse("http://cek-konektivitas.example/check").unwrap());
        assert!(matches!(
            cfg.validate_and_adjust(),
            Err(ConfigError::SchemeNotHttps {
                field: "offline_probe_url",
                ..
            })
        ));
    }

    #[test]
    fn semi_prefix_beyond_32_rejected() {
        let mut cfg = semi_config();
        cfg.semi_subnet_prefix = 48;
        assert!(matches!(
            cfg.validate_and_adjust(),
            Err(ConfigError::InvalidSubnetPrefix { value: 48 })
        ));
    }
}
