//! Polling pengawas: pesan + status kick.
//!
//! Perbaikan vs `main.js`:
//! - interval minimal 5 detik & backoff (temuan #5: `setInterval(fn, 1)`
//!   menghujani backend + CPU spin), bukan `setInterval` baku Node.
//! - HTTP pakai reqwest + rustls; `NODE_TLS_REJECT_UNAUTHORIZED = 0`
//!   dihapus total (temuan #4).
//! - `status == "2"` vs angka disatukan (temuan #1-type).
//! - file JSON temporer (`username.json`, `pesan.json`, `kick.json`)
//!   diganti event langsung ke HUD (logger FS pola lama identik).

use std::{sync::Arc, time::Duration};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use tauri::AppHandle;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    config::Config,
    hud::{self, HudEvent},
};

/// Interval polling minimum, dijaga juga di `config::validate_and_adjust`.
pub const MIN_POLL_MILLIS: u64 = 5_000;
const MAX_BACKOFF_MILLIS: u64 = 60_000;

#[derive(Debug, Error)]
pub enum PollError {
    #[error("{0}")]
    Transport(#[from] reqwest::Error),
}

/// Mulai dua loop polling: pesan pengawas + status kick.
pub fn start(app: AppHandle, cfg: Arc<Config>, http: reqwest::Client) {
    let kicked = Arc::new(Mutex::new(false));
    tauri::async_runtime::spawn(message_loop(app.clone(), cfg.clone(), http.clone()));
    tauri::async_runtime::spawn(status_loop(app, cfg, http, kicked));
}

fn base_interval(cfg_ms: u64) -> u64 {
    cfg_ms.max(MIN_POLL_MILLIS)
}

#[derive(Deserialize)]
struct MessageResp {
    #[serde(default)]
    created: String,
    #[serde(default)]
    pesan: String,
}

#[derive(Deserialize)]
struct StatusResp {
    #[serde(default)]
    status: Value,
    #[serde(default)]
    updated: String,
    #[serde(default)]
    keterangan: String,
}

/// Semantik klien lama: `status == "2"` → kick. Ditambah versi angka
/// supaya tidak terulang bug komparasi tipe (temuan #1).
fn is_kick(v: &Value) -> bool {
    match v {
        Value::String(s) => s == "2",
        Value::Number(n) => n.as_i64() == Some(2),
        _ => false,
    }
}

async fn fetch_json<T: DeserializeOwned>(
    http: &reqwest::Client,
    url: reqwest::Url,
) -> Result<T, PollError> {
    let resp = http.get(url).send().await?;
    let resp = resp.error_for_status()?;
    Ok(resp.json::<T>().await?)
}

async fn message_loop(app: AppHandle, cfg: Arc<Config>, http: reqwest::Client) {
    let base = base_interval(cfg.message_interval_ms);
    let mut backoff: u64 = 1;
    let mut last_created = String::new();
    loop {
        let delay = Duration::from_millis(base.saturating_mul(backoff).min(MAX_BACKOFF_MILLIS));
        tokio::time::sleep(delay).await;
        match cfg.expand_endpoint(&cfg.message_endpoint) {
            None => return, // konfigurasi rusak setelah startup; berhenti diam
            Some(url) => match fetch_json::<MessageResp>(&http, url).await {
                Ok(m) if m.created.is_empty() => backoff = 1,
                Ok(m) => {
                    backoff = 1;
                    if m.created != last_created {
                        last_created = m.created.clone();
                        hud::emit(
                            &app,
                            HudEvent::Message {
                                message: m.pesan,
                                created: m.created,
                            },
                        );
                    }
                }
                Err(e) => {
                    eprintln!("RE-CBT: gagal polling pesan: {e}");
                    backoff = (backoff * 2).min(1024);
                }
            },
        }
    }
}

async fn status_loop(
    app: AppHandle,
    cfg: Arc<Config>,
    http: reqwest::Client,
    kicked: Arc<Mutex<bool>>,
) {
    let base = base_interval(cfg.status_interval_ms);
    let mut backoff: u64 = 1;
    loop {
        let delay = Duration::from_millis(base.saturating_mul(backoff).min(MAX_BACKOFF_MILLIS));
        tokio::time::sleep(delay).await;
        match cfg.expand_endpoint(&cfg.status_endpoint) {
            None => return,
            Some(url) => match fetch_json::<StatusResp>(&http, url).await {
                Ok(s) => {
                    backoff = 1;
                    // Dedupe kick ditangani guard `kicked` (sekali picu, loop selesai);
                    // `updated` kosong tetap diabaikan (tanggal periset lama).
                    if !is_kick(&s.status) || s.updated.is_empty() {
                        continue;
                    }
                    let mut guard = kicked.lock().await;
                    if *guard {
                        continue; // sudah pernah dipicu; hindari dialog ganda
                    }
                    *guard = true;
                    drop(guard);
                    // Klien lama dialog lalu `app.quit()` atau timeout 15 dtk.
                    hud::emit(
                        &app,
                        HudEvent::Kick {
                            reason: s.keterangan.clone(),
                            grace_secs: cfg.kick_grace_ms / 1_000,
                        },
                    );
                    tokio::time::sleep(Duration::from_millis(cfg.kick_grace_ms)).await;
                    app.exit(2);
                    return;
                }
                Err(e) => {
                    eprintln!("RE-CBT: gagal polling status: {e}");
                    backoff = (backoff * 2).min(1024);
                }
            },
        }
    }
}
