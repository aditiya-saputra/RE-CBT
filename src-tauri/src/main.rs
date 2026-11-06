#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! RE-CBT — klien ujian CBT aman (Rust + Tauri 2).
//!
//! Pengganti direct dari klien exambrowser Electron yang dibongkar di
//! `teardown-CBT`: semua mode "klient bermasalah" pada tautan dianalisis
//! dipindahkan ke sisi Rust, renderer tidak punya lingkungan Node,
//! TLS terverifikasi selalu aktif, dan konfigurasi ditandatangani Ed25519.

mod config;
mod hud;
mod poll;
mod preflight;

use std::{path::PathBuf, process, sync::Arc, time::Duration};

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

use config::Config;
use hud::HudEvent;

const DEFAULT_CONFIG_PATH: &str = "config/re-cbt.json";

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    http: reqwest::Client,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("genkey") => {
            if let Err(e) = run_genkey(&args) {
                eprintln!("RE-CBT genkey gagal: {e}");
                process::exit(1);
            }
            return;
        }
        Some("sign") => {
            if let Err(e) = run_sign(&args) {
                eprintln!("RE-CBT sign gagal: {e}");
                process::exit(1);
            }
            return;
        }
        Some("help" | "-h" | "--help") => {
            print_help();
            return;
        }
        _ => {}
    }

    let cfg_path = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    let cfg = match config::load_verified(&cfg_path) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("RE-CBT: konfigurasi ditolak ({}): {e}", cfg_path.display());
            process::exit(1);
        }
    };
    run_app(cfg);
}

fn run_app(cfg: Arc<Config>) {
    let http = match reqwest::Client::builder()
        .user_agent(cfg.user_agent.as_str())
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("RE-CBT: init HTTP gagal: {e}");
            process::exit(1);
        }
    };

    tauri::Builder::default()
        .manage(AppState {
            cfg: cfg.clone(),
            http,
        })
        .setup(move |app| {
            let handle = app.handle().clone();
            if let Err(e) = create_hud(&handle) {
                eprintln!("RE-CBT: HUD gagal dibuat: {e}");
            }
            tauri::async_runtime::spawn(prepare(handle, cfg));
            Ok(())
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("RE-CBT berhenti: {e}");
            process::exit(1);
        });
}

/// Alur beranda: preflight -> jendela ujian -> polling pengawas.
/// Gagal preflight dijadwalkan ulang (backoff 3 -> 30 dtk), pengganti
/// handler 500 mati + halaman `404.html` klien lama.
async fn prepare(handle: tauri::AppHandle, cfg: Arc<Config>) {
    let http = handle.state::<AppState>().http.clone();
    hud::emit(
        &handle,
        HudEvent::Connecting {
            url: cfg.exam_url.to_string(),
        },
    );

    let mut delay = Duration::from_secs(3);
    loop {
        match preflight::check(&http, &cfg.exam_url).await {
            Ok(report) => {
                let _ = report;
                if let Err(e) = open_exam(&handle, &cfg) {
                    hud::emit(
                        &handle,
                        HudEvent::Fatal {
                            message: format!("Gagal membuka jendela ujian: {e}"),
                        },
                    );
                    return;
                }
                hud::emit(&handle, HudEvent::Connected);
                poll::start(handle, cfg, http);
                return;
            }
            Err(err) => {
                hud::emit(
                    &handle,
                    HudEvent::Retry {
                        reason: err.to_string(),
                        next_in_secs: delay.as_secs(),
                    },
                );
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(30));
            }
        }
    }
}

/// Jendela utama: langsung memuat `exam_url`.
/// - `content_protected(true)` ≡ `setContentProtection(true)` klien lama.
/// - `incognito(true)`: tidak ada cache/riwayat yang bocor ke disk
///   (pengganting `session.clearCache()` post-`loadURL` yang race, temuan #12).
///   Tidak ada `nodeIntegration` (temuan #3) — renderer hanya peran webview biasa.
fn open_exam(handle: &tauri::AppHandle, cfg: &Config) -> tauri::Result<()> {
    WebviewWindowBuilder::new(handle, "exam", WebviewUrl::External(cfg.exam_url.clone()))
        .title("RE-CBT — Ujian")
        .fullscreen(cfg.fullscreen)
        .decorations(!cfg.fullscreen)
        .resizable(false)
        .content_protected(true)
        .user_agent(cfg.user_agent.as_str())
        .incognito(true)
        .build()?;
    Ok(())
}

/// HUD kecil pojok kanan-bawah (selalu di atas, tumpang tindih aman dengan
/// jendela ujian fullscreen).
fn create_hud(handle: &tauri::AppHandle) -> tauri::Result<()> {
    let mut builder = WebviewWindowBuilder::new(handle, "hud", WebviewUrl::App("hud.html".into()))
        .title("RE-CBT — pengawas")
        .decorations(false)
        .resizable(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .content_protected(true)
        .inner_size(380.0, 240.0);
    if let Ok(Some(monitor)) = handle.primary_monitor() {
        let scale = monitor.scale_factor();
        let size = monitor.size();
        let lw = size.width as f64 / scale;
        let lh = size.height as f64 / scale;
        builder = builder.position((lw - 388.0).max(0.0), (lh - 248.0).max(0.0));
    }
    builder.build()?;
    Ok(())
}

fn flag_value(flag: &str, args: &[String]) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn run_genkey(args: &[String]) -> Result<(), config::ConfigError> {
    let dir = flag_value("--out-dir", args)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config"));
    config::genkey(&dir)?;
    println!("kunci privat : {}", dir.join("ed25519.priv").display());
    println!("kunci publik : {}", dir.join("ed25519.pub").display());
    println!("LINDUNGI ed25519.priv — file itu mampu menandatangani konfigurasi mana pun.");
    Ok(())
}

fn run_sign(args: &[String]) -> Result<(), config::ConfigError> {
    let usage = "pakai: re-cbt sign <payload.json> --key <ed25519.priv> [--out <out.json>]";
    let payload_path = match args.get(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("{usage}");
            process::exit(2);
        }
    };
    let key_path = match flag_value("--key", args) {
        Some(k) => PathBuf::from(k),
        None => {
            eprintln!("{usage}");
            process::exit(2);
        }
    };
    let out_path = flag_value("--out", args)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    config::sign(&payload_path, &key_path, &out_path)?;
    println!("ditandatangani -> {}", out_path.display());
    Ok(())
}

fn print_help() {
    println!("RE-CBT — klien ujian CBT aman (Rust + Tauri)");
    println!();
    println!("Pemakaian:");
    println!("  re-cbt [path-konfigurasi.json]");
    println!("      jalankan klien (default: {DEFAULT_CONFIG_PATH})");
    println!("  re-cbt genkey [--out-dir <dir>]");
    println!("      buat pasangan kunci Ed25519 (ed25519.priv / ed25519.pub, hex)");
    println!("  re-cbt sign <payload.json> --key <ed25519.priv> [--out <out.json>]");
    println!("      validasi + tandatangani konfigurasi jadi kuncup siap pakai");
    println!("  re-cbt help");
    println!("      tampilkan bantuan ini");
}
