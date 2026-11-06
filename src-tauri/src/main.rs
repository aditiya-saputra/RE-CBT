#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! RE-CBT — klien ujian CBT aman (Rust + Tauri 2).
//!
//! Pengganti direct dari klien exambrowser Electron yang dibongkar di
//! `teardown-CBT`: semua mode "klient bermasalah" pada tautan dianalisis
//! dipindahkan ke sisi Rust, renderer tidak punya lingkungan Node,
//! TLS terverifikasi selalu aktif, dan konfigurasi ditandatangani Ed25519.

mod agent;
mod config;
mod hud;
mod kiosk;
mod poll;
mod preflight;
mod semi;

use std::{path::PathBuf, process, sync::Arc, time::Duration};

use tauri::{Manager, State, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::Mutex;

use config::{Config, Mode};
use hud::HudEvent;

const DEFAULT_CONFIG_PATH: &str = "config/re-cbt.json";

/// Guard percobaan buka-kunci: rate-limit password salah (anti-hammer UI).
struct UnlockGuard {
    wrong: u32,
    locked_until: Option<std::time::Instant>,
}
const UNLOCK_MAX_WRONG: u32 = 5;
const UNLOCK_LOCKOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct AppState {
    http: reqwest::Client,
    cfg: Arc<Config>,
    chord: Arc<Mutex<kiosk::Chord>>,
    unlock: Arc<Mutex<UnlockGuard>>,
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

fn build_http(ua: &str) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(ua)
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(10))
        .build()
}

fn run_app(cfg: Arc<Config>) {
    let http = match build_http(&cfg.user_agent) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("RE-CBT: init HTTP gagal: {e}");
            process::exit(1);
        }
    };

    tauri::Builder::default()
        .manage(AppState {
            http,
            cfg: cfg.clone(),
            chord: Arc::new(Mutex::new(kiosk::Chord::new(cfg.unlock_keys.clone()))),
            unlock: Arc::new(Mutex::new(UnlockGuard {
                wrong: 0,
                locked_until: None,
            })),
        })
        .invoke_handler(tauri::generate_handler![kiosk_key, unlock_check])
        .on_window_event(|window, event| {
            // Kioska: jangan biarkan Alt+F4/✕ menutup window ujian & HUD.
            // Satu pintu keluar: unlock (chord+password), kick pengawas,
            // atau paksa dari OS oleh admin.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if matches!(window.label(), "exam" | "hud") {
                    api.prevent_close();
                    eprintln!("RE-CBT: penutupan '{}' ditolak (kiosk)", window.label());
                }
            }
        })
        .setup(move |app| {
            let handle = app.handle().clone();
            if let Err(e) = create_hud(&handle) {
                eprintln!("RE-CBT: HUD gagal dibuat: {e}");
            }
            tauri::async_runtime::spawn(prepare(handle.clone(), cfg.clone()));
            Ok(())
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("RE-CBT berhenti: {e}");
            process::exit(1);
        });
}

/// Command dari init-script webview ujian: satu token tombol canonical.
/// Melengkapi chord → HUD minta password. Tidak pernah memblokir ipc.
#[tauri::command]
async fn kiosk_key(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    key: String,
) -> Result<(), String> {
    #[cfg(debug_assertions)]
    eprintln!("RE-CBT: kiosk_key '{key}'");
    let now = std::time::Instant::now();
    let mut chord = state.chord.lock().await;
    let before = chord.progress();
    let result = chord.feed(&key, now);
    let after = chord.progress();
    if before != after && before == 0 && after == 1 {
        // kunci pertama ok — sebaris riak kecil diagnostik
        eprintln!(
            "RE-CBT: chord {} ({}/{})",
            state.cfg.unlock_keys.join("+"),
            after,
            state.cfg.unlock_keys.len()
        );
    }
    if result == kiosk::ChordResult::Complete {
        drop(chord);
        hud::emit(
            &app,
            HudEvent::UnlockPrompt {
                keys: state.cfg.unlock_keys.join(" + "),
            },
        );
        eprintln!("RE-CBT: chord unlock lolos — meminta password operator");
    }
    Ok(())
}

/// Command dari HUD: verifikasi password buka-kunci di Rust.
/// Benar = Unlocked → exit(0) bersih. Salah = rate-limit + HUD warning.
#[tauri::command]
async fn unlock_check(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> Result<bool, String> {
    let mut guard = state.unlock.lock().await;
    if let Some(locked_until) = guard.locked_until {
        let now = std::time::Instant::now();
        if now < locked_until {
            let wait = locked_until.duration_since(now).as_secs().max(1);
            hud::emit(
                &app,
                HudEvent::UnlockFailed {
                    attempt: guard.wrong,
                },
            );
            eprintln!("RE-CBT: percobaan buka-kunci terkunci {wait} dtk lagi");
            return Ok(false);
        }
        guard.locked_until = None;
    }
    if password == state.cfg.unlock_password {
        hud::emit(&app, HudEvent::Unlocked);
        eprintln!("RE-CBT: buka-kunci sukses — exit bersih");
        drop(guard);
        graceful_exit(&app).await;
        return Ok(true);
    }
    guard.wrong += 1;
    if guard.wrong >= UNLOCK_MAX_WRONG {
        guard.locked_until = Some(std::time::Instant::now() + UNLOCK_LOCKOUT);
        guard.wrong = 0;
    }
    hud::emit(
        &app,
        HudEvent::UnlockFailed {
            attempt: guard.wrong,
        },
    );
    eprintln!("RE-CBT: password buka-kunci salah");
    Ok(false)
}

async fn graceful_exit(app: &tauri::AppHandle) {
    // beri waktu HUD menampilkan kartu "Terbuka"
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    app.exit(0);
}

/// Alur beranda: preflight -> jendela ujian -> polling pengawas.
/// Gagal preflight dijadwalkan ulang (backoff 3 -> 30 dtk), pengganti
/// handler 500 mati + halaman `404.html` klien lama.
///
/// Mode `semi` menjalankan precheck tambahan dulu (subnet + ketiadaan
/// internet); pelanggarannya fatal dan eksplisit: HUD Fatal → jeda
/// `kick_grace_ms` → exit(1) — paritas "ditolak lalu keluar" klien lama,
/// bukan retry selamanya di lingkungan yang salah.
async fn prepare(handle: tauri::AppHandle, cfg: Arc<Config>) {
    let state = handle.state::<AppState>().inner().clone();
    let mut http = state.http.clone();
    let mut effective_ua = cfg.user_agent.clone();
    let mut delay = Duration::from_secs(3);

    hud::emit(
        &handle,
        HudEvent::Connecting {
            url: cfg.exam_url.to_string(),
        },
    );

    // Fasa 1 — token agent (bila endpoint diset): satu pemanggilan, retry
    // backoff saat gagal; token sukses jadi User-Agent efekti (paritas
    // `urlgetagent` → `argv[1]` klien lama, tanpa pemanggilan 2× / #23).
    if let Some(agent_url) = &cfg.getagent_url {
        loop {
            match agent::fetch(&http, agent_url, &cfg.getagent_headers).await {
                Ok(token) => {
                    effective_ua = token.clone();
                    match build_http(&token) {
                        Ok(c) => http = c.clone(),
                        Err(e) => {
                            eprintln!("RE-CBT: rebuild client pasca-token gagal: {e}");
                        }
                    }
                    eprintln!(
                        "RE-CBT: token agent diperoleh ({} char) dari {}; dipakai sbg User-Agent",
                        token.len(),
                        agent_url
                    );
                    break;
                }
                Err(err) => {
                    eprintln!("RE-CBT: gagal ambil token agent: {err}");
                    hud::emit(
                        &handle,
                        HudEvent::Retry {
                            reason: format!("token agent: {err}"),
                            next_in_secs: delay.as_secs(),
                        },
                    );
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2).min(Duration::from_secs(30));
                }
            }
        }
    }

    // Fasa 2 — mode semi: subnet + ketiadaan internet (fatal, eksplisit).
    if cfg.mode == Mode::Semi {
        if let Err(err) = semi::precheck(&http, &cfg).await {
            let message = format!("Ditolak (mode semi): {err}");
            eprintln!("RE-CBT: {message}");
            hud::emit(
                &handle,
                HudEvent::Fatal {
                    message: message.clone(),
                },
            );
            tokio::time::sleep(Duration::from_millis(cfg.kick_grace_ms)).await;
            handle.exit(1);
            return;
        }
        eprintln!("RE-CBT: mode semi lolos precheck (subnet cocok, internet tidak ada)");
    }

    // Fasa 3 — preflight halaman ujian + buka kioska + polling.
    loop {
        match preflight::check(&http, &cfg.exam_url).await {
            Ok(report) => {
                eprintln!(
                    "RE-CBT: halaman ujian siap (HTTP {}) via TLS tervalidasi: {}",
                    report.status, report.final_url
                );
                if let Err(e) = open_exam(&handle, &cfg, &effective_ua) {
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
                eprintln!("RE-CBT: preflight gagal: {err}");
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
fn open_exam(handle: &tauri::AppHandle, cfg: &Config, effective_ua: &str) -> tauri::Result<()> {
    WebviewWindowBuilder::new(handle, "exam", WebviewUrl::External(cfg.exam_url.clone()))
        .title("RE-CBT — Ujian")
        .fullscreen(cfg.fullscreen)
        .decorations(!cfg.fullscreen)
        .resizable(false)
        .content_protected(true)
        .user_agent(effective_ua)
        .incognito(true)
        .initialization_script(kiosk::exam_init_script())
        .build()?;
    Ok(())
}

/// HUD kecil pojok kanan-bawah (selalu di atas, tumpang tindih aman dengan
/// jendela ujian fullscreen).
fn create_hud(handle: &tauri::AppHandle) -> tauri::Result<()> {
    let hud_page = if cfg!(debug_assertions) && std::env::var("RE_CBT_NO_SELFTEST").is_err() {
        // Selftest kiosk di build debug: hud memicu chord sendiri beberapa
        // detik setelah muat (lihat hud.js) — memvalidasi rantai incognito.
        // Benang penuh dapat dimatikan dengan env RE_CBT_NO_SELFTEST=1.
        "hud.html?kiosk-selftest=1"
    } else {
        "hud.html"
    };
    let mut builder = WebviewWindowBuilder::new(handle, "hud", WebviewUrl::App(hud_page.into()))
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
