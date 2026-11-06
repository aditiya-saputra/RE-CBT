//! HUD: panel status kecil yang selalu di atas — pengganti `main.js` pattern
//! dialog modal ("Pesan Pengawas" / "Pesan Peringatan").
//! Semua komunikasi backend -> HUD lewat event `cbt:hud-event`.

use serde::Serialize;
use tauri::{AppHandle, Emitter};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum HudEvent {
    /// Preflight sedang dicek (alur beranda).
    Connecting { url: String },
    /// Preflight gagal, akan dicoba ulang.
    Retry { reason: String, next_in_secs: u64 },
    /// Jendela ujian sudah terbuka.
    Connected,
    /// Pesan pengawas baru.
    Message { message: String, created: String },
    /// Pengawas mengeluarkan (kick) peserta; hitung mundur sebelum exit.
    Kick { reason: String, grace_secs: u64 },
    /// Kesalahan fatal yang tidak bisa dipulihkan.
    Fatal { message: String },
    /// Chord unlock lengkap — minta password operator di HUD.
    UnlockPrompt { keys: String },
    /// Password unlock salah (HUD menampilkan peringatan).
    UnlockFailed { attempt: u32 },
    /// Password benar — akan exit bersih.
    Unlocked,
}

pub fn emit(app: &AppHandle, ev: HudEvent) {
    if let Err(e) = app.emit("cbt:hud-event", ev) {
        eprintln!("RE-CBT: gagal mengirim event HUD: {e}");
    }
}
