//! Sifat kiosk jendela ujian: pintu keluar otoritatif + blokir jalur kembali.
//!
//! Paritas klien lama:
//! - `unlockkeys` (LControlKey,C,B): chord berurutan meminta buka-kunci.
//!   Bedanya: konfigurasi dari file ditandatangani, perbandingan password
//!   terjadi di Rust, dan logika chord diuji unit — bukan `main.js`.
//! - Blokir context-menu/devtools/reload/print di renderer, pengganti
//!   harapan "webContents" yang race di `main.js`.

use std::time::Instant;

/// Jeda maksimum antar tombol chord (ms). Lebih lambat = chord rusak.
const CHORD_WINDOW_MILLIS: u128 = 1_500;

#[derive(Debug, PartialEq, Eq)]
pub enum ChordResult {
    /// Chord belum lengkap, terus memantau.
    InProgress,
    /// Chord lengkap — minta buka-kunci.
    Complete,
}

/// Mesin status chord berurutan: `control` lalu `c` lalu `b` (sesuai config)
/// dalam jendela waktu CHORD_WINDOW_MILLIS. Tombol salah kemana pun = reset,
/// kecuali tombol itu kebetulan kunci pertama → mulai ulang dari situ.
#[derive(Debug)]
pub struct Chord {
    keys: Vec<String>,
    progress: usize,
    last: Option<Instant>,
}

impl Chord {
    pub fn new(keys: Vec<String>) -> Self {
        let keys = keys
            .into_iter()
            .map(|k| k.trim().to_lowercase())
            .filter(|k| !k.is_empty())
            .collect();
        Self {
            keys,
            progress: 0,
            last: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Jumlah tombol yang sudah terantre benar (untuk diagnostik).
    pub fn progress(&self) -> usize {
        self.progress
    }

    /// Masukkan satu token canonical (dari init-script webview).
    pub fn feed(&mut self, key: &str, now: Instant) -> ChordResult {
        if !self.is_enabled() {
            return ChordResult::InProgress;
        }
        match self.last {
            Some(t) if now.duration_since(t).as_millis() > CHORD_WINDOW_MILLIS => {
                self.progress = 0;
            }
            _ => {}
        }

        let expected = self.keys.get(self.progress);
        let key_l = key.trim().to_lowercase();
        if expected.is_some_and(|e| *e == key_l) {
            self.progress += 1;
            self.last = Some(now);
            if self.progress == self.keys.len() {
                self.progress = 0; // chord selesai; mulai segar lagi
                return ChordResult::Complete;
            }
            return ChordResult::InProgress;
        }

        // Tombol salah: reset, tapi izinkan restart bila ini kunci pertama.
        if self.keys[0] == key_l && self.progress > 0 {
            self.progress = 1;
            self.last = Some(now);
        } else {
            self.progress = 0;
            self.last = Some(now);
        }
        ChordResult::InProgress
    }
}

/// Init-script yang disuntik all page (eksternal termasuk) di webview ujian:
/// 1) mencekal context menu + shortcut kembali (devtools/reload/print/save);
/// 2) memipakan token tombol canonical ke `kiosk_key` (command Rust) untuk
///    mesin chord — sisa hatch escape via Alt+F4 dicekal di sisi Rust
///    (`prevent_close`), bukan di halaman.
pub fn exam_init_script() -> &'static str {
    r#"
(() => {
  'use strict';
  const blockedPlain = new Set(['f12', 'f5', 'f11']);
  const blockedWithCtrl = new Set(['r', 'n', 'p', 's', 't', 'w', 'u']);
  const blockedWithCtrlShift = new Set(['i', 'j', 'c']);

  const canon = (e) => {
    const c = e.code || '';
    switch (c) {
      case 'ControlLeft':
      case 'ControlRight':
        return 'control';
      case 'AltLeft':
      case 'AltRight':
        return 'alt';
      case 'ShiftLeft':
      case 'ShiftRight':
        return 'shift';
      case 'MetaLeft':
      case 'MetaRight':
        return 'meta';
    }
    if (c.startsWith('Key')) return c.slice(3).toLowerCase();
    if (c.startsWith('Digit')) return c.slice(5);
    return c.toLowerCase();
  };

  const report = (token) => {
    try {
      const it = window.__TAURI_INTERNALS__;
      if (it && typeof it.invoke === 'function') {
        it.invoke('kiosk_key', { key: token });
        return;
      }
      const api = window.__TAURI__;
      if (api && api.core && api.core.invoke) {
        api.core.invoke('kiosk_key', { key: token });
      }
    } catch (_) { /* kiosk tetap jalan walau IPC gagal */ }
  };

  document.addEventListener('contextmenu', (e) => e.preventDefault(), true);

  // Probe IPC sekali per muat halaman: mengungkap (di stderr debug build apakah
  // remote-IPC multiproto ini hidup. Token asing itu tertelan chord (reset).
  try {
    const itp = window.__TAURI_INTERNALS__;
    if (itp && typeof itp.invoke === 'function') {
      itp.invoke('kiosk_key', { key: 'onload-probe' });
    }
  } catch (_) { /* ini non-fatal — hanya diagnostik */ }

  window.addEventListener('keydown', (e) => {
    const k = canon(e);
    report(k);
    let blocked = false;
    if (e.ctrlKey && e.shiftKey) blocked = blockedWithCtrlShift.has(k);
    else if (e.ctrlKey) blocked = blockedPlain.has(k) || blockedWithCtrl.has(k);
    else blocked = blockedPlain.has(k);
    if (blocked) {
      e.preventDefault();
      e.stopPropagation();
    }
  }, true);
})();
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(ms: u64) -> Instant {
        Instant::now()
            .checked_add(Duration::from_millis(ms))
            .unwrap_or_else(Instant::now)
    }

    fn chord() -> Chord {
        Chord::new(vec!["control".into(), "c".into(), "b".into()])
    }

    #[test]
    fn chord_in_order_completes() {
        let mut c = chord();
        assert_eq!(c.feed("control", at(0)), ChordResult::InProgress);
        assert_eq!(c.feed("c", at(100)), ChordResult::InProgress);
        assert_eq!(c.feed("b", at(200)), ChordResult::Complete);
    }

    #[test]
    fn chord_is_sequential_not_simultaneous_set() {
        let mut c = chord();
        // Paritas lama: urutan tombol dipaksa. `c,b,control` = bukan complete.
        assert_eq!(c.feed("c", at(0)), ChordResult::InProgress);
        assert_eq!(c.feed("b", at(10)), ChordResult::InProgress);
        assert_eq!(c.feed("control", at(20)), ChordResult::InProgress);
    }

    #[test]
    fn chord_expires_between_keys() {
        let mut c = chord();
        assert_eq!(c.feed("control", at(0)), ChordResult::InProgress);
        assert_eq!(c.feed("c", at(1_400)), ChordResult::InProgress);
        // ~1.8 dtk sejak `c` → chord hangus, `b` mulai progress baru.
        assert_eq!(c.feed("b", at(3_200)), ChordResult::InProgress);
        assert_eq!(c.feed("b", at(3_300)), ChordResult::InProgress);
    }

    #[test]
    fn chord_resets_on_wrong_key_but_restarts_on_first_key() {
        let mut c = chord();
        assert_eq!(c.feed("control", at(0)), ChordResult::InProgress);
        assert_eq!(c.feed("x", at(10)), ChordResult::InProgress); // reset penuh
                                                                  // restart: `control` lagi sebelum chord hilang
        assert_eq!(c.feed("control", at(20)), ChordResult::InProgress);
        assert_eq!(c.feed("c", at(30)), ChordResult::InProgress);
        assert_eq!(c.feed("b", at(40)), ChordResult::Complete);
    }

    #[test]
    fn chord_complete_resets_for_next_use() {
        let mut c = chord();
        for (i, key) in ["control", "c", "b"].iter().enumerate() {
            c.feed(key, at(i as u64 * 100));
        }
        assert_eq!(c.feed("control", at(400)), ChordResult::InProgress);
        assert_eq!(c.feed("c", at(500)), ChordResult::InProgress);
        assert_eq!(c.feed("b", at(600)), ChordResult::Complete);
    }

    #[test]
    fn disabled_chord_never_completes() {
        let mut c = Chord::new(vec![]);
        assert!(!c.is_enabled());
        assert_eq!(c.feed("control", at(0)), ChordResult::InProgress);
    }

    #[test]
    fn case_insensitive_tokens() {
        let mut c = Chord::new(vec![" CONTROL ".into(), "C".into(), "b".into()]);
        assert_eq!(c.feed("CONTROL", at(0)), ChordResult::InProgress);
        assert_eq!(c.feed(" c ", at(100)), ChordResult::InProgress);
        assert_eq!(c.feed("B", at(200)), ChordResult::Complete);
    }

    #[test]
    fn init_script_contains_guards() {
        let js = exam_init_script();
        assert!(js.contains("contextmenu"));
        assert!(js.contains("kiosk_key"));
        assert!(js.contains("f12"));
        assert!(js.contains("preventDefault"));
    }
}
