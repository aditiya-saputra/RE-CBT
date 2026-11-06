# RE-CBT

Klien ujian CBT (Computer-Based Test) yang **aman dan cepat**, ditulis ulang
dari nol di **Rust + Tauri 2**. Proyek ini adalah kelanjutan langsung dari
riset reverse engineering [teardown-CBT](https://github.com/aditiya-saputra/teardown-CBT)
pada klien `ExamBrowser 26.0222` hasil dekompilasi `.NET` + deobfuscation
`main.js` Electron (webcrack). Seluruh kelemahan yang terbukti di sana
kita perbaiki di sini, bukan di-patch.

> **Lingkup & etika:** RE-CBT dibuat untuk server CBT yang **dimiliki dan
> dikelola sendiri** (sekolah/kampus). Ini **bukan** alat untuk menembus atau
> menipu ujian pihak ketiga. Konfigurasi ditandatangani Ed25519 oleh admin:
> tanpa kunci privat, tidak ada yang bisa mengoverride perilaku klien.

---

## Kenapa Rust

| Kebutuhan | Jawaban |
|---|---|
| Kecepatan | Binary tunggal tanpa runtime Electron (+100 MB), startup ~detik, memory footprint kecil |
| Keamanan ujian | TLS selalu terverifikasi (`rustls`), tanpa Node di renderer, konfigurasi tertanda tangan kiris (signing), interval polling anti-hammering |

## Peta perbaikan (teardown-CBT → RE-CBT)

| # | Temuan klien lama (bukti di teardown-CBT) | RE-CBT |
|---|---|---|
| 1 | `did-navigate` membandingkan string vs number → handler HTTP 500 **mati total** (baris 323–325) | `preflight.rs`: GET terverifikasi TLS sebelum jendela ujian dibuka; status gagal eksplisit dgn retry backoff 3→30 s + HUD |
| 2 | `Object.assign(windowParams, …)` memutasi global (305/326/466) | `Config` adalah `Arc` immutable; window dibangun dari nilai, tanpa state global |
| 3 | Error-window `nodeIntegration: true` → jalur RCE dari `404.html` (308) | Tidak ada Node sama sekali: renderer Tauri (WebView2) + CSP ketat di `tauri.conf.json` |
| 4 | `NODE_TLS_REJECT_UNAUTHORIZED = 0` + `ignore-certificate-errors` → semua TLS mati (400) | Tidak ada opsi komplemen TLS: reqwest **default rustls webpki-roots**, verifikasi tak bisa dimatikan dari konfigurasi |
| 5 | `setInterval(fn, undefined)` → clamp 1 ms → hammering server + CPU spin (389/455) | `MIN_POLL_MILLIS = 5_000` dipaksa di `config::validate_and_adjust` + backoff >60 s saat error (unit test ada) |
| 6–8 | implicit global, 3 listener terpisah, logika `statuskirim` terbalik | Rust: type-checked, `Send`/ownership ditegakkan kompiler |
| 9 | `fs.writeFile` error diabaikan (`if (err) {} else {}`) | Semua I/O mengembalikan `Result`; kegagalan HUD/log eksplisit |
| 11 | API deprecated (`new-window`) | API Tauri 2 stabil |
| 12 | `clearCache()` setelah `loadURL` → race (106–109) | `.incognito(true)` — tidak ada cache ditulis dari awal |
| 13 | `executeJavaScript(...).catch(()=>{})` menelan rejek | Tidak ada scraping DOM — identitas peserta eksplisit dari konfigurasi |
| 14 | `appendSwitch` post-ready tidak berefek (dead switch) | Tidak ada switch Chromium tersembunyi |
| — | Konfigurasi AES-256-CBC dgn kunci `nji9vgy7xdr6` + IV hardcoded di binary (§4.1) | JSON konfigurasi **bertanda tangan Ed25519** (`config/re-cbt.json`), kunci publik terpisah `ed25519.pub`, kunci privat tidak pernah ada di klien |
| — | `User-Agent` disuntik dari `argv[1]` (114–120) | `user_agent` eksplisit di konfigurasi tertanda tangan |
| — | `username.json`/`pesan.json`/`kick.json` tersebar di disk dan rawan atauphan | Semua komunikasi via **event** `cbt:hud-event` ke HUD (reload semantik tanpa file) |
| — | Lockdown keyboard sebenarnya dikerjakan by `runningexam.exe` di level OS (§10) | v0.1 fullscreen + `content_protected(true)` (≈ `setContentProtection`); lockdown keyboard OS-level masuk roadmap |

## Arsitektur

```mermaid
flowchart LR
    subgraph process[Proses re-cbt.exe (Rust)]
        CFG[config.rs<br/>verifikasi Ed25519] --> P[preflight.rs<br/>GET TLS-verified]
        P -->|OK| EXAM["jendela `exam`<br/>WebView2 fullscreen + incognito"]
        P -->|gagal| RETRY[backoff 3→30 s]
        EXAM --> POLL[poll.rs<br/>pesan + status kick<br/>min 5 s, backoff]
        POLL -->|cbt:hud-event| HUD["jendela `hud`<br/>HTML/CSS/JS statis"]
    end
    EXAM --> SRV[Server CBT milik sekolah]
    POLL --> SRV
```

## Cara pakai

### 0. Prasyarat

- **Rust stable** (≥ 1.85). Cek: `rustc --version`
- **WebView2 Runtime** (bawaan Windows 10/11)
- Untuk `cargo build`/`cargo run` **lokal di Windows**: [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (MSVC). `cargo check`/`cargo test` unit-konfigurasi tidak butuh linker; CI GitHub (windows-latest) menyediakan MSVC otomatis.

### 1. Admin: buat kunci + tandatangani konfigurasi

```pwsh
cp examples/payload.json my-cbt.json   # lalu edit sesuai server Anda
re-cbt genkey --out-dir config         # ed25519.priv + ed25519.pub
re-cbt sign my-cbt.json --key config/ed25519.priv --out config/re-cbt.json
```

`config/re-cbt.json` berisi `{payload_b64, signature_hex}`; `config/ed25519.pub`
harus berada sebelahnya (dibaca otomatis). **`ed25519.priv` jangan pernah
ada di mesin peserta.**

### 2. Peserta: jalankan

```pwsh
re-cbt                # default config/re-cbt.json
re-cbt D:\kiosk\config\re-cbt.json
```

Alur: HUD menampilkan status koneksi → preflight → jendela ujian fullscreen
(TLS tervalidasi, tanpa cache disk) → polling pesan pengawas & status kick
(min. tiap 5 s, backoff 60 s bila gagal) → jika pengawas mengeluarkan peserta,
HUD menampilkan alasan → exit dalam 15 s (dapat diubah `kick_grace_ms`).

### 3. CLI

| Perintah | Fungsi |
|---|---|
| `re-cbt [path]` | jalankan klien (default `config/re-cbt.json`) |
| `re-cbt genkey [--out-dir <dir>]` | buat pasangan Ed25519 (`.priv`/`.pub`, hex) |
| `re-cbt sign <payload.json> --key <ed25519.priv> [--out <out.json>]` | validasi + tanda tangani konfigurasi |
| `re-cbt help` | bantuan |

## Schema konfigurasi (`payload`)

| Field | Wajib | Default | Keterangan |
|---|---|---|---|
| `exam_url` | ✔ | — | HTTPS saja; halaman/paket ujian yang dimuat jendela utama |
| `supervisor_api_base` | ✔ | — | HTTPS; base URL API pengawas |
| `message_endpoint` | ✔ | — | template `api/task-get-pesan/{username}/{activity}` (tanpa `/` awal) |
| `status_endpoint` | ✔ | — | template `api/task-get-status-peserta/{username}/{activity}` |
| `user_agent` | ✔ | — | identitas UA kirim semua request |
| `activity` | ✔ | — | kegiatan/ujian |
| `participant_username` | ✔ | — | identitas peserta (tidak scraping DOM) |
| `message_interval_ms` | — | 300000 | di-clamp ≥ 5000 |
| `status_interval_ms` | — | 60000 | di-clamp ≥ 5000 |
| `kick_grace_ms` | — | 15000 | jeda dialog → exit saat dikick (min 1000) |
| `fullscreen` | — | true | mode kiosk |

Semua field konfigurasi final | Format ditolak jika: skema bukan HTTPS, field
kosong, template kehilangan `{username}`/`{activity}`, tanda tangan invalid.
`deny_unknown_fields` aktif — typo field ditolak, bukan diam.

## Verifikasi

```pwsh
cargo check      # typecheck tanpa linker (jalur CI cepat)
cargo test       # unit test konfigurasi (HTTPS-only, clamp, template token)
cargo clippy     # linter
cargo build      # butuh Build Tools MSVC di Windows
```

CI: `.github/workflows/ci.yml` — `cargo check`, `cargo test`, `cargo clippy`,
`cargo fmt --check` pada `windows-latest`.

## Roadmap

- [ ] Blokir context-menu/DevTools/os-shortcut di window ujian (setara `runningexam.exe` OS-level)
- [ ] Prokses kamera proktor (port `ExamCam` analisis di teardown-CBT)
- [ ] Bundler `tauri build` + ikon + installer MSIX
- [ ] File log terstruktur (tracing) + upload status tiap polling ke server
- [ ] Autoupdater channel-by-signature (Ed25519 juga yang menandatangani binary)

## Terkait proyek

- **teardown-CBT** — analisis rekayasa balik klien 26.0222: metode deobf
  (webcrack), peta 20 fungsi `main.js`, bug hunt 20 temuan (5 kritis),
  biolka decompiled `.NET`.
  Temuan #1–#5 di atas saling rujuk ke README analisis repo tersebut.

## Lisensi

MIT — lihat `LICENSE`.
