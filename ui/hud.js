// HUD RE-CBT: menerima backend event `cbt:hud-event` (lihat src-tauri/src/hud.rs).
// Semua kartu: { kind, data } dengan rename snake_case dari Rust.

const api = window.__TAURI__;
const card = document.getElementById("card");
const tagEl = document.getElementById("tag");
const titleEl = document.getElementById("title");
const bodyEl = document.getElementById("body");
const okBtn = document.getElementById("ok");
const unlockRow = document.getElementById("unlock");
const unlockPass = document.getElementById("unlockpass");
const unlockOk = document.getElementById("unlockok");

// Selftest debug-only (URL hud memuat ?kiosk-selftest=1): memicu chord
// dilihat dari sisi IPC app-origin — mengisolasi mesin chord di Rust dari
// keandalan focus keyboard window ujian.
if (api && api.core && location.search.includes("kiosk-selftest")) {
  setTimeout(async () => {
    for (const token of ["control", "c", "b"]) {
      try {
        await api.core.invoke("kiosk_key", { key: token });
      } catch (_) { /* tetap jalankan sisa tahap */ }
      await new Promise((r) => setTimeout(r, 150));
    }
  }, 800);
}

function setCard(kind, tag, title, body, dismissable) {
  card.className = kind;
  tagEl.textContent = tag;
  titleEl.textContent = title;
  bodyEl.textContent = body ?? "";
  okBtn.classList.toggle("hidden", !dismissable);
}

okBtn.addEventListener("click", () => {
  setCard("info", "status", "RE-CBT aktif", "Pesan pengawas berikutnya muncul di panel ini.", false);
});

function handleEvent(ev) {
  const d = ev.data || {};
  switch (ev.kind) {
    case "connecting":
      setCard(
        "info",
        "koneksi",
        "Memeriksa halaman ujian",
        `Memastikan ${d.url} dapat dijangkau lewat TLS tervalidasi.`,
        false,
      );
      break;
    case "retry":
      setCard(
        "warn",
        "koneksi",
        "Menunggu server ujian",
        `${d.reason} — mencoba ulang dalam ${d.next_in_secs} dtk.`,
        false,
      );
      break;
    case "connected":
      setCard(
        "info",
        "aktif",
        "RE-CBT aktif",
        "Halaman ujian terbuka. Pesan pengawas akan muncul di panel ini.",
        false,
      );
      break;
    case "message":
      setCard("message", "pesan pengawas", d.created || new Date().toLocaleString(), d.message || "", true);
      break;
    case "kick":
      setCard(
        "kick",
        "peringatan",
        "Anda dikeluarkan oleh pengawas",
        `${d.reason || "Sesi diakhiri."} — jendela ditutup dalam ${d.grace_secs} dtk.`,
        false,
      );
      break;
    case "fatal":
      setCard("kick", "error", "RE-CBT berhenti", d.message || "Kesalahan fatal.", false);
      break;
    case "unlock_prompt":
      setCard(
        "warn",
        "buka-kunci",
        "Pintu operator",
        `Kombinasi ${d.keys || "chord"} dikenali. Masukkan password operator untuk menutup RE-CBT secara bersih.`,
        false,
      );
      unlockRow.classList.remove("hidden");
      if (unlockPass) unlockPass.focus();
      break;
    case "unlock_failed":
      setCard(
        "warn",
        "buka-kunci",
        "Password salah",
        `Percobaan ke-${d.attempt ?? "-"} ditolak.` +
          (d.attempt === 0 ? " Terkunci sementara 30 detik." : ""),
        false,
      );
      if (unlockPass) {
        unlockPass.value = "";
        unlockPass.focus();
      }
      break;
    case "unlocked":
      unlockRow.classList.add("hidden");
      setCard("ok-green", "buka-kunci", "Terbuka", "Password benar — RE-CBT ditutup dengan bersih.", false);
      break;
    default:
      setCard("info", "?", `Event tak dikenal: ${ev.kind}`, "", true);
  }
}

async function submitUnlock() {
  const password = unlockPass.value;
  if (!password) return;
  unlockOk.disabled = true;
  try {
    await api.core.invoke("unlock_check", { password });
  } catch (err) {
    setCard("warn", "buka-kunci", "Gagal", `IPC gagal: ${err}`, true);
  } finally {
    unlockOk.disabled = false;
  }
}

unlockOk.addEventListener("click", submitUnlock);
unlockPass.addEventListener("keydown", (e) => {
  if (e.key === "Enter") submitUnlock();
});

(async function listen() {
  if (!api || !api.event) {
    setCard("warn", "hud", "RE-CBT HUD", "Runtime Tauri tidak terdeteksi (mode preview?).", true);
    return;
  }
  try {
    await api.event.listen("cbt:hud-event", (e) => handleEvent(e.payload || {}));
  } catch (err) {
    setCard("warn", "hud", "RE-CBT HUD", `Gagal listen event: ${err}`, true);
  }
})();
