// HUD RE-CBT: menerima backend event `cbt:hud-event` (lihat src-tauri/src/hud.rs).
// Semua kartu: { kind, data } dengan rename snake_case dari Rust.

const card = document.getElementById("card");
const tagEl = document.getElementById("tag");
const titleEl = document.getElementById("title");
const bodyEl = document.getElementById("body");
const okBtn = document.getElementById("ok");

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
    default:
      setCard("info", "?", `Event tak dikenal: ${ev.kind}`, "", true);
  }
}

(async function listen() {
  const api = window.__TAURI__;
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
