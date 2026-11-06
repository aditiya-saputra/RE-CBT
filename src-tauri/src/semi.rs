//! Pengecekan pra-ujian khusus mode `semi` (LAN terisolasi).
//!
//! Paritas `ModeUjian=1` klien lama: mesin harus satu subnet dengan host
//! ujian, dan internet **tidak boleh** terdeteksi. Dua perbedaan penting
//! dari klien lama: host ujian dan URL probe datang dari konfigurasi
//! ditandatangani (tidak ada IP/secrets yang di-hardcode), dan hasil
//! pengecekan dikirim eksplisit ke HUD sebelum aplikasi keluar.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use thiserror::Error;

use crate::config::Config;

/// Timeout probe deteksi internet. Saat LAN benar-benar terisolasi, kegagalan
/// biasanya instan (DNS/route gagal); timeout ini meng-cover jaringan yang
/// "setengah hidup" (captive/proxy yang mencekik koneksi luar).
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum SemiError {
    #[error("tidak ada IP lokal dalam subnet {host}/{prefix} (IP lokal: {locals})")]
    OnDifferentSubnet {
        host: Ipv4Addr,
        prefix: u8,
        locals: String,
    },
    #[error("internet terdeteksi via probe {url} — mode semi menuntut LAN terisolasi")]
    InternetDetected { url: String },
    #[error("host '{0}' bukan IPv4 — tidak bisa memeriksa subnet")]
    NotIpv4Host(String),
    #[error("offline_probe_url hilang dari konfigurasi (mode semi)")]
    MissingProbe,
}

/// Daftar semua alamat IPv4 milik mesin (kartu jaringan aktif).
/// Gagal enumerasi = daftar kosong (subnet check akan menolak — gagal-tutup).
pub fn local_ipv4s() -> Vec<Ipv4Addr> {
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces
            .into_iter()
            .filter_map(|i| match i.addr {
                if_addrs::IfAddr::V4(v4) => Some(v4.ip),
                _ => None,
            })
            .collect(),
        Err(e) => {
            eprintln!("RE-CBT: gagal enumerasi IP lokal: {e}");
            Vec::new()
        }
    }
}

/// Alamat network `ip` menurut prefix `prefix` (host bit di-nol-kan).
fn network(ip: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask
}

/// True jika `local` satu subnet dengan `host` menurut `prefix`.
pub fn subnet_matches(local: Ipv4Addr, host: Ipv4Addr, prefix: u8) -> bool {
    network(local, prefix) == network(host, prefix)
}

fn fmt_locals(locals: &[Ipv4Addr]) -> String {
    if locals.is_empty() {
        "(tidak ada)".to_string()
    } else {
        locals
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Cek subnet: paling sedikit satu IP milik mesin berada di subnet `host`.
pub fn check_subnet(host: Ipv4Addr, prefix: u8, locals: &[Ipv4Addr]) -> Result<(), SemiError> {
    if locals.iter().any(|l| subnet_matches(*l, host, prefix)) {
        return Ok(());
    }
    Err(SemiError::OnDifferentSubnet {
        host,
        prefix,
        locals: fmt_locals(locals),
    })
}

/// Cek ketiadaan internet: probe HARUS gagal. **Sukses** request tervalidasi
/// TLS (client rustls yang sama) berarti internet hidup → mode semi ditolak.
/// Gagal DNS/route/TLS/timeout = benar (tidak ada internet).
pub async fn check_no_internet(
    http: &reqwest::Client,
    probe: &reqwest::Url,
) -> Result<(), SemiError> {
    match http.get(probe.clone()).timeout(PROBE_TIMEOUT).send().await {
        Ok(_) => Err(SemiError::InternetDetected {
            url: probe.to_string(),
        }),
        Err(_) => Ok(()),
    }
}

/// Pengecekan lengkap pra-ujian mode semi:
/// subnet dulu (instan), lalu probe internet (maks 5 dtk saat offline).
pub async fn precheck(http: &reqwest::Client, cfg: &Config) -> Result<(), SemiError> {
    let host = parse_host(&cfg.exam_url)?;
    check_subnet(host, cfg.semi_subnet_prefix, &local_ipv4s())?;
    let probe = cfg
        .offline_probe_url
        .as_ref()
        .ok_or(SemiError::MissingProbe)?;
    check_no_internet(http, probe).await
}

fn parse_host(url: &reqwest::Url) -> Result<Ipv4Addr, SemiError> {
    let raw = url.host_str().unwrap_or_default();
    Ipv4Addr::from_str(raw).map_err(|_| SemiError::NotIpv4Host(raw.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(o1: u8, o2: u8, o3: u8, o4: u8) -> Ipv4Addr {
        Ipv4Addr::new(o1, o2, o3, o4)
    }

    #[test]
    fn same_subnet_24() {
        assert!(subnet_matches(
            ip(192, 168, 10, 5),
            ip(192, 168, 10, 200),
            24
        ));
    }

    #[test]
    fn different_third_octet_rejected_on_24() {
        assert!(!subnet_matches(
            ip(192, 168, 11, 5),
            ip(192, 168, 10, 200),
            24
        ));
    }

    #[test]
    fn prefix_16_joins_third_octet() {
        assert!(subnet_matches(
            ip(192, 168, 11, 5),
            ip(192, 168, 10, 200),
            16
        ));
    }

    #[test]
    fn prefix_32_requires_exact_ip() {
        let a = ip(192, 168, 10, 5);
        let b = ip(192, 168, 10, 6);
        assert!(subnet_matches(a, a, 32));
        assert!(!subnet_matches(a, b, 32));
    }

    #[test]
    fn prefix_0_matches_everything() {
        assert!(subnet_matches(ip(10, 0, 0, 1), ip(192, 168, 1, 2), 0));
    }

    #[test]
    fn check_subnet_passes_when_any_local_matches() {
        let locals = vec![ip(127, 0, 0, 1), ip(192, 168, 10, 77)];
        assert!(check_subnet(ip(192, 168, 10, 200), 24, &locals).is_ok());
    }

    #[test]
    fn check_subnet_reports_locals_on_failure() {
        let locals = vec![ip(127, 0, 0, 1)];
        let err = check_subnet(ip(192, 168, 10, 200), 24, &locals).unwrap_err();
        assert!(matches!(err, SemiError::OnDifferentSubnet { .. }));
        assert!(err.to_string().contains("127.0.0.1"));
    }

    #[test]
    fn empty_locals_named_clearly() {
        let err = check_subnet(ip(192, 168, 10, 200), 24, &[]).unwrap_err();
        assert!(err.to_string().contains("(tidak ada)"));
    }

    #[test]
    fn parse_host_rejects_hostname() {
        let url = reqwest::Url::parse("https://cbt.sekolah.sch.id/unbk").unwrap();
        assert!(matches!(parse_host(&url), Err(SemiError::NotIpv4Host(_))));
    }
}
