//! Preflight halaman ujian.
//!
//! Penggantitas dari handler `did-navigate` klien lama yang mati total
//! (string vs number, temuan #1): alih-alih melumpuhkan handler 500,
//! RE-CBT **tidak memuat halaman** sampai server terbukti hidup via TLS
//! yang diverifikasi penuh (rustls) — kegagalan jadi eksplisit dan diberi
//! jadwal mencoba ulang dengan backoff.
//!
//! Kalau nanti sudah lebih kebutuhan offline, di sini titik kunci
//! merute/limit halaman ujian, bukan di renderer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PreflightError {
    #[error("HTTP {status} pada {url}")]
    BadStatus { status: u16, url: String },
    #[error("redirect turun ke non-HTTPS: {0}")]
    Downgrade(String),
    #[error("jaringan: {0}")]
    Transport(#[from] reqwest::Error),
}

pub struct PreflightOk {
    pub final_url: reqwest::Url,
    pub status: u16,
}

/// GET sekali ke `exam_url` dengan TLS rustls.
/// Sukses hanya jika final URL masih HTTPS dan status 2xx/3xx.
/// Body drop — tujuannya verifikasi keterjangkauan, bukan rendering.
pub async fn check(
    client: &reqwest::Client,
    exam_url: &reqwest::Url,
) -> Result<PreflightOk, PreflightError> {
    let resp = client.get(exam_url.clone()).send().await?;
    let final_url = resp.url().clone();
    if final_url.scheme() != "https" {
        return Err(PreflightError::Downgrade(final_url.to_string()));
    }
    let status = resp.status().as_u16();
    if !(200..=399).contains(&status) {
        return Err(PreflightError::BadStatus {
            status,
            url: final_url.to_string(),
        });
    }
    Ok(PreflightOk { final_url, status })
}
