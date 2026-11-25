// SPDX-License-Identifier: Apache-2.0
//! NodeConfig.update_channel: an https server with its own CA
//! replaces the image channel; a foreign CA fails the TLS handshake and the
//! slot is not touched; clearing the override returns to the image channel.
mod common;
use common::*;
use foil_agent::pb::{ChannelOrigin, StageError, StagePhase, UpdateChannel};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

struct Ca {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn ca(name: &str) -> Ca {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, name);
    let key = KeyPair::generate().unwrap();
    let c = p.self_signed(&key).unwrap();
    Ca { pem: c.pem(), issuer: Issuer::new(p, key) }
}


/// What the server does to a faulted connection instead of serving it.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// close right after accept, before any TLS byte
    CloseBeforeTls,
    /// read the ClientHello record, then close (FIN)
    AfterClientHelloFin,
    /// read only the record header of the ClientHello and close with the rest unread (the kernel sends RST)
    AfterClientHelloRst,
    /// answer with the ServerHello record only, then close (the handshake is cut in the middle)
    AfterServerHello,
    /// answer the ClientHello with a fatal TLS alert (handshake_failure)
    Alert,
    /// answer the ClientHello with plain text instead of TLS
    Plaintext,
}

/// read one TLS record (header + body) from the stream; false on EOF
fn read_record(s: &mut std::net::TcpStream) -> bool {
    let mut h = [0u8; 5];
    if s.read_exact(&mut h).is_err() {
        return false;
    }
    let mut b = vec![0u8; u16::from_be_bytes([h[3], h[4]]) as usize];
    s.read_exact(&mut b).is_ok()
}

fn fault(mut s: std::net::TcpStream, f: Fault, cfg: Arc<rustls::ServerConfig>) {
    use std::net::Shutdown;
    match f {
        Fault::CloseBeforeTls => {}
        Fault::AfterClientHelloFin => {
            read_record(&mut s);
            let _ = s.shutdown(Shutdown::Write);
        }
        Fault::AfterClientHelloRst => {
            let mut h = [0u8; 5];
            let _ = s.read_exact(&mut h); // the record body stays unread: closing now resets the connection
        }
        Fault::AfterServerHello => {
            let mut conn = rustls::ServerConnection::new(cfg).unwrap();
            while conn.is_handshaking() && !conn.wants_write() {
                if conn.read_tls(&mut s).unwrap_or(0) == 0 || conn.process_new_packets().is_err() {
                    return;
                }
            }
            let mut out = Vec::new();
            while conn.wants_write() {
                if conn.write_tls(&mut out).is_err() {
                    return;
                }
            }
            // the first record is the ServerHello: send it alone and stop
            if out.len() >= 5 {
                let n = 5 + u16::from_be_bytes([out[3], out[4]]) as usize;
                let _ = s.write_all(&out[..n.min(out.len())]);
            }
            let _ = s.shutdown(Shutdown::Write);
        }
        Fault::Alert => {
            read_record(&mut s);
            let _ = s.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
            let _ = s.shutdown(Shutdown::Write);
        }
        Fault::Plaintext => {
            read_record(&mut s);
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
            let _ = s.shutdown(Shutdown::Write);
        }
    }
    // let the peer read what was sent before the socket goes
    std::thread::sleep(std::time::Duration::from_millis(50));
}

/// Minimal blocking HTTPS/1.1 file server (GET only, no Range), a thread per connection; the first `faulty`
/// connections get `f` instead of the file. Returns the port and the number of accepted connections.
fn serve_tls_faulty(dir: PathBuf, ca: &Ca, f: Fault, faulty: usize) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let p = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &ca.issuer).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let cfg = Arc::new(cfg);
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = accepted.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < faulty {
                let cfg = cfg.clone();
                std::thread::spawn(move || fault(s, f, cfg));
                continue;
            }
            let (cfg, dir) = (cfg.clone(), dir.clone());
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let mut t = rustls::StreamOwned::new(conn, s);
                let mut buf = vec![0u8; 8192];
                let Ok(n) = t.read(&mut buf) else { return }; // handshake fails here for a foreign CA
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/");
                let name = path.rsplit('/').next().unwrap_or("");
                let ok = path.starts_with("/foilbird/");
                match std::fs::read(dir.join(name)).ok().filter(|_| ok) {
                    Some(d) => {
                        let _ = write!(t, "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", d.len());
                        let _ = t.write_all(&d);
                    }
                    None => {
                        let _ = t.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                    }
                }
                let _ = t.flush();
                t.conn.send_close_notify();
                let _ = t.flush();
            });
        }
    });
    (port, accepted)
}

#[tokio::test]
async fn override_https_own_ca_foreign_ca_and_back_to_image() {
    let root = tmp("https");
    let good = ca("channel ca");
    let (port, accepted) = serve_tls_faulty(fixtures().join("channel"), &good, Fault::CloseBeforeTls, 0);
    let mock = Arc::new(Mock::default());
    // image channel: an empty directory, so a release from it would fail
    let empty = root.join("image-channel");
    std::fs::create_dir_all(&empty).unwrap();
    let s = stager(empty.clone(), root.join("staging"), "0", mock.clone());
    assert_eq!(s.current_channel().1.origin, ChannelOrigin::Image as i32);

    // foreign CA: TLS refused, nothing installed, staging cleaned
    let foreign = ca("someone else");
    s.set_override(Some(&UpdateChannel { endpoint: format!("127.0.0.1:{port}"), prefix: "/foilbird/".into(), ca_pem: foreign.pem.clone() }));
    let info = s.current_channel().1;
    assert_eq!(info.origin, ChannelOrigin::Config as i32);
    assert_eq!(info.location, format!("https://127.0.0.1:{port}/foilbird/"));
    s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(StageError::try_from(st.error).unwrap(), StageError::Download, "{st:?}");
    // what TLS said is Fatal at once: no retries
    assert!(st.detail.contains("TLS: ") && !st.detail.contains("retries)"), "foreign CA must be fatal without retries: {st:?}");
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1, "a refused certificate is not tried again");
    assert!(mock.installs.lock().unwrap().is_empty(), "slot must not be touched");
    assert_eq!(std::fs::read_dir(root.join("staging")).unwrap().count(), 0, "staging cleaned");

    // own CA: staged from the override
    s.set_override(Some(&UpdateChannel { endpoint: format!("127.0.0.1:{port}"), prefix: "foilbird".into(), ca_pem: good.pem.clone() }));
    s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(st.phase, StagePhase::Staged as i32, "{st:?}");
    assert_eq!(mock.installs.lock().unwrap().len(), 1);

    // cleared: back to the image channel
    s.set_override(None);
    let info = s.current_channel().1;
    assert_eq!(info.origin, ChannelOrigin::Image as i32);
    assert_eq!(info.location, empty.display().to_string());
}

#[test]
fn unusable_override_does_not_fall_back() {
    let root = tmp("https-bad");
    let s = stager(fixtures().join("channel"), root.join("staging"), "0", Arc::new(Mock::default()));
    s.set_override(Some(&UpdateChannel { endpoint: "127.0.0.1:1".into(), prefix: String::new(), ca_pem: String::new() }));
    let (ch, info) = s.current_channel();
    assert!(ch.is_none(), "no silent fallback to the image channel");
    assert_eq!(info.origin, ChannelOrigin::Config as i32);
    assert!(!info.error.is_empty());
}

/// wait for the stage to end (the retries take seconds)
async fn settle_long(s: &foil_agent::update::Stager) -> foil_agent::pb::StageStatus {
    for _ in 0..1500 {
        {
            let st = s.state.lock().await;
            if !st.busy() {
                return st.stage.clone().unwrap();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("stage did not end in 30 s");
}

/// stage release 2 from a server that faults the first `n` connections with `f`
async fn stage_with(f: Fault, n: usize, tag: &str) -> (foil_agent::pb::StageStatus, usize, usize) {
    let root = tmp(tag);
    let good = ca("channel ca");
    let (port, accepted) = serve_tls_faulty(fixtures().join("channel"), &good, f, n);
    let mock = Arc::new(Mock::default());
    let empty = root.join("image-channel");
    std::fs::create_dir_all(&empty).unwrap();
    let s = stager(empty, root.join("staging"), "0", mock.clone());
    s.set_override(Some(&UpdateChannel { endpoint: format!("127.0.0.1:{port}"), prefix: "/foilbird/".into(), ca_pem: good.pem.clone() }));
    s.start("2").await.ok().expect("accepted");
    let st = settle_long(&s).await;
    let installs = mock.installs.lock().unwrap().len();
    (st, accepted.load(std::sync::atomic::Ordering::SeqCst), installs)
}

/// The transport cut before or in the middle of the handshake is retried (every connection cut: retries exhausted,
/// 1 + 3 connections; the kind the agent saw goes to handshake_interruptions.txt for the record). What the TLS layer
/// says (an alert, plain text instead of TLS) is final at once: one connection.
#[tokio::test]
async fn handshake_interruptions_retried_tls_answers_final() {
    let mut record = String::new();
    for f in [Fault::CloseBeforeTls, Fault::AfterClientHelloFin, Fault::AfterClientHelloRst, Fault::AfterServerHello] {
        let (st, n, _) = stage_with(f, usize::MAX, &format!("https-cut-{f:?}")).await;
        assert_eq!(StageError::try_from(st.error).unwrap(), StageError::Download, "{f:?}: {st:?}");
        assert!(st.detail.contains("(after 3 retries)") && st.detail.contains("[transport: "), "{f:?} must be retried: {st:?}");
        assert_eq!(n, 4, "{f:?}: 1 + 3 connections");
        record.push_str(&format!("{f:?}: Retry, {}\n", st.detail));
    }
    for f in [Fault::Alert, Fault::Plaintext] {
        let (st, n, _) = stage_with(f, usize::MAX, &format!("https-tls-{f:?}")).await;
        assert_eq!(StageError::try_from(st.error).unwrap(), StageError::Download, "{f:?}: {st:?}");
        assert!(st.detail.contains("TLS: ") && !st.detail.contains("retries)"), "{f:?} must be final at once: {st:?}");
        assert_eq!(n, 1, "{f:?}: not tried again");
        record.push_str(&format!("{f:?}: Fatal, {}\n", st.detail));
    }
    std::fs::write(std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("handshake_interruptions.txt"), record).unwrap();
}

/// A connection broken during the handshake is the transport: retried, and the stage completes.
#[tokio::test]
async fn handshake_broken_once_is_retried() {
    for f in [Fault::CloseBeforeTls, Fault::AfterClientHelloRst, Fault::AfterServerHello] {
        let (st, n, installs) = stage_with(f, 1, &format!("https-once-{f:?}")).await;
        assert_eq!(st.phase, StagePhase::Staged as i32, "{f:?}: {st:?}");
        assert_eq!(installs, 1, "{f:?}");
        assert!(n >= 2, "{f:?}: the cut connection was tried again");
    }
}
