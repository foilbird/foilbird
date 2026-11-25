// SPDX-License-Identifier: Apache-2.0
//! HTTP channel against an in-process HTTP/1.1 server: release staged over
//! HTTP; connection drop mid-file recovered by retry (with Range); permanent
//! drop, tampered file and foreign signature refused, slot untouched.
mod common;
use common::*;
use foil_agent::pb::{StageError, StagePhase};
use foil_agent::update::{self, HttpChannel};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Plan {
    drop_once: HashMap<String, bool>, // name -> already dropped
    drop_always: Vec<String>,
    requests: Vec<(String, Option<String>)>, // (name, range)
}

async fn serve(dir: PathBuf, plan: Arc<Mutex<Plan>>) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let (dir, plan) = (dir.clone(), plan.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").trim_start_matches('/').to_string();
                let name = path.rsplit('/').next().unwrap_or("").to_string();
                let range = req.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("range: bytes=").map(|r| r.trim_end_matches('-').to_string()));
                let (drop, data) = {
                    let mut p = plan.lock().unwrap();
                    p.requests.push((name.clone(), range.clone()));
                    let once = p.drop_once.get_mut(&name).map(|d| !std::mem::replace(d, true)).unwrap_or(false);
                    (once || p.drop_always.contains(&name), std::fs::read(dir.join(&name)).ok())
                };
                let Some(data) = data else {
                    let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
                    return;
                };
                let from: usize = range.and_then(|r| r.parse().ok()).unwrap_or(0).min(data.len());
                let body = &data[from..];
                let head = if from > 0 {
                    format!("HTTP/1.1 206 Partial Content\r\ncontent-length: {}\r\ncontent-range: bytes {from}-{}/{}\r\nconnection: close\r\n\r\n", body.len(), data.len() - 1, data.len())
                } else {
                    format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len())
                };
                let _ = s.write_all(head.as_bytes()).await;
                if drop {
                    let _ = s.write_all(&body[..body.len() / 2]).await;
                    return; // connection closed mid-body
                }
                let _ = s.write_all(body).await;
            });
        }
    });
    port
}

fn stager_http(port: u16, staging: PathBuf, mock: Arc<Mock>) -> Arc<update::Stager> {
    let mut ch = HttpChannel::new(&format!("http://127.0.0.1:{port}/foilbird-deb/"), None).unwrap();
    ch.retries = 2;
    ch.idle_timeout = std::time::Duration::from_secs(3);
    let s = stager(PathBuf::new(), staging, "0", mock);
    Arc::new(update::Stager {
        channel: Some(Arc::new(ch)),
        channel_override: Default::default(),
        platform: s.platform.clone(),
        policy: s.policy.clone(),
        staging_root: s.staging_root.clone(),
        state: Default::default(),
    })
}

fn err(s: &foil_agent::pb::StageStatus) -> StageError {
    StageError::try_from(s.error).unwrap()
}

#[tokio::test]
async fn stages_over_http_and_recovers_a_drop() {
    let root = tmp("http-ok");
    let plan = Arc::new(Mutex::new(Plan::default()));
    plan.lock().unwrap().drop_once.insert("foilbird_2.usr-x86-64.0f0f.raw.zst".into(), false);
    let port = serve(fixtures().join("channel"), plan.clone()).await;
    let mock = Arc::new(Mock::default());
    let s = stager_http(port, root.join("staging"), mock.clone());
    s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(st.phase, StagePhase::Staged as i32, "{st:?}");
    assert_eq!(mock.installs.lock().unwrap().len(), 1);
    let reqs = plan.lock().unwrap().requests.clone();
    let usr: Vec<_> = reqs.iter().filter(|r| r.0 == "foilbird_2.usr-x86-64.0f0f.raw.zst").collect();
    assert_eq!(usr.len(), 2, "one drop, one retry: {reqs:?}");
    assert!(usr[1].1.is_some(), "retry resumes with Range: {usr:?}");
}

#[tokio::test]
async fn permanent_drop_tamper_and_foreign_key_are_refused() {
    let root = tmp("http-bad");
    // permanent drop
    let plan = Arc::new(Mutex::new(Plan::default()));
    plan.lock().unwrap().drop_always.push("foilbird_2.efi".into());
    let port = serve(fixtures().join("channel"), plan.clone()).await;
    let mock = Arc::new(Mock::default());
    let s = stager_http(port, root.join("staging"), mock.clone());
    s.start("2").await.ok().expect("accepted");
    let st = settle(&s).await;
    assert_eq!(err(&st), StageError::Download, "{st:?}");
    // tampered file (version 4 in the fixtures)
    s.start("4").await.ok().expect("accepted");
    assert_eq!(err(&settle(&s).await), StageError::HashMismatch);
    // foreign signature
    let ch = root.join("foreign");
    std::fs::create_dir_all(&ch).unwrap();
    for e in std::fs::read_dir(fixtures().join("channel")).unwrap().flatten() {
        std::fs::copy(e.path(), ch.join(e.file_name())).unwrap();
    }
    std::fs::copy(fixtures().join("SHA256SUMS.other.gpg"), ch.join("SHA256SUMS.gpg")).unwrap();
    let port2 = serve(ch, Arc::new(Mutex::new(Plan::default()))).await;
    let s2 = stager_http(port2, root.join("staging2"), mock.clone());
    s2.start("2").await.ok().expect("accepted");
    assert_eq!(err(&settle(&s2).await), StageError::BadSignature);
    // missing release file -> 404 is final, no retries
    assert!(mock.installs.lock().unwrap().is_empty(), "slot must not be touched");
    assert_eq!(std::fs::read_dir(root.join("staging")).unwrap().count(), 0, "staging cleaned");
}

#[test]
fn channel_url_rules() {
    assert!(HttpChannel::new("http://192.0.2.1:8080/foilbird-deb/", None).is_ok());
    assert!(HttpChannel::new("https://updates.example.org/x/", None).is_err(), "https needs a CA");
    for bad in ["ftp://x/", "http://user@x/", "http:///x", "http://x/a b", "http://x/?q=1"] {
        assert!(HttpChannel::new(bad, None).is_err(), "{bad}");
    }
}
