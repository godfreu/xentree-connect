//! Browser login: a one-shot loopback listener receives the token from a
//! redirect to `http://127.0.0.1:PORT/callback`.

use std::{net::Ipv4Addr, time::Duration};

use secrecy::SecretString;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, timeout_at, Instant},
};
use url::Url;
use uuid::Uuid;

use super::AuthError;
use crate::api::{endpoint_url, ApiError};

const CALLBACK_PATH: &str = "/callback";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

const DONE_PAGE: &str = "<!doctype html><meta charset=utf-8><title>Xentree Connect</title>\
<body style=\"font-family:system-ui,sans-serif;text-align:center;margin-top:20vh\">\
<h1>You're signed in</h1><p>You can close this tab now and return to your terminal.</p>";
const FAILED_PAGE: &str = "<!doctype html><meta charset=utf-8><title>Xentree Connect</title>\
<body style=\"font-family:system-ui,sans-serif;text-align:center;margin-top:20vh\">\
<h1>Sign-in failed</h1><p>Return to your terminal and try again.</p>";

/// A bound, not yet awaited, loopback listener with its CSRF `state`.
pub struct BrowserLogin {
    listener: TcpListener,
    port: u16,
    state: String,
}

impl BrowserLogin {
    pub async fn bind() -> Result<Self, AuthError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(AuthError::Listen)?;
        let port = listener.local_addr().map_err(AuthError::Listen)?.port();
        Ok(Self {
            listener,
            port,
            state: Uuid::new_v4().simple().to_string(),
        })
    }

    /// `{base}/login?cli_callback=http://127.0.0.1:{port}/callback&state=…`
    pub fn login_url(&self, base: &Url) -> Result<Url, ApiError> {
        let mut url = endpoint_url(base, &["login"])?;
        url.query_pairs_mut()
            .append_pair(
                "cli_callback",
                &format!("http://127.0.0.1:{}{CALLBACK_PATH}", self.port),
            )
            .append_pair("state", &self.state);
        Ok(url)
    }

    /// Serves callbacks until one carries the right `state` and a token, or
    /// `limit` passes. Stray requests (favicon, probes, wrong state) get an
    /// error page and don't end the wait.
    pub async fn wait(self, limit: Duration) -> Result<SecretString, AuthError> {
        let deadline = Instant::now() + limit;
        loop {
            let (stream, _) = timeout_at(deadline, self.listener.accept())
                .await
                .map_err(|_| AuthError::TimedOut)?
                .map_err(AuthError::Listen)?;
            if let Some(outcome) = handle(stream, &self.state).await {
                return outcome;
            }
        }
    }
}

/// `Some` once the connection settled the login either way.
async fn handle(mut stream: TcpStream, state: &str) -> Option<Result<SecretString, AuthError>> {
    let Some(target) = read_target(&mut stream).await else {
        respond(&mut stream, "400 Bad Request", FAILED_PAGE).await;
        return None;
    };
    let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
        respond(&mut stream, "400 Bad Request", FAILED_PAGE).await;
        return None;
    };
    if url.path() != CALLBACK_PATH {
        respond(&mut stream, "404 Not Found", FAILED_PAGE).await;
        return None;
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    let state_ok = param("state").is_some_and(|s| bool::from(s.as_bytes().ct_eq(state.as_bytes())));
    if !state_ok {
        respond(&mut stream, "400 Bad Request", FAILED_PAGE).await;
        return None;
    }
    if let Some(err) = param("error") {
        respond(&mut stream, "400 Bad Request", FAILED_PAGE).await;
        return Some(Err(AuthError::Callback(err.chars().take(200).collect())));
    }
    match param("token")
        .or_else(|| param("access_token"))
        .filter(|t| !t.trim().is_empty())
    {
        Some(token) => {
            respond(&mut stream, "200 OK", DONE_PAGE).await;
            Some(Ok(SecretString::from(token)))
        }
        None => {
            respond(&mut stream, "400 Bad Request", FAILED_PAGE).await;
            None
        }
    }
}

/// The request target of a `GET`, e.g. `/callback?token=…`.
async fn read_target(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(2).any(|w| w == b"\r\n") {
        if buf.len() > MAX_REQUEST_BYTES {
            return None;
        }
        let n = timeout(READ_TIMEOUT, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line_end = buf.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&buf[..line_end]).ok()?;
    let mut parts = line.split(' ');
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(target)) if target.starts_with('/') => Some(target.to_string()),
        _ => None,
    }
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
Content-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Best effort; the caller also prints the link for SSH and headless hosts.
pub fn open_browser(url: &str) -> bool {
    use std::process::{Command, Stdio};

    #[cfg(target_os = "macos")]
    let mut cmd = Command::new("open");
    #[cfg(windows)]
    let mut cmd = {
        // Not `cmd /C start`: it would treat the `&` in the URL as a command separator.
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(not(any(target_os = "macos", windows)))]
    let mut cmd = Command::new("xdg-open");

    cmd.arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    async fn get(port: u16, target: &str) -> String {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn login_url_carries_callback_and_state() {
        let l = BrowserLogin::bind().await.unwrap();
        let base = Url::parse("https://my.xentree.ai").unwrap();
        let url = l.login_url(&base).unwrap();
        assert_eq!(url.path(), "/login");
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            q["cli_callback"],
            format!("http://127.0.0.1:{}/callback", l.port)
        );
        assert_eq!(q["state"], l.state);
        assert!(l.state.len() >= 32);
    }

    #[tokio::test]
    async fn captures_the_token_and_ignores_strays() {
        let l = BrowserLogin::bind().await.unwrap();
        let (port, state) = (l.port, l.state.clone());
        let task = tokio::spawn(l.wait(Duration::from_secs(10)));

        assert!(get(port, "/favicon.ico").await.starts_with("HTTP/1.1 404"));
        let wrong = get(port, "/callback?token=evil&state=nope").await;
        assert!(wrong.starts_with("HTTP/1.1 400") && !wrong.contains("close this tab"));
        let no_token = get(port, &format!("/callback?state={state}")).await;
        assert!(no_token.starts_with("HTTP/1.1 400"));

        let ok = get(port, &format!("/callback?token=a%2Bb.c&state={state}")).await;
        assert!(ok.starts_with("HTTP/1.1 200") && ok.contains("close this tab"));
        assert_eq!(task.await.unwrap().unwrap().expose_secret(), "a+b.c");
    }

    #[tokio::test]
    async fn an_error_callback_fails_the_login() {
        let l = BrowserLogin::bind().await.unwrap();
        let (port, state) = (l.port, l.state.clone());
        let task = tokio::spawn(l.wait(Duration::from_secs(10)));
        get(
            port,
            &format!("/callback?error=access_denied&state={state}"),
        )
        .await;
        assert!(matches!(
            task.await.unwrap(),
            Err(AuthError::Callback(m)) if m == "access_denied"
        ));
    }

    #[tokio::test]
    async fn times_out_when_nobody_calls_back() {
        let l = BrowserLogin::bind().await.unwrap();
        assert!(matches!(
            l.wait(Duration::from_millis(50)).await,
            Err(AuthError::TimedOut)
        ));
    }
}
