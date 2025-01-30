use std::{
    error::Error,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
    time::Duration,
};

use boot_time::Instant;
use log::warn;
use serde_json::Value;
use url::Url;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};

use super::{
    eventer::TokenEvent, expiry_instant, AccountId, AuthenticatorState, Config, TokenState,
    UREQ_TIMEOUT,
};

/// How often should we try making a request to an OAuth server for possibly-temporary transport
/// issues?
const RETRY_POST: u8 = 10;
/// How long to delay between each retry?
const RETRY_DELAY: u64 = 6;
/// What is the maximum HTTP request size, in bytes, we allow? We are less worried about malicious
/// actors than we are about malfunctioning systems. We thus set this to a far higher value than we
/// actually expect to see in practise: if any client connecting exceeds this, they've probably got
/// real problems!
const MAX_HTTP_REQUEST_SIZE: usize = 16 * 1024;

/// Handle an incoming (hopefully OAuth2) HTTP request.
fn request<T: Read + Write>(
    pstate: Arc<AuthenticatorState>,
    mut stream: T,
    is_https: bool,
) -> Result<(), Box<dyn Error>> {
    // This function is split into two halves. In the first half, we process the incoming HTTP
    // request: if there's a problem, it (mostly) means the request is mal-formed or stale, and
    // there's no effect on the tokenstate. In the second half we make a request to an OAuth
    // server: if there's a problem, we have to reset the tokenstate and force the user to make an
    // entirely fresh request.
    let uri = match parse_get(&mut stream, is_https) {
        Ok(x) => x,
        Err(_) => {
            // If someone couldn't even be bothered giving us a valid URI, it's unlikely this was a
            // genuine request that's worth reporting as an error.
            http_400(stream);
            return Ok(());
        }
    };

    // All valid requests (even those reporting an error!) should report back a valid "state" to
    // us, so fish that out of the URI and check that it matches a request we made.
    let state = match uri.query_pairs().find(|(k, _)| k == "state") {
        Some((_, state)) => state.into_owned(),
        None => {
            // As well as malformed OAuth queries this will also 404 for favicon.ico.
            http_404(stream);
            return Ok(());
        }
    };
    let mut ct_lk = pstate.ct_lock();
    let act_id = match ct_lk.act_id_matching_token_state(&state) {
        Some(x) => x,
        None => {
            drop(ct_lk);
            http_200(
                stream,
                "No pending token matches request state: request a fresh token",
            );
            return Ok(());
        }
    };

    // Now that we know which account has been matched we can check if the full URI requested
    // matched the redirect URI we expected for that account.
    let act = ct_lk.account(act_id);
    let expected_uri = act.redirect_uri(pstate.http_port, pstate.https_port)?;
    if expected_uri.scheme() != uri.scheme()
        || expected_uri.host_str() != uri.host_str()
        || expected_uri.port() != uri.port()
    {
        // If the redirect URI doesn't match then all we can do is 404.
        drop(ct_lk);
        http_404(stream);
        return Ok(());
    }

    // Did authentication fail?
    if let Some((_, reason)) = uri.query_pairs().find(|(k, _)| k == "error") {
        let act_id = ct_lk.tokenstate_replace(act_id, TokenState::Empty);
        let act_name = ct_lk.account(act_id).name.clone();
        let msg = format!(
            "Authentication for {} failed: {}",
            ct_lk.account(act_id).name,
            reason
        );
        drop(ct_lk);
        http_400(stream);
        pstate.notifier.notify_error(&pstate, act_name, msg)?;
        return Ok(());
    }

    // Fish out the code query.
    let code = match uri.query_pairs().find(|(k, _)| k == "code") {
        Some((_, code)) => code.to_string(),
        None => {
            // A request without a 'code' is broken. This seems very unlikely to happen and if it
            // does, would retrying our request from scratch improve anything?
            drop(ct_lk);
            http_400(stream);
            return Ok(());
        }
    };

    let code_verifier = match ct_lk.tokenstate(act_id) {
        TokenState::Pending {
            ref code_verifier, ..
        } => code_verifier.clone(),
        _ => unreachable!(),
    };
    let token_uri = act.token_uri.clone();
    let client_id = act.client_id.clone();
    let redirect_uri = act
        .redirect_uri(pstate.http_port, pstate.https_port)?
        .to_string();
    let mut pairs = vec![
        ("code", code.as_str()),
        ("client_id", client_id.as_str()),
        ("code_verifier", code_verifier.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
    ];
    let client_secret = act.client_secret.clone();
    if let Some(ref x) = client_secret {
        pairs.push(("client_secret", x));
    }

    // At this point we know we've got a sensible looking query, so we complete the HTTP request,
    // because we don't know how long we'll spend going through the rest of the OAuth process, and
    // we can notify the user another way than through their web browser.
    drop(ct_lk);
    http_200(
        stream,
        "pizauth processing authentication: you can safely close this page.",
    );

    // Try moderately hard to deal with temporary network errors and the like, but assume that any
    // request that partially makes a connection but does not then fully succeed is an error (since
    // we can't reuse authentication codes), and we'll have to start again entirely.
    let mut body = None;
    for _ in 0..RETRY_POST {
        match ureq::AgentBuilder::new()
            .timeout(UREQ_TIMEOUT)
            .build()
            .post(token_uri.as_str())
            .send_form(&pairs)
        {
            Ok(response) => match response.into_string() {
                Ok(s) => {
                    body = Some(s);
                    break;
                }
                Err(e) => {
                    fail(pstate, act_id, &e.to_string())?;
                    return Ok(());
                }
            },
            Err(ureq::Error::Status(code, response)) => {
                let reason = match response.into_string() {
                    Ok(r) => format!("{code:}: {r:}"),
                    Err(_) => format!("{code:}"),
                };
                fail(pstate, act_id, &reason)?;
                return Ok(());
            }
            Err(_) => (), // Temporary network error or the like
        }
        thread::sleep(Duration::from_secs(RETRY_DELAY));
    }
    let body = match body {
        Some(x) => x,
        None => {
            fail(pstate, act_id, &format!("couldn't connect to {token_uri:}"))?;
            return Ok(());
        }
    };

    let parsed = match serde_json::from_str::<Value>(&body) {
        Ok(x) => x,
        Err(e) => {
            fail(pstate, act_id, &format!("Invalid JSON: {e}"))?;
            return Ok(());
        }
    };

    let mut ct_lk = pstate.ct_lock();
    if !ct_lk.is_act_id_valid(act_id) {
        return Ok(());
    }

    if let Some(err_msg) = parsed["error"].as_str() {
        drop(ct_lk);
        fail(pstate, act_id, err_msg)?;
        return Ok(());
    }

    match (
        parsed["token_type"].as_str(),
        parsed["expires_in"].as_u64(),
        parsed["access_token"].as_str(),
        parsed["refresh_token"].as_str(),
    ) {
        (Some("Bearer"), Some(expires_in), Some(access_token), refresh_token) => {
            let now = Instant::now();
            let expiry = expiry_instant(&ct_lk, act_id, now, expires_in)?;
            let act_name = ct_lk.account(act_id).name.to_owned();
            ct_lk.tokenstate_replace(
                act_id,
                TokenState::Active {
                    access_token: access_token.to_owned(),
                    access_token_obtained: now,
                    access_token_expiry: expiry,
                    ongoing_refresh: false,
                    consecutive_refresh_fails: 0,
                    last_refresh_attempt: None,
                    refresh_token: refresh_token.map(|x| x.to_owned()),
                },
            );
            drop(ct_lk);
            pstate.refresher.notify_changes();
            pstate.eventer.token_event(act_name, TokenEvent::New);
        }
        _ => {
            drop(ct_lk);
            fail(pstate, act_id, "invalid response received")?;
        }
    }
    Ok(())
}

/// If a request to an OAuth server has failed then notify the user of that failure and mark the
/// tokenstate as [TokenState::Empty] unless the config has changed or the user has initiated a new
/// request while we've been trying (unsuccessfully) with the OAuth server.
fn fail(
    pstate: Arc<AuthenticatorState>,
    act_id: AccountId,
    msg: &str,
) -> Result<(), Box<dyn Error>> {
    let mut ct_lk = pstate.ct_lock();
    if ct_lk.is_act_id_valid(act_id) {
        // It's possible -- though admittedly unlikely -- that another thread has managed to grab
        // an `Active` token so we have to handle the possibility.
        let is_active = matches!(ct_lk.tokenstate(act_id), TokenState::Active { .. });
        let act_id = ct_lk.tokenstate_replace(act_id, TokenState::Empty);
        let act_name = ct_lk.account(act_id).name.clone();
        let msg = format!(
            "Authentication for {} failed: {msg:}",
            ct_lk.account(act_id).name
        );
        drop(ct_lk);
        pstate
            .notifier
            .notify_error(&pstate, act_name.clone(), msg)?;
        if is_active {
            pstate
                .eventer
                .token_event(act_name, TokenEvent::Invalidated);
        }
    }
    Ok(())
}

/// A very literal, and rather unforgiving, implementation of RFC2616 (HTTP/1.1), returning the URL
/// of GET requests: returns `Err` for anything else.
fn parse_get<T: Read + Write>(stream: &mut T, is_https: bool) -> Result<Url, Box<dyn Error>> {
    let mut rdr = BufReader::new(stream);
    let mut req_line = String::new();
    rdr.read_line(&mut req_line)?;
    let mut http_req_size = req_line.len();

    // First the request line:
    //  Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
    // where Method = "GET" and `SP` is a single space character.
    let req_line_sp = req_line.split(' ').collect::<Vec<_>>();
    if !matches!(req_line_sp.as_slice(), &["GET", _, _]) {
        return Err("Malformed HTTP request".into());
    }
    let path = req_line_sp[1];

    // Consume rest of HTTP request
    let mut req: Vec<String> = Vec::new();
    loop {
        if http_req_size >= MAX_HTTP_REQUEST_SIZE {
            return Err("HTTP request exceeds maximum permitted size".into());
        }
        let mut line = String::new();
        rdr.read_line(&mut line)?;
        if line.as_str().trim().is_empty() {
            break;
        }
        http_req_size += line.len();
        match line.chars().next() {
            Some(' ') | Some('\t') => {
                // Continuation of previous header
                match req.last_mut() {
                    Some(x) => {
                        // Not calling `trim_start` means that the two joined lines have at least
                        // one space|tab between them.
                        x.push_str(line.as_str().trim_end());
                    }
                    None => return Err("Malformed HTTP header".into()),
                }
            }
            _ => req.push(line.as_str().trim_end().to_owned()),
        }
    }

    // Find the host field.
    let mut host = None;
    for f in req {
        // Fields are a case insensitive name, followed by a colon, then zero or more tabs/spaces,
        // and then the value.
        if let Some(i) = f.as_str().find(':') {
            if f.as_str()[..i].eq_ignore_ascii_case("host") {
                if host.is_some() {
                    // Fields can be repeated, but that doesn't make sense for "host"
                    return Err("Repeated 'host' field in HTTP header".into());
                }
                let j: usize = f[i + ':'.len_utf8()..]
                    .chars()
                    .take_while(|c| *c == ' ' || *c == '\t')
                    .map(|c| c.len_utf8())
                    .sum();
                host = Some(f[i + ':'.len_utf8() + j..].to_string());
            }
        }
    }

    // If host is Some, use addressed port to select scheme (http / https)
    // This works, as no HTTPS request will arrive until here on the HTTP port and vice versa
    match host {
        Some(h) => Url::parse(&format!(
            "{}://{h:}{path:}",
            if is_https { "https" } else { "http" }
        ))
        .map_err(|e| format!("Invalid request URI: {e:}").into()),
        None => Err("No host field specified in HTTP request".into()),
    }
}

fn http_200<T: Read + Write>(mut stream: T, body: &str) {
    stream
        .write_all(
            format!("HTTP/1.1 200 OK\r\n\r\n<html><body><h2>{body}</h2></body></html>").as_bytes(),
        )
        .ok();
}

fn http_404<T: Read + Write>(mut stream: T) {
    stream.write_all(b"HTTP/1.1 404\r\n\r\n").ok();
}

fn http_400<T: Read + Write>(mut stream: T) {
    stream.write_all(b"HTTP/1.1 400\r\n\r\n").ok();
}

pub fn http_server_setup(conf: &Config) -> Result<Option<(u16, TcpListener)>, Box<dyn Error>> {
    // Bind TCP port for HTTP
    match &conf.http_listen {
        Some(http_listen) => {
            let listener = TcpListener::bind(http_listen)?;
            Ok(Some((listener.local_addr()?.port(), listener)))
        }
        None => Ok(None),
    }
}

pub fn http_server(
    pstate: Arc<AuthenticatorState>,
    listener: TcpListener,
) -> Result<(), Box<dyn Error>> {
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let pstate = Arc::clone(&pstate);
            thread::spawn(|| {
                if let Err(e) = request(pstate, stream, false) {
                    warn!("{e:}");
                }
            });
        }
    });
    Ok(())
}

pub fn https_server_setup(
    conf: &Config,
) -> Result<Option<(u16, TcpListener, CertifiedKey)>, Box<dyn Error>> {
    match &conf.https_listen {
        Some(https_listen) => {
            // Set a process wide default crypto provider.
            let _ = rustls::crypto::ring::default_provider().install_default();

            // Generate self-signed certificate
            let mut names = vec![
                String::from("localhost"),
                String::from("127.0.0.1"),
                String::from("::1"),
            ];
            if let Ok(x) = hostname::get() {
                if let Some(x) = x.to_str() {
                    names.push(String::from(x));
                }
            }
            let cert = generate_simple_self_signed(names)?;

            // Bind TCP port for HTTPS
            let listener = TcpListener::bind(https_listen)?;
            Ok(Some((listener.local_addr()?.port(), listener, cert)))
        }
        None => Ok(None),
    }
}

pub fn https_server(
    pstate: Arc<AuthenticatorState>,
    listener: TcpListener,
    cert: CertifiedKey,
) -> Result<(), Box<dyn Error>> {
    // Build TLS configuration.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.into()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())),
        )
        .map_err(|e| e.to_string())?;

    // Negotiate application layer protocols: Only HTTP/1.1 is allowed
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            // generate a new TLS connection
            let conn = rustls::ServerConnection::new(Arc::new(server_config.clone()));
            if let Err(e) = conn {
                warn!("{e:}");
                continue;
            }
            let mut conn = conn.unwrap();

            let pstate = Arc::clone(&pstate);
            thread::spawn(move || {
                // convert TCP stream into TLS stream
                let stream = rustls::Stream::new(&mut conn, &mut stream);
                if let Err(e) = request(pstate, stream, true) {
                    warn!("{e:}");
                }
            });
        }
    });
    Ok(())
}
