use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use log::warn;
use url::Url;

use super::{expiry_instant, AuthenticatorState, CTGuardAccountId, Config, TokenState};

/// How often should we try making a request to an OAuth server for possibly-temporary transport
/// issues?
const RETRY_POST: u8 = 10;
/// How long to delay between each retry?
const RETRY_DELAY: u64 = 6;

/// Handle an incoming (hopefully OAuth2) HTTP request.
fn request(pstate: Arc<AuthenticatorState>, mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    // This function is split into two halves. In the first half, we process the incoming HTTP
    // request: if there's a problem, it (mostly) means the request is mal-formed or stale, and
    // there's no effect on the tokenstate. In the second half we make a request to an OAuth
    // server: if there's a problem, we have to reset the tokenstate and force the user to make an
    // entirely fresh request.

    let uri = match parse_get(&mut stream) {
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
    let act = ct_lk.account(&act_id);
    let expected_uri = act.redirect_uri(pstate.http_port)?;
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
        let act_name = ct_lk.account(&act_id).name.clone();
        let msg = format!(
            "Authentication for {} failed: {}",
            ct_lk.account(&act_id).name,
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

    let code_verifier = match ct_lk.tokenstate(&act_id) {
        TokenState::Pending {
            ref code_verifier, ..
        } => code_verifier.clone(),
        _ => unreachable!(),
    };
    let token_uri = act.token_uri.clone();
    let client_id = act.client_id.clone();
    let redirect_uri = act.redirect_uri(pstate.http_port)?.to_string();
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
        match ureq::post(token_uri.as_str()).send_form(&pairs) {
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
    let parsed = match body {
        Some(x) => json::parse(&x)?,
        None => {
            fail(pstate, act_id, &format!("couldn't connect to {token_uri:}"))?;
            return Ok(());
        }
    };

    let mut ct_lk = pstate.ct_lock();
    let act_id = match ct_lk.validate_act_id(act_id) {
        Some(x) => x,
        None => return Ok(()),
    };

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
        (Some(token_type), Some(expires_in), Some(access_token), refresh_token)
            if token_type == "Bearer" =>
        {
            let refreshed_at = Instant::now();
            let expiry = expiry_instant(&ct_lk, &act_id, refreshed_at, expires_in)?;
            ct_lk.tokenstate_replace(
                act_id,
                TokenState::Active {
                    access_token: access_token.to_owned(),
                    expiry,
                    refreshed_at,
                    last_refresh_attempt: None,
                    refresh_token: refresh_token.map(|x| x.to_owned()),
                },
            );
            drop(ct_lk);
            pstate.refresher.notify_changes();
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
    act_id: CTGuardAccountId,
    msg: &str,
) -> Result<(), Box<dyn Error>> {
    let mut ct_lk = pstate.ct_lock();
    if let Some(act_id) = ct_lk.validate_act_id(act_id) {
        let act_id = ct_lk.tokenstate_replace(act_id, TokenState::Empty);
        let act_name = ct_lk.account(&act_id).name.clone();
        let msg = format!(
            "Authentication for {} failed: {msg:}",
            ct_lk.account(&act_id).name
        );
        drop(ct_lk);
        pstate.notifier.notify_error(&pstate, act_name, msg)?;
    }
    Ok(())
}

/// A very literal, and rather unforgiving, implementation of RFC2616 (HTTP/1.1), returning the URL
/// of GET requests: returns `Err` for anything else.
fn parse_get(stream: &mut TcpStream) -> Result<Url, Box<dyn Error>> {
    let mut rdr = BufReader::new(stream);
    let mut req_line = String::new();
    rdr.read_line(&mut req_line)?;

    // First the request line:
    //   Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
    // where Method = "GET" and `SP` is a single space character.
    let req_line_sp = req_line.split(' ').collect::<Vec<_>>();
    if !matches!(req_line_sp.as_slice(), &["GET", _, _]) {
        return Err("Malformed HTTP request".into());
    }
    let path = req_line_sp[1];

    // Consume rest of HTTP request
    let mut req: Vec<String> = Vec::new();
    loop {
        let mut line = String::new();
        rdr.read_line(&mut line)?;
        if line.as_str().trim().is_empty() {
            break;
        }
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

    match host {
        Some(h) => Url::parse(&format!("http://{h:}{path:}"))
            .map_err(|e| format!("Invalid request URI: {e:}").into()),
        None => Err("No host field specified in HTTP request".into()),
    }
}

fn http_200(mut stream: TcpStream, body: &str) {
    stream
        .write_all(
            format!("HTTP/1.1 200 OK\r\n\r\n<html><body><h2>{body}</h2></body></html>").as_bytes(),
        )
        .ok();
}

fn http_404(mut stream: TcpStream) {
    stream.write_all(b"HTTP/1.1 404").ok();
}

fn http_400(mut stream: TcpStream) {
    stream.write_all(b"HTTP/1.1 400").ok();
}

pub fn http_server_setup(conf: &Config) -> Result<(u16, TcpListener), Box<dyn Error>> {
    let listener = TcpListener::bind(&conf.http_listen)?;
    Ok((listener.local_addr()?.port(), listener))
}

pub fn http_server(
    pstate: Arc<AuthenticatorState>,
    listener: TcpListener,
) -> Result<(), Box<dyn Error>> {
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let pstate = Arc::clone(&pstate);
            thread::spawn(|| {
                if let Err(e) = request(pstate, stream) {
                    warn!("{e:}");
                }
            });
        }
    });
    Ok(())
}
