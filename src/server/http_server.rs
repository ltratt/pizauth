use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use log::{info, warn};
use url::Url;

use super::{refresher::update_refresher, AuthenticatorState, TokenState};

/// Handle an incoming (hopefully OAuth2) HTTP request.
fn request(pstate: Arc<AuthenticatorState>, mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let uri = match parse_get(&mut stream) {
        Ok(x) => x,
        Err(e) => {
            http_400(stream);
            return Err(e);
        }
    };

    // Ideally we'd first validate the URL we've been given to check it's in the format we
    // expected, but we don't yet know which account this query might relate to, so we can't quite
    // do that.

    // A valid query must have `code` and `state` parts to the query.
    let (code, state) = match (
        uri.query_pairs().find(|(k, _)| k == "code"),
        uri.query_pairs().find(|(k, _)| k == "state"),
    ) {
        (Some((_, code)), Some((_, state))) => (code.into_owned(), state),
        _ => {
            // As well as malformed OAuth queries this will 404 for favicon.ico
            http_404(stream);
            return Ok(());
        }
    };

    // Validate the state.
    let state = urlencoding::decode_binary(state.as_bytes()).into_owned();
    let ct_lk = pstate.conf_tokens.lock().unwrap();
    let act_name =
        match ct_lk.1.iter().find(
            |(_, v)| matches!(*v, &TokenState::Pending { state: s, .. } if s == state.as_slice()),
        ) {
            Some((k, _)) => k.to_owned(),
            None => {
                drop(ct_lk);
                http_200(
                    stream,
                    "No pending token matches request state: request a fresh token",
                );
                return Ok(());
            }
        };

    let act = match ct_lk.0.accounts.get(&act_name) {
        Some(x) => x,
        None => {
            // Account has been deleted on config reload.
            drop(ct_lk);
            http_200(stream, "No such account");
            return Ok(());
        }
    };

    // Now that we know which account has been matched we can (finally!) check if the full URI
    // requested matched the redirect URI we expected for that account.
    let expected_uri = act.redirect_uri(pstate.http_port)?;
    if expected_uri.scheme() != uri.scheme()
        || expected_uri.host_str() != uri.host_str()
        || expected_uri.port() != uri.port()
    {
        drop(ct_lk);
        http_404(stream);
        return Err("Incorrect redirect URI".into());
    }

    let token_uri = act.token_uri.clone();
    let client_id = act.client_id.clone();
    let client_secret = act.client_secret.clone();
    let redirect_uri = act.redirect_uri(pstate.http_port)?.to_string();
    let pairs = [
        ("code", code.as_str()),
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
    ];

    drop(ct_lk);
    let body = ureq::post(token_uri.as_str())
        .send_form(&pairs)?
        .into_string()?;
    let parsed = json::parse(&body)?;

    if parsed["error"].as_str().is_some() {
        // Obtaining a token failed. We could just try with the same authentication data again, but
        // we can't know for sure if the other server might have cached something (e.g. the request
        // state) which will cause it to fail. The safest thing is thus to force an entirely new
        // authentication request to be generated next time.
        let mut ct_lk = pstate.conf_tokens.lock().unwrap();
        if let Some(e) = ct_lk.1.get_mut(&act_name) {
            // Since we released and regained the lock, the TokenState might have changed in
            // another thread: if it's changed from what it was above, we don't do anything.
            if matches!(*e, TokenState::Pending { state: s, .. } if s == state.as_slice()) {
                *e = TokenState::Empty;
            }
        }
        return Err("Failed to obtain token for {act_name:}".into());
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
            let expiry = match refreshed_at.checked_add(Duration::from_secs(expires_in)) {
                Some(x) => x,
                None => {
                    http_400(stream);
                    return Err("Can't represent expiry".into());
                }
            };
            let mut ct_lk = pstate.conf_tokens.lock().unwrap();
            if let Some(e) = ct_lk.1.get_mut(&act_name) {
                info!(
                    "New token for {act_name:} (token valid for {} seconds)",
                    expires_in
                );
                *e = TokenState::Active {
                    access_token: access_token.to_owned(),
                    expiry,
                    refreshed_at,
                    refresh_token: refresh_token.map(|x| x.to_owned()),
                };
                drop(ct_lk);
                http_200(stream, "pizauth successfully received authentication code");
                update_refresher(pstate);
            }
        }
        _ => {
            http_400(stream);
            return Err("Invalid request".into());
        }
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

pub fn http_server_setup() -> Result<(u16, TcpListener), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
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
