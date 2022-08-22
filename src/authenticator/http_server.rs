use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use log::warn;
use url::Url;

use super::{AuthenticatorState, TokenState};

pub fn http_server_setup() -> Result<(u16, TcpListener), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok((listener.local_addr()?.port(), listener))
}

fn request(pstate: Arc<AuthenticatorState>, stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut rdr = BufReader::new(&stream);
    let mut line = String::new();
    rdr.read_line(&mut line).unwrap();

    match line.split(' ').collect::<Vec<_>>().as_slice() {
        &["GET", path, ver] if ver.starts_with("HTTP/1") && path.starts_with("/?") => {
            // We fudge a URL so that we can use the Url library's query parser.
            let url = {
                let mut fudge = String::from("http://localhost");
                fudge.push_str(path);
                Url::parse(&fudge)?
            };

            // Check the state we receive matches a pending request.
            dbg!(url.query_pairs().collect::<Vec<_>>());
            let state = match url.query_pairs().find(|(k, _)| k == "state") {
                Some((_, v)) => v,
                None => {
                    http_error(stream);
                    return Err(format!("Invalid request '{line:}'").into());
                }
            };
            let state = urlencoding::decode_binary(state.as_bytes()).into_owned();
            let ct_lk = pstate.conf_tokens.lock().unwrap();
            let act_name = match ct_lk.1.iter().find(|(_, v)|matches!(*v, &TokenState::Pending { state: s, .. } if s == state.as_slice())) {
                Some((k, _)) => k.to_owned(),
                None => {
                    http_error_msg(
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
                    http_error(stream);
                    return Ok(());
                }
            };

            let code = match url.query_pairs().find(|(k, _)| k == "code") {
                Some((_, v)) => v,
                None => {
                    http_error(stream);
                    return Err(format!("Invalid request '{line:}'").into());
                }
            }
            .into_owned();

            let token_uri = act.token_uri.clone();
            let client_id = act.client_id.clone();
            let client_secret = act.client_secret.clone();
            let redirect_uri = act.redirect_uri(pstate.http_port);
            let pairs = [
                ("code", code.as_str()),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("grant_type", "authorization_code"),
            ];

            // Make sure that we don't hold the lock while performing a network request.
            drop(ct_lk);
            http_success_msg(stream, "pizauth successfully received authentication code");
            let body = ureq::post(token_uri.as_str())
                .send_form(&pairs)?
                .into_string()?;
            let parsed = json::parse(&body)?;

            match (
                parsed["token_type"].as_str(),
                parsed["expires_in"].as_u64(),
                parsed["access_token"].as_str(),
                parsed["refresh_token"].as_str(),
            ) {
                (Some(token_type), Some(expires_in), Some(access_token), refresh_token)
                    if token_type == "Bearer" =>
                {
                    let mut ct_lk = pstate.conf_tokens.lock().unwrap();
                    if let Some(e) = ct_lk.1.get_mut(&act_name) {
                        *e = TokenState::Active {
                            access_token: access_token.to_owned(),
                            expires_in,
                            refresh_token: refresh_token.map(|x| x.to_owned()),
                        };
                    }
                    drop(ct_lk);
                }
                _ => todo!(),
            }
        }
        ["GET", "/favicon.ico", _] => (),
        _ => {
            http_error(stream);
            return Err(format!("Invalid request '{line:}'").into());
        }
    }

    Ok(())
}

fn http_error(mut stream: TcpStream) {
    stream.write_all(b"HTTP/1.1 400").ok();
}

fn http_error_msg(mut stream: TcpStream, msg: &str) {
    stream
        .write_all(
            format!("HTTP/1.1 200 OK\r\n\r\n<html><body><h2>{msg}</h2></body></html>").as_bytes(),
        )
        .ok();
}

fn http_success_msg(mut stream: TcpStream, msg: &str) {
    stream
        .write_all(
            format!("HTTP/1.1 200 OK\r\n\r\n<html><body><h2>{msg}</h2></body></html>").as_bytes(),
        )
        .ok();
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
