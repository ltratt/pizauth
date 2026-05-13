use std::{
    collections::HashMap,
    ffi::OsStr,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;
use url::{form_urlencoded, Url};

const ACCOUNT: &str = "test_account";
const CLIENT_ID: &str = "test_client_id";
const CLIENT_SECRET: &str = "test_secret";
const CODE: &str = "test_code";
const ACCESS_TOKEN: &str = "test_access_token";
const REFRESH_TOKEN: &str = "test_refresh_token";

struct PizauthServer {
    child: Child,
    xdg_dir: PathBuf,
}

impl PizauthServer {
    fn start(cwd: &Path, xdg_dir: &Path, configp: &Path, readyp: &Path) -> Self {
        let child = pizauth_cmd(xdg_dir, ["server", "-d", "-c"])
            .arg(configp)
            .current_dir(cwd)
            .spawn()
            .unwrap();
        // There's no better way than just waiting until `readyp` appears.
        let timeout = Instant::now() + Duration::from_secs(3);
        while Instant::now() < timeout && !readyp.exists() {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(readyp.exists());
        Self {
            child,
            xdg_dir: xdg_dir.to_owned(),
        }
    }
}

impl Drop for PizauthServer {
    fn drop(&mut self) {
        let cmd = pizauth_cmd(&self.xdg_dir, ["shutdown"]).output();
        assert!(cmd.unwrap().status.success());
        // Currently we kill the main server with SIGTERM, so this `wait` would return an error if
        // we checked!
        let _ = self.child.wait();
    }
}

struct OAuthServer {
    addr: String,
    thread: Option<thread::JoinHandle<()>>,
}

impl OAuthServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let expected_redirect_uri = Arc::new(Mutex::new(None));

        let thread = {
            let expected_redirect_uri = Arc::clone(&expected_redirect_uri);
            thread::spawn(move || {
                for _ in 0..2 {
                    let (stream, _) = listener.accept().unwrap();
                    handle_oauth_request(stream, &expected_redirect_uri);
                }
            })
        };

        Self {
            addr,
            thread: Some(thread),
        }
    }

    fn auth_uri(&self) -> String {
        format!("http://{}/authorize", self.addr)
    }

    fn token_uri(&self) -> String {
        format!("http://{}/token", self.addr)
    }

    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn pizauth_config(oauths: &OAuthServer) -> String {
    let auth_uri = oauths.auth_uri();
    let token_uri = oauths.token_uri();
    format!(
        r#"
http_listen = "127.0.0.1:0";
https_listen = none;
startup_cmd = "touch ready";

account "{ACCOUNT}" {{
    auth_uri = "{auth_uri}";
    token_uri = "{token_uri}";
    client_id = "{CLIENT_ID}";
    client_secret = "{CLIENT_SECRET}";
}}
"#
    )
}

fn pending_auth_url(output: &Output) -> Url {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let marker = "Access token unavailable until authorised with URL ";
    let url = stderr.split(marker).nth(1).unwrap().trim();
    Url::parse(url).unwrap()
}

fn pizauth_cmd<I, S>(xdg_dir: &Path, args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pizauth"));
    cmd.env("XDG_RUNTIME_DIR", xdg_dir)
        .env("SHELL", "/bin/sh")
        .args(args);
    cmd
}

fn handle_oauth_request(stream: TcpStream, expected_redirect_uri: &Mutex<Option<String>>) {
    let request = HttpRequest::read(stream);
    let path = request.target.split('?').next().unwrap();
    match (request.method.as_str(), path) {
        ("GET", "/authorize") => {
            let url = Url::parse(&format!("http://localhost{}", request.target)).unwrap();
            let params = url.query_pairs().collect::<HashMap<_, _>>();
            assert_eq!(
                params.get("access_type").map(|x| x.as_ref()),
                Some("offline")
            );
            assert_eq!(params.get("client_id").map(|x| x.as_ref()), Some(CLIENT_ID));
            assert_eq!(
                params.get("code_challenge_method").map(|x| x.as_ref()),
                Some("S256")
            );
            assert!(params.contains_key("code_challenge"));
            assert_eq!(
                params.get("response_type").map(|x| x.as_ref()),
                Some("code")
            );

            let redirect_uri = params.get("redirect_uri").unwrap().to_string();
            let state = params.get("state").unwrap().to_string();
            *expected_redirect_uri.lock().unwrap() = Some(redirect_uri.clone());

            let mut redirect = Url::parse(&redirect_uri).unwrap();
            redirect.query_pairs_mut().append_pair("code", CODE);
            redirect.query_pairs_mut().append_pair("state", &state);
            request.respond(
                302,
                &[("Location", redirect.as_str()), ("Content-Length", "0")],
                "",
            );
        }
        ("POST", "/token") => {
            let params = form_urlencoded::parse(request.body.as_bytes()).collect::<HashMap<_, _>>();
            assert_eq!(
                params.get("grant_type").map(|x| x.as_ref()),
                Some("authorization_code")
            );
            assert_eq!(params.get("code").map(|x| x.as_ref()), Some(CODE));
            assert_eq!(params.get("client_id").map(|x| x.as_ref()), Some(CLIENT_ID));
            assert_eq!(
                params.get("client_secret").map(|x| x.as_ref()),
                Some(CLIENT_SECRET)
            );
            assert!(params.contains_key("code_verifier"));
            assert_eq!(
                params.get("redirect_uri").map(|x| x.as_ref()),
                expected_redirect_uri.lock().unwrap().as_deref()
            );

            request.respond(
                200,
                &[("Content-Type", "application/json")],
                &format!(
                    r#"{{
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "access_token": "{ACCESS_TOKEN}",
                        "refresh_token": "{REFRESH_TOKEN}"
                    }}"#
                ),
            );
        }
        _ => panic!(
            "unexpected OAuth request: {} {}",
            request.method, request.target
        ),
    }
}

struct HttpRequest {
    stream: TcpStream,
    method: String,
    target: String,
    body: String,
}

impl HttpRequest {
    fn read(stream: TcpStream) -> Self {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut parts = request_line.trim_end().split(' ');
        let method = parts.next().unwrap().to_owned();
        let target = parts.next().unwrap().to_owned();

        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.to_ascii_lowercase(), value.trim_start().to_owned());
            }
        }

        let content_length = headers
            .get("content-length")
            .map_or(0, |x| x.parse::<usize>().unwrap());
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).unwrap();
        let stream = reader.into_inner();

        Self {
            stream,
            method,
            target,
            body: String::from_utf8(body).unwrap(),
        }
    }

    fn respond(mut self, status: u16, headers: &[(&str, &str)], body: &str) {
        write!(self.stream, "HTTP/1.1 {status}\r\n").unwrap();
        for (name, value) in headers {
            write!(self.stream, "{name}: {value}\r\n").unwrap();
        }
        write!(self.stream, "Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    }
}

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
}

fn http_get(url: &Url) -> HttpResponse {
    let host = url.host_str().unwrap();
    let port = url.port_or_known_default().unwrap();
    let mut stream = TcpStream::connect((host, port)).unwrap();
    let target = match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => url.path().to_owned(),
    };
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).unwrap();
    let status = status_line
        .split(' ')
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim_start().to_owned());
        }
    }
    HttpResponse { status, headers }
}

#[test]
fn basic_request_token() {
    let dir = TempDir::new().unwrap();
    let readyp = dir.path().join("ready");
    let xdg_dir = dir.path().join("runtime");
    let configp = dir.path().join("pizauth.conf");

    let mut oauths = OAuthServer::start();
    fs::write(&configp, pizauth_config(&oauths)).unwrap();

    let _pizauths = PizauthServer::start(dir.path(), &xdg_dir, &configp, &readyp);

    let show = pizauth_cmd(&xdg_dir, ["show", ACCOUNT]).output().unwrap();
    assert!(!show.status.success());
    let auth_url = pending_auth_url(&show);

    let auth_response = http_get(&auth_url);
    assert_eq!(auth_response.status, 302);
    let redirect_url = auth_response
        .headers
        .get("location")
        .unwrap()
        .parse::<Url>()
        .unwrap();

    let callback_response = http_get(&redirect_url);
    assert_eq!(callback_response.status, 200);
    oauths.join();

    let show = pizauth_cmd(&xdg_dir, ["show", ACCOUNT]).output().unwrap();
    assert!(
        show.status.success(),
        "show failed: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    assert_eq!(
        String::from_utf8(show.stdout).unwrap(),
        format!("{ACCESS_TOKEN}\n")
    );
}
