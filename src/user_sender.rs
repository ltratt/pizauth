use std::{
    error::Error,
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::Path,
};

use crate::server::sock_path;

pub fn refresh(cache_path: &Path, account: &str, with_url: bool) -> Result<(), Box<dyn Error>> {
    let sock_path = sock_path(cache_path);
    let with_url = if with_url { "withurl" } else { "withouturl" };
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|_| "pizauth authenticator not running or not responding")?;
    stream
        .write_all(format!("refresh {with_url:} {account:}").as_bytes())
        .map_err(|_| "Socket not writeable")?;
    stream.shutdown(Shutdown::Write)?;

    let mut rtn = String::new();
    stream.read_to_string(&mut rtn)?;
    match rtn.splitn(2, ':').collect::<Vec<_>>()[..] {
        ["pending", url] => {
            Err(format!("Access token unavailable until authorised with URL {url:}").into())
        }
        ["scheduled", ""] => Ok(()),
        ["error", cause] => Err(cause.into()),
        _ => Err(format!("Malformed response '{rtn:}'").into()),
    }
}

pub fn reload(cache_path: &Path) -> Result<(), Box<dyn Error>> {
    let sock_path = sock_path(cache_path);
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|_| "pizauth authenticator not running or not responding")?;
    stream
        .write_all(b"reload")
        .map_err(|_| "Socket not writeable")?;
    stream.shutdown(Shutdown::Write)?;

    let mut rtn = String::new();
    stream.read_to_string(&mut rtn)?;
    match rtn.splitn(2, ':').collect::<Vec<_>>()[..] {
        ["ok", ""] => Ok(()),
        ["error", cause] => Err(cause.into()),
        _ => Err(format!("Malformed response '{rtn:}'").into()),
    }
}

pub fn show_token(cache_path: &Path, account: &str, with_url: bool) -> Result<(), Box<dyn Error>> {
    let sock_path = sock_path(cache_path);
    let with_url = if with_url { "withurl" } else { "withouturl" };
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|_| "pizauth authenticator not running or not responding")?;
    stream
        .write_all(format!("showtoken {with_url:} {account:}").as_bytes())
        .map_err(|_| "Socket not writeable")?;
    stream.shutdown(Shutdown::Write)?;

    let mut rtn = String::new();
    stream.read_to_string(&mut rtn)?;
    match rtn.splitn(2, ':').collect::<Vec<_>>()[..] {
        ["access_token", x] => {
            println!("{x:}");
            Ok(())
        }
        ["pending", url] => {
            Err(format!("Access token unavailable until authorised with URL {url:}").into())
        }
        ["error", cause] => Err(cause.into()),
        _ => Err(format!("Malformed response '{rtn:}'").into()),
    }
}

pub fn shutdown(cache_path: &Path) -> Result<(), Box<dyn Error>> {
    let sock_path = sock_path(cache_path);
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|_| "pizauth authenticator not running or not responding")?;
    stream
        .write_all(b"shutdown")
        .map_err(|_| "Socket not writeable")?;
    Ok(())
}
