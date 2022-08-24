use std::{
    error::Error,
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::Path,
};

use crate::{config::Config, server::sock_path};

pub fn show_token(_conf: Config, cache_path: &Path, account: &str) -> Result<(), Box<dyn Error>> {
    let sock_path = sock_path(cache_path);
    let mut stream = UnixStream::connect(&sock_path)
        .map_err(|_| "pizauth authenticator not running or not responding")?;
    stream
        .write_all(format!("showtoken {account:}").as_bytes())
        .map_err(|_| "Socket not writeable")?;
    stream.shutdown(Shutdown::Write)?;
    let mut rtn = String::new();
    stream.read_to_string(&mut rtn)?;
    match rtn.splitn(2, ':').collect::<Vec<_>>()[..] {
        ["access_token", x] => {
            println!("{x:}");
            Ok(())
        }
        ["pending", ""] => Err("Token unavailable until authentication complete".into()),
        ["error", cause] => Err(cause.into()),
        _ => Err(format!("Malformed response '{rtn:}'").into()),
    }
}
