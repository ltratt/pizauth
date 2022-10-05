#![allow(clippy::derive_partial_eq_without_eq)]

mod config;
mod config_ast;
mod server;
mod user_sender;

use std::{
    env::{self, current_exe},
    fs,
    os::unix::net::UnixStream,
    path::PathBuf,
    process,
};

use getopts::Options;
use log::error;
use nix::unistd::daemon;
#[cfg(target_os = "openbsd")]
use pledge::pledge;
use server::sock_path;

use config::Config;
use user_sender::show_token;

/// Name of cache directory within $XDG_DATA_HOME.
const PIZAUTH_CACHE_LEAF: &str = "pizauth";
/// Name of socket file within $XDG_DATA_HOME/PIZAUTH_CACHE_LEAF.
const PIZAUTH_CACHE_SOCK_LEAF: &str = "pizauth.sock";
/// Name of `pizauth.conf` file relative to $XDG_CONFIG_HOME.
const PIZAUTH_CONF_LEAF: &str = "pizauth.conf";

fn progname() -> String {
    match current_exe() {
        Ok(p) => p
            .file_name()
            .map(|x| x.to_str().unwrap_or("pizauth"))
            .unwrap_or("pizauth")
            .to_owned(),
        Err(_) => "pizauth".to_owned(),
    }
}

/// Exit with a fatal error: only to be called before the log crate is setup.
fn fatal(msg: &str) -> ! {
    eprintln!("{msg:}");
    process::exit(1);
}

/// Print out program usage then exit. This function must not be called after daemonisation.
fn usage() -> ! {
    let pn = progname();
    eprintln!(
        "Usage:\n  {pn:} refresh [-u] <account>\n  {pn:} reload\n  {pn:} server [-c <config-path>] [-dv]\n  {pn:} show [-v] <account>\n  {pn:} shutdown"
    );
    process::exit(1)
}

fn cache_path() -> PathBuf {
    let mut p = PathBuf::new();
    match env::var_os("XDG_DATA_HOME") {
        Some(s) => p.push(s),
        None => match env::var_os("HOME") {
            Some(s) => {
                p.push(s);
                p.push(".cache")
            }
            None => fatal("Neither $DATA_HOME or $HOME set"),
        },
    }
    p.push(PIZAUTH_CACHE_LEAF);
    fs::create_dir_all(&p).unwrap_or_else(|e| fatal(&format!("Can't create cache dir: {}", e)));
    p
}

fn conf_path(matches: &getopts::Matches) -> PathBuf {
    match matches.opt_str("c") {
        Some(p) => PathBuf::from(&p),
        None => {
            let mut p = PathBuf::new();
            match env::var_os("XDG_CONFIG_HOME") {
                Some(s) => p.push(s),
                None => match env::var_os("HOME") {
                    Some(s) => {
                        p.push(s);
                        p.push(".config")
                    }
                    None => fatal("Neither $XDG_CONFIG_HOME or $HOME set"),
                },
            }
            p.push(PIZAUTH_CONF_LEAF);
            if !p.is_file() {
                fatal(&format!(
                    "No config file found at {}",
                    p.to_str().unwrap_or("pizauth.conf")
                ));
            }
            p
        }
    }
}

fn main() {
    // Generic pledge support for all pizauth's commands. Note that the server later restricts
    // these further.
    #[cfg(target_os = "openbsd")]
    pledge(
        "stdio rpath wpath cpath tmppath inet fattr flock unix dns proc ps exec unveil",
        None,
    )
    .unwrap();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }
    let mut opts = Options::new();
    opts.optflag("h", "help", "")
        .optflagmulti("v", "verbose", "");

    let cache_path = cache_path();
    match args[1].as_str() {
        "refresh" => {
            let matches = opts
                .optflag("u", "", "Don't display authorisation URLs.")
                .parse(&args[2..])
                .unwrap_or_else(|_| usage());
            if matches.opt_present("h") || matches.free.len() != 1 {
                usage();
            }
            stderrlog::new()
                .module(module_path!())
                .verbosity(matches.opt_count("v"))
                .init()
                .unwrap();
            let with_url = !matches.opt_present("u");
            if let Err(e) = user_sender::refresh(&cache_path, &matches.free[0], with_url) {
                error!("{e:}");
                process::exit(1);
            }
        }
        "reload" => {
            let matches = opts.parse(&args[2..]).unwrap_or_else(|_| usage());
            if matches.opt_present("h") || !matches.free.is_empty() {
                usage();
            }
            stderrlog::new()
                .module(module_path!())
                .verbosity(matches.opt_count("v"))
                .init()
                .unwrap();
            if let Err(e) = user_sender::reload(&cache_path) {
                error!("{e:}");
                process::exit(1);
            }
        }
        "server" => {
            let matches = opts
                .optflagopt("c", "config", "Path to pizauth.conf.", "<conf-path>")
                .optflag("d", "", "Don't detach from the terminal.")
                .parse(&args[2..])
                .unwrap_or_else(|_| usage());
            if matches.opt_present("h") || !matches.free.is_empty() {
                usage();
            }

            let sock_path = sock_path(&cache_path);
            if sock_path.exists() {
                // Is an existing authenticator running?
                if UnixStream::connect(&sock_path).is_ok() {
                    eprintln!("pizauth authenticator already running");
                    process::exit(1);
                }
                fs::remove_file(&sock_path).ok();
            }

            let conf_path = conf_path(&matches);
            let conf = Config::from_path(&conf_path).unwrap_or_else(|m| fatal(&m));

            let daemonise = !matches.opt_present("d");
            if daemonise {
                let formatter = syslog::Formatter3164 {
                    process: progname(),
                    ..Default::default()
                };
                let logger = syslog::unix(formatter)
                    .unwrap_or_else(|e| fatal(&format!("Cannot connect to syslog: {e:}")));
                let levelfilter = match matches.opt_count("v") {
                    0 => log::LevelFilter::Error,
                    1 => log::LevelFilter::Warn,
                    2 => log::LevelFilter::Info,
                    3 => log::LevelFilter::Debug,
                    _ => log::LevelFilter::Trace,
                };
                log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
                    .map(|()| log::set_max_level(levelfilter))
                    .unwrap_or_else(|e| fatal(&format!("Cannot set logger: {e:}")));
                daemon(true, false).unwrap_or_else(|e| fatal(&format!("Cannot daemonise: {e:}")));
            } else {
                stderrlog::new()
                    .module(module_path!())
                    .verbosity(matches.opt_count("v"))
                    .init()
                    .unwrap();
            }
            if let Err(e) = server::server(conf_path, conf, cache_path.as_path()) {
                error!("{e:}");
                process::exit(1);
            }
        }
        "show" => {
            let matches = opts
                .optflag("u", "", "Don't display authorisation URLs.")
                .parse(&args[2..])
                .unwrap_or_else(|_| usage());
            if matches.opt_present("h") {
                usage();
            }
            if matches.free.len() != 1 {
                usage();
            }
            stderrlog::new()
                .module(module_path!())
                .verbosity(matches.opt_count("v"))
                .init()
                .unwrap();
            let account = matches.free[0].as_str();
            if let Err(e) = show_token(cache_path.as_path(), account, !matches.opt_present("u")) {
                error!("{e:}");
                process::exit(1);
            }
        }
        "shutdown" => {
            let matches = opts.parse(&args[2..]).unwrap_or_else(|_| usage());
            if matches.opt_present("h") || !matches.free.is_empty() {
                usage();
            }
            stderrlog::new()
                .module(module_path!())
                .verbosity(matches.opt_count("v"))
                .init()
                .unwrap();
            if let Err(e) = user_sender::shutdown(&cache_path) {
                error!("{e:}");
                process::exit(1);
            }
        }
        _ => usage(),
    }
}
