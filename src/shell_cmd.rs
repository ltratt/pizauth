use std::{env, error::Error, process::Command, time::Duration};

use wait_timeout::ChildExt;

/// Run the string `cmd` as `$SHELL -c '<cmd>'` with the environment `env`. If the command runs for
/// longer than `timeout`, it will be sent `SIGKILL`. If any error occurs, `Err` is returned with a
/// string suitable for reporting to the user.
pub fn shell_cmd<const T: usize>(
    cmd: &str,
    env: [(&str, &str); T],
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let s = env::var("SHELL").map_err(|e| format!("{e:}"))?;
    let mut child = Command::new(s)
        .envs(env)
        .args(["-c", cmd])
        .spawn()
        .map_err(|e| format!("Couldn't execute '{cmd:}': {e:}"))?;
    let s = child
        .wait_timeout(timeout)
        .map_err(|e| format!("Waiting on '{cmd:}' failed: {e:}"))?;
    match s {
        Some(status) if !status.success() => Err(format!(
            "'{cmd:}' returned {}",
            status
                .code()
                .map(|x| x.to_string())
                .unwrap_or_else(|| "<Unknown exit code".to_string())
        )
        .into()),
        None => {
            child.kill().ok();
            child.wait().ok();
            Err(format!("'{cmd:}' exceeded timeout").into())
        }
        _ => Ok(()),
    }
}
