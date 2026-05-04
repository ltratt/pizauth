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
    match env::var("SHELL") {
        Ok(s) => match Command::new(s).envs(env).args(["-c", cmd]).spawn() {
            Ok(mut child) => match child.wait_timeout(timeout) {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Err(format!(
                            "'{cmd:}' returned {}",
                            status
                                .code()
                                .map(|x| x.to_string())
                                .unwrap_or_else(|| "<Unknown exit code".to_string())
                        )
                        .into());
                    }
                }
                Ok(None) => {
                    child.kill().ok();
                    child.wait().ok();
                    return Err(format!("'{cmd:}' exceeded timeout").into());
                }
                Err(e) => return Err(format!("Waiting on '{cmd:}' failed: {e:}").into()),
            },
            Err(e) => return Err(format!("Couldn't execute '{cmd:}': {e:}").into()),
        },
        Err(e) => return Err(format!("{e:}").into()),
    }
    Ok(())
}
