use std::{collections::HashMap, error::Error, path::Path, sync::Arc};

use log::info;

use super::{AuthenticatorState, TokenState};
use crate::Config;

pub fn reload_conf(pstate: Arc<AuthenticatorState>, conf_path: &str) -> Result<(), Box<dyn Error>> {
    let new_conf = Config::from_path(Path::new(conf_path))?;
    let mut ct_lk = pstate.ct_lock();
    let mut resets = Vec::new();
    let new_tokens = new_conf
        .accounts
        .iter()
        .map(|(act_name, act)| {
            let tokstate = match ct_lk.validate_act_name(act_name) {
                // If the account already exists and if the account hasn't changed any of its
                // details, we can keep the tokenstate unchanged.
                Some(act_id) if ct_lk.account(&act_id) == act.as_ref() => {
                    ct_lk.tokenstate(&act_id).clone()
                }
                // If the account already exists, some details of the account have changed, and
                // the tokenstate isn't `Empty`, then we warn the user that we're going to reset
                // things. [If the tokenstate is `Empty`, the warning is superfluous.]
                Some(act_id) if !matches!(ct_lk.tokenstate(&act_id), TokenState::Empty) => {
                    resets.push(format!(
                        "Account {} has changed some of its details: resetting token state entirely",
                        ct_lk.account(&act_id).name));
                    TokenState::Empty
                }
                _ => TokenState::Empty,
            };
            (act_name.to_owned(), tokstate)
        })
        .collect::<HashMap<_, _>>();
    ct_lk.update((new_conf, new_tokens));
    drop(ct_lk);
    for msg in resets {
        info!("{}", msg);
    }
    Ok(())
}
