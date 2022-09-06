use std::{collections::HashMap, error::Error, path::Path, sync::Arc};

use super::{AuthenticatorState, TokenState};
use crate::Config;

pub fn reload_conf(pstate: Arc<AuthenticatorState>, conf_path: &str) -> Result<(), Box<dyn Error>> {
    let new_conf = Config::from_path(Path::new(conf_path))?;
    let mut ct_lk = pstate.ct_lock();
    let new_tokens = new_conf
        .accounts
        .iter()
        .map(|(k, _)| {
            let tokstate = match ct_lk.validate_act_name(k) {
                Some(act_id) => ct_lk.tokenstate(&act_id).clone(),
                None => TokenState::Empty,
            };
            (k.to_owned(), tokstate)
        })
        .collect::<HashMap<_, _>>();
    ct_lk.update((new_conf, new_tokens));
    Ok(())
}
