use std::{error::Error, thread, time::Duration};

use super::Frontend;

pub struct Null;

impl Frontend for Null {
    fn new() -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn main_loop(self: std::sync::Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        // This frontend has nothing to do in its main loop, so we just want to make sure that we
        // don't terminate the whole program by returning early. Duration::MAX equates to about
        // 584,942,417,355 years which is about 40x the age of the universe at the time of writing.
        // Still, this is meant to be a long-running daemon, so we loop, just in case the timeout
        // is exceeded.
        loop {
            thread::sleep(Duration::MAX);
        }
    }

    fn notify_error(&self, _: String, _: &str) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn notify_success(&self, _: String) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn notify_authorisations(
        &self,
        _: Vec<(String, url::Url)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
