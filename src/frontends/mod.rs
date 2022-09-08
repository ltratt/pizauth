#[cfg(feature = "frontend_notify-rust")]
pub mod notify_rust;

use std::error::Error;

use url::Url;

pub trait Frontend: Send + Sync {
    /// Create a front-end instance.
    fn new() -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;

    /// Execute the main loop of the front-end. When this function returns, pizauth will terminate.
    fn main_loop(&self) -> Result<(), Box<dyn Error>>;

    /// Inform the front-end of which accounts and URLs have yet to be authorised. Note that:
    ///   1. This function may be called from an arbitrary thread. If the frontend needs to execute
    ///      some code on a specific thread, it will need to communicate the notification to that
    ///      thread itself.
    ///   2. This function can block for as long as it wants, but for as long as it blocks, the
    ///      frontend will not be informed of further notifications.
    fn notify_authorisations(&self, to_notify: Vec<(String, Url)>) -> Result<(), Box<dyn Error>>;
}

pub fn preferred_frontend() -> Result<Box<dyn Frontend>, Box<dyn Error>> {
    #[cfg(feature = "frontend_notify-rust")]
    Ok(Box::new(notify_rust::NotifyRust::new()?))
}
