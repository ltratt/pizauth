//! Provides daemon(3) on macOS.

// We provide our own wrapper for daemon on macOS because nix does not export one for macOS.  This
// is *probably* why nix does not support daemon(3) on macOS:
//
//  - nix will not compile on macOS, due to errors
//  - ... nix compiles with #[deny(warnings)], which treats warnings as errors
//  - libc emits a deprecation warning for daemon(3) on macOS [1]
//  - ... because daemon(3) has been deprecated in macOS since Mac OS X 10.5
//  - ... presumably because Apple wants you to use launchd(8) instead [2].
//  - Therefore, this deprecation warning is treated as an error in nix
//
// [1]: https://github.com/rust-lang/libc/blob/96c85c1b913604fb5b1eb8822e344b7c08bcd6b9/src/unix/bsd/apple/mod.rs#L5064-L5067
// [2]: https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
//
// This module essentially reimplements nix's daemon wrapper on macOS, but allows deprecation
// warnings.
//
// See: https://github.com/ltratt/pizauth/issues/3
use libc::c_int;
#[allow(deprecated)]
use libc::daemon as libc_daemon;
use nix::errno::Errno;

pub fn daemon(nochdir: bool, noclose: bool) -> nix::Result<()> {
    #[allow(deprecated)]
    let res = unsafe { libc_daemon(nochdir as c_int, noclose as c_int) };
    Errno::result(res).map(drop)
}
